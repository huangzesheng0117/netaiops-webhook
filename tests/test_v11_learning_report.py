from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import date, datetime, timezone
from pathlib import Path

from netaiops.governance.contracts import (
    AuditStatus,
    EvidenceSourceStatus,
    LearningSignalSeverity,
    ProposalStatus,
    ReplayMode,
)
from netaiops.governance.report_builder import (
    LearningReportError,
    build_learning_report,
    render_learning_report_markdown,
    report_consistency_summary,
    report_window,
)
from netaiops.governance.schemas import (
    ArtifactReference,
    IncidentMemoryRecord,
    LearningSignalRecord,
    ProposalRecord,
    ReplayRecord,
)
from netaiops.governance.store import GovernanceStore

FIXED_CREATED_AT = datetime(2026, 7, 8, 1, 0, tzinfo=timezone.utc)
DAY = datetime(2026, 7, 6, 1, 0, tzinfo=timezone.utc)
NEXT_DAY = datetime(2026, 7, 7, 1, 0, tzinfo=timezone.utc)
REF = ArtifactReference(
    kind="analysis",
    path="data/analysis/fixture.analysis.json",
    sha256="a" * 64,
    exists=True,
    size_bytes=10,
)


def memory(request_id: str, created_at: datetime, family: str, metrics: EvidenceSourceStatus):
    return IncidentMemoryRecord(
        memory_id=f"memory_{request_id}",
        request_id=request_id,
        created_at=created_at,
        source_type="alertmanager",
        alert_time=created_at,
        device={"hostname": f"device-{request_id}"},
        object={"name": "Te1/0/1"},
        family=family,
        alert_summary="summary",
        analysis_summary="analysis",
        evidence_status={
            "metrics": metrics,
            "device": EvidenceSourceStatus.SUCCESS,
            "review": EvidenceSourceStatus.SUCCESS,
            "notification": EvidenceSourceStatus.SUCCESS,
            "logs": EvidenceSourceStatus.NOT_AVAILABLE,
        },
        command_summary={"failed": 0, "hard_error_count": 0, "readonly_only": True},
        review_summary={"missing_evidence_count": 0, "read_error_count": 0},
        notification_result={"status": "success", "sent": True},
        quality_flags=["logs_not_available"],
        git_metadata={"branch": "main", "commit": "b" * 40, "dirty": False},
        artifact_refs=[REF],
    )


def signal(
    signal_id: str,
    request_id: str,
    created_at: datetime,
    signal_type: str,
    *,
    eligible: bool = True,
):
    severity = (
        LearningSignalSeverity.INFO
        if signal_type == "logs_not_available"
        else LearningSignalSeverity.ERROR
    )
    return LearningSignalRecord(
        signal_id=signal_id,
        request_id=request_id,
        created_at=created_at,
        signal_type=signal_type,
        severity=severity,
        detected_from=["fixture"],
        reason="fixture reason",
        evidence_refs=[REF],
        dedupe_key=f"{signal_type}|fixture",
        proposal_eligible=eligible,
    )


def proposal(
    proposal_id: str,
    signal_id: str,
    created_at: datetime,
    status: ProposalStatus,
):
    return ProposalRecord(
        proposal_id=proposal_id,
        signal_id=signal_id,
        signal_type="command_failed",
        affected_family="interface_status_or_flap",
        affected_components=["device_evidence_template"],
        evidence_refs=[REF],
        suggested_change={"objective": "human review only"},
        expected_benefit="improve evidence reliability",
        risk={"level": "medium", "auto_apply": False},
        replay_scope={"mode": "offline", "external_calls": {"device": False}},
        status=status,
        reviewer="reviewer" if status != ProposalStatus.DRAFT else "",
        created_at=created_at,
        updated_at=created_at,
        audit_trail=[],
    )


def replay(
    replay_id: str,
    request_id: str,
    created_at: datetime,
    outcome: str,
    *,
    safety_regression: bool = False,
):
    return ReplayRecord(
        replay_id=replay_id,
        request_id=request_id,
        mode=ReplayMode.OFFLINE,
        created_at=created_at,
        baseline_refs=[REF],
        candidate_refs=[REF],
        before={},
        after={},
        diff={"changed": False},
        quality_delta={"outcome": outcome, "score_delta": 0},
        safety_delta={"regression": safety_regression},
        external_calls={
            "glm": False,
            "prometheus": False,
            "device": False,
            "notification": False,
            "production_write": False,
        },
        errors=[],
        warnings=[],
    )


class LearningReportFixture:
    def __init__(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "governance"
        self.store = GovernanceStore(self.root)
        self.populate()

    def close(self):
        self.tempdir.cleanup()

    def populate(self):
        self.store.write(
            "incident_memory",
            "memory_req1",
            memory("req1", DAY, "interface_status_or_flap", EvidenceSourceStatus.NO_DATA),
        )
        self.store.write(
            "incident_memory",
            "memory_req2",
            memory("req2", DAY.replace(hour=2), "interface_status_or_flap", EvidenceSourceStatus.SUCCESS),
        )
        self.store.write(
            "incident_memory",
            "memory_req3",
            memory("req3", NEXT_DAY, "hardware_health", EvidenceSourceStatus.SUCCESS),
        )
        self.store.write("signals", "signal_cmd", signal("signal_cmd", "req1", DAY, "command_failed"))
        self.store.write(
            "signals",
            "signal_logs",
            signal("signal_logs", "req1", DAY.replace(hour=2), "logs_not_available", eligible=False),
        )
        self.store.write(
            "signals",
            "signal_prom",
            signal("signal_prom", "req2", DAY.replace(hour=3), "prometheus_no_data"),
        )
        self.store.write(
            "signals",
            "signal_outside",
            signal("signal_outside", "req3", NEXT_DAY, "notification_failed"),
        )
        self.store.write(
            "proposals",
            "proposal_draft",
            proposal("proposal_draft", "signal_cmd", DAY, ProposalStatus.DRAFT),
        )
        self.store.write(
            "proposals",
            "proposal_approved",
            proposal("proposal_approved", "signal_prom", DAY.replace(hour=3), ProposalStatus.APPROVED),
        )
        self.store.write(
            "replays",
            "replay_improved",
            replay("replay_improved", "req1", DAY, "improved"),
        )
        self.store.write(
            "replays",
            "replay_unchanged",
            replay("replay_unchanged", "req2", DAY.replace(hour=2), "unchanged"),
        )
        self.store.write(
            "replays",
            "replay_regressed",
            replay("replay_regressed", "req2", DAY.replace(hour=3), "regressed", safety_regression=True),
        )


class LearningReportTests(unittest.TestCase):
    def setUp(self):
        self.fx = LearningReportFixture()

    def tearDown(self):
        self.fx.close()

    def report(self):
        return build_learning_report(
            self.fx.root,
            period="daily",
            anchor_date="2026-07-06",
            created_at=FIXED_CREATED_AT,
        )

    def test_daily_window(self):
        start, end = report_window("daily", "2026-07-06")
        self.assertEqual(start.isoformat(), "2026-07-06T00:00:00+00:00")
        self.assertEqual(end.isoformat(), "2026-07-07T00:00:00+00:00")

    def test_weekly_window_starts_monday(self):
        start, end = report_window("weekly", "2026-07-08")
        self.assertEqual(start.date(), date(2026, 7, 6))
        self.assertEqual(end.date(), date(2026, 7, 13))

    def test_monthly_window(self):
        start, end = report_window("monthly", "2026-12-20")
        self.assertEqual(start.date(), date(2026, 12, 1))
        self.assertEqual(end.date(), date(2027, 1, 1))

    def test_invalid_period_rejected(self):
        with self.assertRaises(LearningReportError):
            report_window("yearly", "2026-07-06")

    def test_invalid_date_rejected(self):
        with self.assertRaises(LearningReportError):
            report_window("daily", "2026-99-99")

    def test_daily_counts(self):
        summary = self.report()["summary"]
        self.assertEqual(summary["memory_count"], 2)
        self.assertEqual(summary["signal_count"], 3)
        self.assertEqual(summary["proposal_count"], 2)
        self.assertEqual(summary["replay_count"], 3)

    def test_request_count_is_unique(self):
        self.assertEqual(self.report()["summary"]["request_count"], 2)

    def test_family_distribution(self):
        self.assertEqual(
            self.report()["family_distribution"],
            [{"family": "interface_status_or_flap", "count": 2}],
        )

    def test_signal_counts_include_zero_contract_types(self):
        counts = self.report()["signal_counts"]
        self.assertEqual(counts["command_failed"], 1)
        self.assertEqual(counts["notification_failed"], 0)

    def test_logs_not_available_is_separate(self):
        summary = self.report()["summary"]
        self.assertEqual(summary["logs_not_available_count"], 1)
        self.assertEqual(summary["issue_signal_count"], 2)

    def test_proposal_status_counts(self):
        counts = self.report()["proposal_status_counts"]
        self.assertEqual(counts["draft"], 1)
        self.assertEqual(counts["approved"], 1)
        self.assertEqual(counts["verified"], 0)

    def test_replay_outcome_counts(self):
        counts = self.report()["replay_outcome_counts"]
        self.assertEqual(counts, {"improved": 1, "regressed": 1, "unchanged": 1})

    def test_replay_safety_regression_count(self):
        self.assertEqual(self.report()["summary"]["replay_safety_regression_count"], 1)

    def test_evidence_coverage(self):
        coverage = self.report()["evidence_coverage"]
        self.assertEqual(coverage["metrics"], {"no_data": 1, "success": 1})
        self.assertEqual(coverage["logs"], {"not_available": 2})

    def test_corrupt_record_is_isolated(self):
        path = self.fx.root / "signals" / "bad.json"
        path.write_text("{bad", encoding="utf-8")
        report = self.report()
        self.assertEqual(report["summary"]["corrupt_record_count"], 1)
        self.assertEqual(report["collection_stats"]["signals"]["corrupt_total"], 1)

    def test_report_id_is_deterministic(self):
        first = self.report()["report_id"]
        second = self.report()["report_id"]
        self.assertEqual(first, second)

    def test_report_external_calls_are_false(self):
        calls = self.report()["source"]["external_calls"]
        self.assertFalse(any(calls.values()))
        self.assertFalse(self.report()["source"]["production_write"])

    def test_logs_status_not_webhook_failure(self):
        self.assertFalse(
            self.report()["governance_boundaries"]["logs_not_available_is_webhook_failure"]
        )

    def test_markdown_contains_window_and_title(self):
        markdown = render_learning_report_markdown(self.report())
        self.assertIn("# NetAIOps Webhook v11 Learning Report", markdown)
        self.assertIn("2026-07-06T00:00:00+00:00", markdown)

    def test_json_markdown_summary_is_consistent(self):
        report = self.report()
        markdown = render_learning_report_markdown(report)
        result = report_consistency_summary(report, markdown)
        self.assertTrue(result["consistent"])
        self.assertEqual(result["missing_metrics"], [])

    def test_empty_store_report_is_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = build_learning_report(
                Path(tmp) / "empty",
                period="daily",
                anchor_date="2026-07-06",
                created_at=FIXED_CREATED_AT,
            )
        self.assertEqual(report["summary"]["request_count"], 0)
        self.assertEqual(report["summary"]["corrupt_record_count"], 0)

    def test_cli_writes_json_and_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            json_out = Path(tmp) / "report.json"
            md_out = Path(tmp) / "report.md"
            tool = Path(__file__).resolve().parents[1] / "tools" / "v11_learning_report.py"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(tool),
                    "--governance-root",
                    str(self.fx.root),
                    "--period",
                    "daily",
                    "--date",
                    "2026-07-06",
                    "--json-out",
                    str(json_out),
                    "--markdown-out",
                    str(md_out),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(json_out.read_text(encoding="utf-8"))
            markdown = md_out.read_text(encoding="utf-8")
            self.assertEqual(payload["summary"]["request_count"], 2)
            self.assertTrue(report_consistency_summary(payload, markdown)["consistent"])


if __name__ == "__main__":
    unittest.main()
