from __future__ import annotations

import unittest
from datetime import datetime, timezone

from pydantic import ValidationError

from netaiops.governance.contracts import (
    EvidenceSourceStatus,
    LearningSignalSeverity,
)
from netaiops.governance.schemas import (
    ArtifactReference,
    IncidentMemoryRecord,
)
from netaiops.governance.signal_detector import (
    detect_learning_signals,
    signal_detection_summary,
)


FIXED_TIME = datetime(2026, 7, 7, 8, 0, tzinfo=timezone.utc)


def make_memory(**overrides):
    payload = {
        "memory_id": "memory_20260703_145814_955415_6fe18e1f",
        "request_id": "20260703_145814_955415_6fe18e1f",
        "created_at": FIXED_TIME,
        "source_type": "alertmanager",
        "alert_time": FIXED_TIME,
        "device": {"hostname": "switch-01", "device_ip": "10.0.0.1"},
        "object": {"name": "Te1/0/1", "interface": "Te1/0/1"},
        "family": "interface_or_link_utilization_high",
        "alert_summary": "Interface utilization high",
        "analysis_summary": "Evidence review required",
        "evidence_status": {
            "metrics": EvidenceSourceStatus.SUCCESS,
            "device": EvidenceSourceStatus.SUCCESS,
            "review": EvidenceSourceStatus.SUCCESS,
            "notification": EvidenceSourceStatus.SUCCESS,
            "logs": EvidenceSourceStatus.NOT_AVAILABLE,
        },
        "command_summary": {
            "total": 2,
            "completed": 2,
            "failed": 0,
            "partial": 0,
            "hard_error_count": 0,
        },
        "review_summary": {
            "status": "completed",
            "missing_evidence_count": 0,
            "read_error_count": 0,
        },
        "notification_result": {"status": "success", "sent": True},
        "quality_flags": ["logs_not_available"],
        "git_metadata": {"branch": "main", "commit": "a" * 40, "dirty": False},
        "artifact_refs": [
            ArtifactReference(
                kind="analysis",
                path="data/analysis/request.analysis.json",
                sha256="a" * 64,
                exists=True,
                size_bytes=100,
            ),
            ArtifactReference(
                kind="plan",
                path="data/plans/request.plan.json",
                sha256="b" * 64,
                exists=True,
                size_bytes=100,
            ),
            ArtifactReference(
                kind="prometheus_evidence",
                path="data/prometheus_evidence/request.json",
                sha256="c" * 64,
                exists=True,
                size_bytes=100,
            ),
            ArtifactReference(
                kind="execution",
                path="data/execution/request.execution.json",
                sha256="d" * 64,
                exists=True,
                size_bytes=100,
            ),
            ArtifactReference(
                kind="review",
                path="data/reviews/request.review.json",
                sha256="e" * 64,
                exists=True,
                size_bytes=100,
            ),
            ArtifactReference(
                kind="notification_send_result",
                path="data/evidence_hub/requests/request/send.json",
                sha256="f" * 64,
                exists=True,
                size_bytes=100,
            ),
            ArtifactReference(
                kind="evidence_hub_summary",
                path="data/evidence_hub/requests/request/summary.json",
                sha256="1" * 64,
                exists=True,
                size_bytes=100,
            ),
        ],
    }
    payload.update(overrides)
    return IncidentMemoryRecord.model_validate(payload)


def signal_map(memory):
    return {
        item.signal_type: item
        for item in detect_learning_signals(memory, generated_at=FIXED_TIME)
    }


class LearningSignalDetectorTests(unittest.TestCase):
    def test_success_memory_only_emits_logs_capability_status(self):
        signals = signal_map(make_memory())
        self.assertEqual(set(signals), {"logs_not_available"})

    def test_logs_not_available_is_info_and_not_proposal_eligible(self):
        signal = signal_map(make_memory())["logs_not_available"]
        self.assertEqual(signal.severity, LearningSignalSeverity.INFO)
        self.assertFalse(signal.proposal_eligible)
        self.assertIn("Elasticsearch", signal.reason)

    def test_command_failure_and_hard_error_are_detected(self):
        memory = make_memory(
            command_summary={"failed": 2, "hard_error_count": 1},
            quality_flags=["command_failed", "cli_hard_error", "logs_not_available"],
        )
        signals = signal_map(memory)
        self.assertIn("command_failed", signals)
        self.assertIn("cli_hard_error", signals)
        self.assertIn("failed=2", signals["command_failed"].reason)
        self.assertIn("count=1", signals["cli_hard_error"].reason)

    def test_metrics_no_data_is_detected_from_status(self):
        memory = make_memory(
            evidence_status={
                **make_memory().evidence_status,
                "metrics": EvidenceSourceStatus.NO_DATA,
            },
            quality_flags=["logs_not_available"],
        )
        self.assertIn("prometheus_no_data", signal_map(memory))

    def test_metrics_failed_is_detected_from_status(self):
        memory = make_memory(
            evidence_status={
                **make_memory().evidence_status,
                "metrics": EvidenceSourceStatus.FAILED,
            },
        )
        self.assertIn("prometheus_failed", signal_map(memory))

    def test_metrics_not_configured_is_detected_from_status(self):
        memory = make_memory(
            evidence_status={
                **make_memory().evidence_status,
                "metrics": EvidenceSourceStatus.NOT_CONFIGURED,
            },
        )
        self.assertIn("prometheus_not_configured", signal_map(memory))

    def test_quality_flags_map_to_governed_signal_types(self):
        memory = make_memory(
            quality_flags=[
                "classification_fallback",
                "playbook_missing",
                "policy_blocked",
                "model_parse_failed",
                "runner_false_negative",
                "logs_not_available",
            ]
        )
        signals = signal_map(memory)
        for expected in (
            "classification_fallback",
            "playbook_missing",
            "policy_blocked",
            "model_parse_failed",
            "runner_false_negative",
        ):
            self.assertIn(expected, signals)

    def test_unknown_quality_flag_is_ignored(self):
        memory = make_memory(quality_flags=["unknown_flag", "logs_not_available"])
        self.assertEqual(set(signal_map(memory)), {"logs_not_available"})

    def test_review_missing_evidence_is_detected(self):
        memory = make_memory(
            review_summary={
                "status": "needs_attention",
                "missing_evidence_count": 2,
                "read_error_count": 0,
            }
        )
        self.assertIn("review_missing_evidence", signal_map(memory))

    def test_review_skipped_is_detected(self):
        memory = make_memory(
            evidence_status={
                **make_memory().evidence_status,
                "review": EvidenceSourceStatus.SKIPPED,
            }
        )
        self.assertIn("review_missing_evidence", signal_map(memory))

    def test_notification_failure_is_detected(self):
        memory = make_memory(notification_result={"status": "failed", "sent": False})
        self.assertIn("notification_failed", signal_map(memory))

    def test_evidence_refs_are_selected_by_signal(self):
        signals = signal_map(
            make_memory(
                command_summary={"failed": 1, "hard_error_count": 0},
                quality_flags=["command_failed", "logs_not_available"],
            )
        )
        kinds = {ref.kind for ref in signals["command_failed"].evidence_refs}
        self.assertEqual(kinds, {"execution", "review"})

    def test_missing_preferred_evidence_falls_back_to_first_ref(self):
        memory = make_memory(
            artifact_refs=[make_memory().artifact_refs[0]],
            notification_result={"status": "failed", "sent": False},
        )
        signal = signal_map(memory)["notification_failed"]
        self.assertEqual(signal.evidence_refs[0].kind, "analysis")

    def test_signal_ids_and_dedupe_keys_are_deterministic(self):
        memory = make_memory(
            command_summary={"failed": 1, "hard_error_count": 0},
            quality_flags=["command_failed", "logs_not_available"],
        )
        first = signal_map(memory)["command_failed"]
        second = signal_map(memory)["command_failed"]
        self.assertEqual(first.signal_id, second.signal_id)
        self.assertEqual(first.dedupe_key, second.dedupe_key)

    def test_mapping_input_is_accepted(self):
        payload = make_memory().model_dump(mode="json")
        signals = detect_learning_signals(payload, generated_at=FIXED_TIME)
        self.assertEqual(signals[0].request_id, payload["request_id"])

    def test_invalid_mapping_is_rejected(self):
        with self.assertRaises(ValueError):
            detect_learning_signals({"request_id": "missing-fields"})

    def test_generated_at_requires_timezone(self):
        with self.assertRaises(ValueError):
            detect_learning_signals(make_memory(), generated_at=datetime(2026, 7, 7, 8, 0))

    def test_summary_counts_types_severity_and_proposal_eligibility(self):
        memory = make_memory(
            command_summary={"failed": 1, "hard_error_count": 1},
            quality_flags=["command_failed", "cli_hard_error", "logs_not_available"],
        )
        summary = signal_detection_summary(
            detect_learning_signals(memory, generated_at=FIXED_TIME)
        )
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["proposal_eligible"], 2)
        self.assertEqual(summary["non_proposal"], 1)
        self.assertEqual(summary["by_severity"]["error"], 2)
        self.assertEqual(summary["by_severity"]["info"], 1)

    def test_reasons_do_not_copy_memory_summaries(self):
        memory = make_memory(
            alert_summary="TOP SECRET RAW PAYLOAD",
            analysis_summary="SENSITIVE DEVICE OUTPUT",
            quality_flags=["model_parse_failed", "logs_not_available"],
        )
        text = " ".join(item.reason for item in detect_learning_signals(memory))
        self.assertNotIn("TOP SECRET", text)
        self.assertNotIn("SENSITIVE DEVICE OUTPUT", text)


if __name__ == "__main__":
    unittest.main()
