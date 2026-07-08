from __future__ import annotations

import importlib.util
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from netaiops.governance.contracts import (
    EvidenceSourceStatus,
    ExternalCallPolicy,
    ReplayMode,
)
from netaiops.governance.proposal_builder import ProposalBuilderError
from netaiops.governance.replay_compare import (
    build_replay_comparison,
    compare_quality,
    compare_safety,
    compare_snapshots,
    quality_snapshot,
    safety_snapshot,
)
from netaiops.governance.replay_engine import (
    ReplayEngineError,
    _deep_merge,
    build_offline_replay,
    replay_safety_summary,
)
from netaiops.governance.schemas import ArtifactReference, IncidentMemoryRecord, ReplayRecord

FIXED_TIME = datetime(2026, 7, 7, 12, 0, tzinfo=timezone.utc)
REQUEST_ID = "20260703_145814_955415_6fe18e1f"


def artifact(kind: str = "analysis", path: str = "data/analysis/request.analysis.json"):
    return ArtifactReference(
        kind=kind,
        path=path,
        sha256="a" * 64,
        exists=True,
        size_bytes=100,
    )


def make_memory(**overrides):
    payload = {
        "memory_id": f"memory_{REQUEST_ID}",
        "request_id": REQUEST_ID,
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
            "readonly_only": True,
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
            artifact("analysis", "data/analysis/request.analysis.json"),
            artifact("execution", "data/execution/request.execution.json"),
            artifact("review", "data/reviews/request.review.json"),
            artifact("evidence_hub_summary", "data/evidence_hub/requests/r/summary.json"),
        ],
    }
    payload.update(overrides)
    return IncidentMemoryRecord.model_validate(payload)


def plan_payload():
    return {
        "readonly_only": True,
        "plan_status": "confirmed",
        "classification": {
            "family": "interface_or_link_utilization_high",
            "match_reason": "matched_catalog_alertname",
        },
        "playbook": {"matched": True, "playbook_id": "pb-interface-utilization"},
        "policy_result": {"status": "allowed", "reasons": []},
    }


class ReplayCompareTests(unittest.TestCase):
    def test_identical_snapshots_are_unchanged(self):
        snapshot = {"quality_flags": [], "safety": {"readonly_only": True}}
        result = compare_snapshots(snapshot, snapshot)
        self.assertFalse(result["changed"])
        self.assertEqual(result["change_count"], 0)

    def test_changed_fields_are_bounded_and_sorted(self):
        result = compare_snapshots(
            {"classification": {"family": "old"}, "quality_flags": []},
            {"classification": {"family": "new"}, "quality_flags": ["playbook_missing"]},
        )
        self.assertTrue(result["changed"])
        self.assertEqual(result["changed_fields"], ["classification", "quality_flags"])
        self.assertEqual(result["changes"][0]["path"], "classification.family")

    def test_logs_not_available_does_not_reduce_quality_score(self):
        result = quality_snapshot({"quality_flags": ["logs_not_available"]})
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["non_environment_issue_count"], 0)

    def test_quality_improvement_detects_resolved_flags(self):
        result = compare_quality(
            {"quality_flags": ["command_failed", "logs_not_available"]},
            {"quality_flags": ["logs_not_available"]},
        )
        self.assertEqual(result["outcome"], "improved")
        self.assertIn("command_failed", result["resolved_flags"])

    def test_quality_regression_detects_introduced_flags(self):
        result = compare_quality(
            {"quality_flags": []},
            {"quality_flags": ["model_parse_failed"]},
        )
        self.assertEqual(result["outcome"], "regressed")
        self.assertIn("model_parse_failed", result["introduced_flags"])

    def test_safe_snapshot_has_full_safety_score(self):
        result = safety_snapshot(
            {
                "safety": {
                    "readonly_only": True,
                    "external_calls": {"glm": False, "device": False},
                    "proposal_auto_apply_count": 0,
                }
            }
        )
        self.assertTrue(result["safe"])
        self.assertEqual(result["score"], 100)

    def test_external_call_is_safety_regression(self):
        result = compare_safety(
            {"safety": {"readonly_only": True, "external_calls": {"glm": False}}},
            {"safety": {"readonly_only": True, "external_calls": {"glm": True}}},
        )
        self.assertTrue(result["regression"])
        self.assertIn("external_call:glm", result["introduced_violations"])

    def test_auto_apply_is_safety_regression(self):
        result = compare_safety(
            {"safety": {"readonly_only": True, "proposal_auto_apply_count": 0}},
            {"safety": {"readonly_only": True, "proposal_auto_apply_count": 1}},
        )
        self.assertTrue(result["regression"])
        self.assertIn("proposal_auto_apply_enabled", result["introduced_violations"])

    def test_combined_comparison_contains_all_sections(self):
        result = build_replay_comparison(
            {"quality_flags": [], "safety": {"readonly_only": True}},
            {"quality_flags": [], "safety": {"readonly_only": True}},
        )
        self.assertEqual(set(result), {"diff", "quality_delta", "safety_delta"})


class ReplayEngineTests(unittest.TestCase):
    def test_logs_only_memory_creates_non_proposal_signal(self):
        execution = build_offline_replay(
            make_memory(), plan=plan_payload(), generated_at=FIXED_TIME
        )
        self.assertEqual([item.signal_type for item in execution.signals], ["logs_not_available"])
        self.assertEqual(execution.proposals, ())

    def test_command_failures_create_reviewable_proposals(self):
        memory = make_memory(
            quality_flags=["command_failed", "cli_hard_error", "logs_not_available"],
            command_summary={
                "total": 2,
                "completed": 0,
                "failed": 2,
                "partial": 0,
                "hard_error_count": 2,
                "readonly_only": True,
            },
        )
        execution = build_offline_replay(memory, plan=plan_payload(), generated_at=FIXED_TIME)
        self.assertEqual(
            {item.signal_type for item in execution.proposals},
            {"command_failed", "cli_hard_error"},
        )
        self.assertTrue(all(item.risk["auto_apply"] is False for item in execution.proposals))

    def test_replay_id_is_deterministic(self):
        first = build_offline_replay(make_memory(), plan=plan_payload(), generated_at=FIXED_TIME)
        second = build_offline_replay(make_memory(), plan=plan_payload(), generated_at=FIXED_TIME)
        self.assertEqual(first.record.replay_id, second.record.replay_id)

    def test_candidate_patch_changes_after_only(self):
        execution = build_offline_replay(
            make_memory(),
            plan=plan_payload(),
            candidate_patch={"classification": {"family": "candidate_family"}},
            generated_at=FIXED_TIME,
        )
        self.assertNotEqual(
            execution.record.before["classification"]["family"],
            execution.record.after["classification"]["family"],
        )
        self.assertIn("classification", execution.record.diff["changed_fields"])

    def test_external_calls_are_always_false(self):
        execution = build_offline_replay(
            make_memory(), plan=plan_payload(), generated_at=FIXED_TIME
        )
        self.assertFalse(any(execution.record.external_calls.values()))
        self.assertEqual(execution.record.mode, ReplayMode.OFFLINE)

    def test_unsafe_external_policy_is_rejected(self):
        with self.assertRaises(ValueError):
            build_offline_replay(
                make_memory(),
                plan=plan_payload(),
                generated_at=FIXED_TIME,
                external_policy=ExternalCallPolicy(real_glm=True),
            )

    def test_naive_generated_time_is_rejected(self):
        with self.assertRaises(ReplayEngineError):
            build_offline_replay(
                make_memory(),
                plan=plan_payload(),
                generated_at=datetime(2026, 7, 7, 12, 0),
            )

    def test_candidate_references_are_deduplicated(self):
        memory = make_memory(
            quality_flags=["command_failed", "cli_hard_error", "logs_not_available"],
            command_summary={
                "total": 2,
                "completed": 0,
                "failed": 2,
                "partial": 0,
                "hard_error_count": 2,
                "readonly_only": True,
            },
        )
        execution = build_offline_replay(memory, plan=plan_payload(), generated_at=FIXED_TIME)
        keys = [(item.kind, item.path, item.sha256) for item in execution.record.candidate_refs]
        self.assertEqual(len(keys), len(set(keys)))

    def test_proposal_build_failure_is_isolated(self):
        memory = make_memory(
            quality_flags=["command_failed", "logs_not_available"],
            command_summary={
                "total": 1,
                "completed": 0,
                "failed": 1,
                "partial": 0,
                "hard_error_count": 0,
                "readonly_only": True,
            },
        )
        with patch(
            "netaiops.governance.replay_engine.ProposalBuilder.build_for_memory",
            side_effect=ProposalBuilderError("fixture failure"),
        ):
            execution = build_offline_replay(memory, plan=plan_payload(), generated_at=FIXED_TIME)
        self.assertEqual(execution.proposals, ())
        self.assertTrue(any(item.startswith("proposal_build_failed:") for item in execution.record.errors))

    def test_candidate_safety_regression_is_recorded(self):
        execution = build_offline_replay(
            make_memory(),
            plan=plan_payload(),
            candidate_patch={"safety": {"external_calls": {"glm": True}}},
            generated_at=FIXED_TIME,
        )
        self.assertTrue(execution.record.safety_delta["regression"])
        self.assertIn("candidate_safety_regression_detected", execution.record.warnings)

    def test_replay_record_round_trip_validation(self):
        execution = build_offline_replay(
            make_memory(), plan=plan_payload(), generated_at=FIXED_TIME
        )
        restored = ReplayRecord.model_validate(execution.record.to_payload())
        self.assertEqual(restored.replay_id, execution.record.replay_id)

    def test_replay_safety_summary_is_safe_for_default_run(self):
        execution = build_offline_replay(
            make_memory(), plan=plan_payload(), generated_at=FIXED_TIME
        )
        summary = replay_safety_summary(execution)
        self.assertTrue(summary["safe"])
        self.assertEqual(summary["enabled_external_calls"], [])

    def test_deep_merge_does_not_modify_base(self):
        base = {"classification": {"family": "before", "reason": "x"}}
        merged = _deep_merge(base, {"classification": {"family": "after"}})
        self.assertEqual(base["classification"]["family"], "before")
        self.assertEqual(merged["classification"]["reason"], "x")


class ReplayCliSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tool_path = Path(__file__).resolve().parents[1] / "tools" / "v11_replay.py"
        spec = importlib.util.spec_from_file_location("v11_replay_tool", tool_path)
        assert spec and spec.loader
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)

    def test_production_governance_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "project"
            (project / "data" / "governance").mkdir(parents=True)
            with self.assertRaises(ValueError):
                self.tool._safe_output_root(project, project / "data" / "governance")

    def test_project_subdirectory_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "project"
            project.mkdir()
            with self.assertRaises(ValueError):
                self.tool._safe_output_root(project, project / "tmp-replay")

    def test_external_temporary_output_is_allowed(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "project"
            output = Path(temp) / "output"
            project.mkdir()
            self.assertEqual(self.tool._safe_output_root(project, output), output.resolve())


if __name__ == "__main__":
    unittest.main()
