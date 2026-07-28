from __future__ import annotations

import json
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from netaiops.v12.api import AgentTraceReadService
from netaiops.v12.governance_adapter import (
    AgentTraceGovernanceAdapter,
    AgentTraceGovernanceAdapterError,
    GovernanceTraceSummary,
)
from tests.test_v12_agent_ui import REQUEST_ID, create_trace


NOW = datetime(2026, 7, 28, 10, 0, tzinfo=timezone.utc)


class GovernanceAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.trace_root = root / "requests"
        self.governance_root = root / "governance" / "agent_traces"
        create_trace(self.trace_root)
        self.service = AgentTraceReadService(self.trace_root)
        self.adapter = AgentTraceGovernanceAdapter(
            trace_service=self.service,
            governance_root=self.governance_root,
            utcnow=lambda: NOW,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_build_summary_contract(self) -> None:
        summary = self.adapter.build_for_request(REQUEST_ID)
        self.assertIsInstance(summary, GovernanceTraceSummary)
        self.assertEqual(summary.request_id, REQUEST_ID)

    def test_summary_contains_agent_statuses(self) -> None:
        summary = self.adapter.build_for_request(REQUEST_ID)
        self.assertEqual(
            [item["agent_name"] for item in summary.agent_statuses],
            ["triage", "device_evidence"],
        )

    def test_summary_contains_agent_duration(self) -> None:
        summary = self.adapter.build_for_request(REQUEST_ID)
        self.assertEqual(summary.agent_statuses[1]["duration_ms"], 40)

    def test_summary_contains_missing_evidence_types(self) -> None:
        summary = self.adapter.build_for_request(REQUEST_ID)
        self.assertEqual(
            summary.missing_evidence_types,
            ["knowledge", "logs"],
        )

    def test_summary_contains_judge_result(self) -> None:
        summary = self.adapter.build_for_request(REQUEST_ID)
        self.assertEqual(summary.judge_result["status"], "partial")
        self.assertEqual(summary.judge_result["conflict_count"], 1)

    def test_summary_contains_judge_confidence_cap(self) -> None:
        summary = self.adapter.build_for_request(REQUEST_ID)
        self.assertEqual(summary.judge_result["confidence_cap"], 0.7)

    def test_summary_contains_rca_confidence(self) -> None:
        summary = self.adapter.build_for_request(REQUEST_ID)
        self.assertEqual(summary.rca_confidence["candidate_count"], 1)
        self.assertEqual(summary.rca_confidence["maximum"], 0.65)

    def test_summary_contains_rca_average(self) -> None:
        summary = self.adapter.build_for_request(REQUEST_ID)
        self.assertEqual(summary.rca_confidence["average"], 0.65)

    def test_summary_contains_artifact_refs(self) -> None:
        summary = self.adapter.build_for_request(REQUEST_ID)
        self.assertGreater(len(summary.artifact_refs), 0)

    def test_summary_contains_error_categories(self) -> None:
        summary = self.adapter.build_for_request(REQUEST_ID)
        self.assertEqual(
            summary.error_categories,
            ["device_command_partial"],
        )

    def test_summary_preserves_fallback_state(self) -> None:
        summary = self.adapter.build_for_request(REQUEST_ID)
        self.assertTrue(summary.fallback_to_legacy)

    def test_summary_has_aware_timestamp(self) -> None:
        summary = self.adapter.build_for_request(REQUEST_ID)
        self.assertIsNotNone(summary.generated_at.utcoffset())

    def test_summary_does_not_copy_full_logs(self) -> None:
        self.assertFalse(
            self.adapter.build_for_request(REQUEST_ID).full_logs_copied
        )

    def test_summary_does_not_copy_full_commands(self) -> None:
        self.assertFalse(
            self.adapter.build_for_request(
                REQUEST_ID
            ).full_device_output_copied
        )

    def test_summary_does_not_copy_full_metrics(self) -> None:
        self.assertFalse(
            self.adapter.build_for_request(REQUEST_ID).full_metrics_copied
        )

    def test_summary_does_not_copy_raw_payload(self) -> None:
        self.assertFalse(
            self.adapter.build_for_request(REQUEST_ID).raw_payload_copied
        )

    def test_summary_does_not_leak_fixture_marker(self) -> None:
        summary = self.adapter.build_for_request(REQUEST_ID)
        encoded = json.dumps(
            summary.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
        )
        self.assertNotIn("DO-NOT-EXPOSE", encoded)

    def test_summary_external_calls_are_false(self) -> None:
        summary = self.adapter.build_for_request(REQUEST_ID)
        self.assertTrue(
            all(value is False for value in summary.external_calls.values())
        )

    def test_persist_writes_file(self) -> None:
        result = self.adapter.persist_for_request(REQUEST_ID)
        self.assertTrue(result["ok"])
        self.assertTrue(
            (self.governance_root / f"{REQUEST_ID}.json").is_file()
        )

    def test_persist_file_mode_is_0640(self) -> None:
        self.adapter.persist_for_request(REQUEST_ID)
        path = self.governance_root / f"{REQUEST_ID}.json"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)

    def test_persist_is_idempotent_replacement(self) -> None:
        first = self.adapter.persist_for_request(REQUEST_ID)
        second = self.adapter.persist_for_request(REQUEST_ID)
        self.assertEqual(first["path"], second["path"])

    def test_load_round_trip(self) -> None:
        summary = self.adapter.build_for_request(REQUEST_ID)
        self.adapter.persist(summary)
        loaded = self.adapter.load(REQUEST_ID)
        self.assertEqual(loaded.request_id, REQUEST_ID)
        self.assertEqual(loaded.agent_statuses, summary.agent_statuses)

    def test_safe_wrapper_returns_failure(self) -> None:
        result = self.adapter.persist_for_request_safe("req-missing")
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "failed")

    def test_safe_wrapper_has_no_external_calls(self) -> None:
        result = self.adapter.persist_for_request_safe("req-missing")
        self.assertTrue(
            all(
                value is False
                for value in result["external_calls"].values()
            )
        )

    def test_naive_clock_is_rejected(self) -> None:
        adapter = AgentTraceGovernanceAdapter(
            trace_service=self.service,
            governance_root=self.governance_root,
            utcnow=lambda: datetime(2026, 7, 28, 10, 0),
        )
        with self.assertRaises(AgentTraceGovernanceAdapterError):
            adapter.build_for_request(REQUEST_ID)

    def test_governance_root_symlink_is_rejected(self) -> None:
        target = Path(self.temporary.name) / "real-governance"
        target.mkdir(parents=True)
        link = Path(self.temporary.name) / "governance-link"
        link.symlink_to(target, target_is_directory=True)
        adapter = AgentTraceGovernanceAdapter(
            trace_service=self.service,
            governance_root=link,
            utcnow=lambda: NOW,
        )
        summary = adapter.build_for_request(REQUEST_ID)
        with self.assertRaises(AgentTraceGovernanceAdapterError):
            adapter.persist(summary)

    def test_invalid_request_id_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.adapter.build_for_request("../escape")

    def test_invalid_artifact_ref_is_rejected(self) -> None:
        detail = self.service.get_trace(REQUEST_ID)
        detail["artifact_refs"] = [
            "artifact://req-other/report/report-1"
        ]
        with self.assertRaises(AgentTraceGovernanceAdapterError):
            self.adapter.build_summary(detail)

    def test_only_approved_top_level_fields_are_persisted(self) -> None:
        self.adapter.persist_for_request(REQUEST_ID)
        payload = json.loads(
            (
                self.governance_root / f"{REQUEST_ID}.json"
            ).read_text(encoding="utf-8")
        )
        allowed = {
            "schema_version",
            "record_type",
            "request_id",
            "generated_at",
            "final_state",
            "fallback_to_legacy",
            "stop_reason",
            "elapsed_ms",
            "agent_statuses",
            "missing_evidence_types",
            "judge_result",
            "rca_confidence",
            "artifact_refs",
            "error_categories",
            "full_logs_copied",
            "full_device_output_copied",
            "full_metrics_copied",
            "raw_payload_copied",
            "external_calls",
        }
        self.assertEqual(set(payload), allowed)

    def test_adapter_source_has_no_external_clients(self) -> None:
        root = Path(__file__).resolve().parents[1]
        text = (
            root / "netaiops/v12/governance_adapter.py"
        ).read_text(encoding="utf-8").lower()
        for token in (
            "import requests",
            "import httpx",
            "import socket",
            "send_notification(",
            "send_dongdong(",
            "fastmcp(",
            "openai(",
        ):
            self.assertNotIn(token, text)


if __name__ == "__main__":
    unittest.main()
