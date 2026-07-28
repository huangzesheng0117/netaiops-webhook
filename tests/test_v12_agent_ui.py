from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from netaiops.v12.api import (
    AgentTraceCorruptError,
    AgentTraceReadError,
    AgentTraceReadService,
    create_agent_trace_api_router,
)
from netaiops.v12.ui import create_agent_trace_ui_router


REQUEST_ID = "req-batch-n-001"
OTHER_ID = "req-batch-n-002"
NOW = "2026-07-28T10:00:00+00:00"
METRICS_REF = f"evidence://{REQUEST_ID}/metrics/metrics-1"
DEVICE_REF = f"evidence://{REQUEST_ID}/device/device-1"
EVENT_REF = f"event://{REQUEST_ID}/event/event-1"
PLAN_REF = f"plan://{REQUEST_ID}/plan/plan-1"


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def create_trace(root: Path, request_id: str = REQUEST_ID) -> Path:
    directory = root / request_id / "v12"
    metrics_ref = f"evidence://{request_id}/metrics/metrics-1"
    device_ref = f"evidence://{request_id}/device/device-1"
    event_ref = f"event://{request_id}/event/event-1"
    plan_ref = f"plan://{request_id}/plan/plan-1"
    judge_ref = (
        f"artifact://{request_id}/judge_result/judge-1"
    )
    report_ref = f"report://{request_id}/report/report-1"
    rca_ref = f"artifact://{request_id}/rca_result/rca-1"

    write_json(
        directory / "agent_runs.json",
        {
            "schema_version": "v12.1",
            "request_id": request_id,
            "final_state": "completed",
            "state_history": ["received", "triage", "completed"],
            "fallback_to_legacy": True,
            "stop_reason": None,
            "elapsed_ms": 123,
            "agent_runs": [
                {
                    "schema_version": "v12.1",
                    "request_id": request_id,
                    "agent_name": "triage",
                    "status": "success",
                    "started_at": NOW,
                    "finished_at": NOW,
                    "duration_ms": 10,
                    "inputs_ref": [],
                    "outputs_ref": [event_ref],
                    "warnings": [],
                    "errors": [],
                    "external_calls": [],
                },
                {
                    "schema_version": "v12.1",
                    "request_id": request_id,
                    "agent_name": "device_evidence",
                    "status": "partial",
                    "started_at": NOW,
                    "finished_at": NOW,
                    "duration_ms": 40,
                    "inputs_ref": [plan_ref],
                    "outputs_ref": [device_ref],
                    "warnings": [],
                    "errors": [
                        {
                            "code": "device_command_partial",
                            "message": "summary only",
                        }
                    ],
                    "external_calls": [],
                },
            ],
        },
    )
    write_json(
        directory / "evidence_bundle.json",
        {
            "schema_version": "v12.1",
            "request_id": request_id,
            "event_ref": event_ref,
            "plan_ref": plan_ref,
            "bundle_status": "partial",
            "built_at": NOW,
            "evidence": {
                "metrics": {
                    "request_id": request_id,
                    "source": "metrics",
                    "status": "success",
                    "reason": None,
                    "evidence_refs": [metrics_ref],
                    "facts": {
                        "prometheus_samples": "DO-NOT-EXPOSE"
                    },
                },
                "device": {
                    "request_id": request_id,
                    "source": "device",
                    "status": "partial",
                    "reason": "partial_commands",
                    "evidence_refs": [device_ref],
                    "facts": {
                        "full_device_output": "DO-NOT-EXPOSE"
                    },
                },
                "logs": {
                    "request_id": request_id,
                    "source": "logs",
                    "status": "not_available",
                    "reason": "logs_evidence_not_approved",
                    "evidence_refs": [],
                    "facts": {"full_logs": "DO-NOT-EXPOSE"},
                },
                "knowledge": {
                    "request_id": request_id,
                    "source": "knowledge",
                    "status": "not_available",
                    "reason": "local_knowledge_base_not_built",
                    "source_refs": [],
                    "context_facts": [],
                },
            },
        },
    )
    write_json(
        directory / "judge_result.json",
        {
            "schema_version": "v12.1",
            "request_id": request_id,
            "status": "partial",
            "required_sources": ["metrics", "device"],
            "missing_required_sources": [],
            "missing_optional_sources": ["logs", "knowledge"],
            "conflicts": [
                {
                    "statement": "metrics and device conflict",
                    "evidence_refs": [metrics_ref, device_ref],
                    "severity": "medium",
                }
            ],
            "rca_allowed": True,
            "confidence_cap": 0.7,
            "evidence_refs": [metrics_ref, device_ref],
            "judged_at": NOW,
        },
    )
    write_json(
        directory / "rca_result.json",
        {
            "schema_version": "v12.1",
            "request_id": request_id,
            "status": "partial",
            "event_ref": event_ref,
            "bundle_ref": (
                f"artifact://{request_id}/evidence_bundle/bundle-1"
            ),
            "judge_ref": judge_ref,
            "candidates": [
                {
                    "statement": "candidate A",
                    "confidence": 0.65,
                    "supporting_evidence_refs": [
                        metrics_ref,
                        device_ref,
                    ],
                    "contradicting_evidence_refs": [],
                    "missing_evidence": ["logs"],
                    "uncertainties": ["device partial"],
                    "scope": {"raw_payload": "DO-NOT-EXPOSE"},
                }
            ],
            "missing_evidence": ["knowledge"],
            "uncertainties": ["logs unavailable"],
            "generated_at": NOW,
            "provider": "mock",
        },
    )
    write_json(
        directory / "report.json",
        {
            "schema_version": "v12.1",
            "request_id": request_id,
            "status": "success",
            "title": "Agent report",
            "summary": "summary",
            "sections": [],
            "evidence_refs": [metrics_ref],
            "artifact_refs": [report_ref],
            "generated_at": NOW,
            "notification_compatible": True,
        },
    )
    write_json(
        directory / "shadow_integration.json",
        {
            "schema_version": "v12.1",
            "request_id": request_id,
            "route": "/webhook/alertmanager",
            "status": "completed",
            "reason": "shadow_completed",
            "legacy_preserved": True,
            "fail_open_to_legacy": True,
            "legacy_notification_count": 1,
            "shadow_notification_count": 0,
            "notification_count_delta": 0,
            "second_card_sent": False,
            "production_card_replaced": False,
            "artifact_refs": [rca_ref],
            "error_code": None,
            "started_at": NOW,
            "finished_at": NOW,
            "duration_ms": 1,
        },
    )
    return directory


class AgentTraceReadServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "requests"
        create_trace(self.root)
        self.service = AgentTraceReadService(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_health_is_read_only(self) -> None:
        result = self.service.health()
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["read_only"])
        self.assertFalse(result["external_calls"]["production_write"])

    def test_health_counts_trace(self) -> None:
        self.assertEqual(self.service.health()["trace_count"], 1)

    def test_health_reports_external_calls_false(self) -> None:
        calls = self.service.health()["external_calls"]
        self.assertTrue(all(value is False for value in calls.values()))

    def test_list_returns_request(self) -> None:
        result = self.service.list_traces()
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["items"][0]["request_id"], REQUEST_ID)

    def test_list_search_matches_request_id(self) -> None:
        self.assertEqual(
            self.service.list_traces(q="batch-n")["total"],
            1,
        )

    def test_list_search_excludes_nonmatch(self) -> None:
        self.assertEqual(
            self.service.list_traces(q="missing")["total"],
            0,
        )

    def test_list_status_matches_final_state(self) -> None:
        self.assertEqual(
            self.service.list_traces(status="completed")["total"],
            1,
        )

    def test_list_status_matches_agent_status(self) -> None:
        self.assertEqual(
            self.service.list_traces(status="partial")["total"],
            1,
        )

    def test_list_pagination(self) -> None:
        create_trace(self.root, OTHER_ID)
        first = self.service.list_traces(limit=1, offset=0)
        second = self.service.list_traces(limit=1, offset=1)
        self.assertEqual(len(first["items"]), 1)
        self.assertEqual(len(second["items"]), 1)
        self.assertNotEqual(
            first["items"][0]["request_id"],
            second["items"][0]["request_id"],
        )

    def test_invalid_limit_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.service.list_traces(limit=0)

    def test_boolean_limit_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.service.list_traces(limit=True)

    def test_invalid_offset_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.service.list_traces(offset=-1)

    def test_detail_contains_agent_order(self) -> None:
        detail = self.service.get_trace(REQUEST_ID)
        self.assertEqual(
            [item["order"] for item in detail["agent_runs"]],
            [1, 2],
        )

    def test_detail_contains_status_and_duration(self) -> None:
        detail = self.service.get_trace(REQUEST_ID)
        self.assertEqual(detail["agent_runs"][1]["status"], "partial")
        self.assertEqual(detail["agent_runs"][1]["duration_ms"], 40)

    def test_detail_contains_input_refs(self) -> None:
        detail = self.service.get_trace(REQUEST_ID)
        self.assertIn(PLAN_REF, detail["agent_runs"][1]["inputs_ref"])

    def test_detail_contains_output_refs(self) -> None:
        detail = self.service.get_trace(REQUEST_ID)
        self.assertIn(
            DEVICE_REF,
            detail["agent_runs"][1]["outputs_ref"],
        )

    def test_detail_contains_error_category(self) -> None:
        detail = self.service.get_trace(REQUEST_ID)
        self.assertEqual(
            detail["agent_runs"][1]["error_categories"],
            ["device_command_partial"],
        )

    def test_detail_contains_evidence_source_status(self) -> None:
        detail = self.service.get_trace(REQUEST_ID)
        statuses = {
            item["source"]: item["status"]
            for item in detail["evidence_sources"]
        }
        self.assertEqual(statuses["logs"], "not_available")
        self.assertEqual(statuses["device"], "partial")

    def test_detail_contains_evidence_reasons(self) -> None:
        detail = self.service.get_trace(REQUEST_ID)
        reasons = {
            item["source"]: item["reason"]
            for item in detail["evidence_sources"]
        }
        self.assertEqual(
            reasons["logs"],
            "logs_evidence_not_approved",
        )

    def test_detail_contains_judge_result(self) -> None:
        detail = self.service.get_trace(REQUEST_ID)
        self.assertEqual(detail["judge"]["status"], "partial")
        self.assertEqual(detail["judge"]["confidence_cap"], 0.7)

    def test_detail_contains_missing_evidence(self) -> None:
        detail = self.service.get_trace(REQUEST_ID)
        self.assertEqual(
            detail["judge"]["missing_optional_sources"],
            ["logs", "knowledge"],
        )

    def test_detail_contains_conflicts(self) -> None:
        detail = self.service.get_trace(REQUEST_ID)
        self.assertEqual(
            detail["judge"]["conflicts"][0]["severity"],
            "medium",
        )

    def test_detail_contains_rca_candidate(self) -> None:
        detail = self.service.get_trace(REQUEST_ID)
        self.assertEqual(
            detail["rca"]["candidates"][0]["statement"],
            "candidate A",
        )

    def test_detail_contains_confidence(self) -> None:
        detail = self.service.get_trace(REQUEST_ID)
        self.assertEqual(
            detail["rca"]["candidates"][0]["confidence"],
            0.65,
        )

    def test_detail_contains_uncertainties(self) -> None:
        detail = self.service.get_trace(REQUEST_ID)
        self.assertIn(
            "device partial",
            detail["rca"]["candidates"][0]["uncertainties"],
        )

    def test_detail_contains_fallback(self) -> None:
        detail = self.service.get_trace(REQUEST_ID)
        self.assertTrue(detail["fallback_to_legacy"])
        self.assertTrue(detail["shadow"]["legacy_preserved"])

    def test_detail_contains_shadow_notification_delta(self) -> None:
        detail = self.service.get_trace(REQUEST_ID)
        self.assertEqual(
            detail["shadow"]["notification_count_delta"],
            0,
        )

    def test_detail_contains_report_summary(self) -> None:
        detail = self.service.get_trace(REQUEST_ID)
        self.assertEqual(detail["report"]["summary"], "summary")

    def test_detail_collects_artifact_refs(self) -> None:
        detail = self.service.get_trace(REQUEST_ID)
        self.assertIn(METRICS_REF, detail["artifact_refs"])
        self.assertIn(DEVICE_REF, detail["artifact_refs"])

    def test_detail_excludes_full_sensitive_artifacts(self) -> None:
        detail = self.service.get_trace(REQUEST_ID)
        encoded = json.dumps(detail, ensure_ascii=False, sort_keys=True)
        self.assertNotIn("DO-NOT-EXPOSE", encoded)
        self.assertFalse(
            detail["data_boundaries"]["full_logs_exposed"]
        )

    def test_detail_external_calls_are_false(self) -> None:
        detail = self.service.get_trace(REQUEST_ID)
        self.assertTrue(
            all(
                value is False
                for value in detail["external_calls"].values()
            )
        )

    def test_missing_trace_returns_not_found(self) -> None:
        with self.assertRaises(FileNotFoundError):
            self.service.get_trace("req-missing")

    def test_invalid_request_id_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.service.get_trace("../escape")

    def test_corrupt_agent_runs_rejected(self) -> None:
        write_json(
            self.root / REQUEST_ID / "v12" / "agent_runs.json",
            {"request_id": REQUEST_ID, "agent_runs": "bad"},
        )
        with self.assertRaises(AgentTraceCorruptError):
            self.service.get_trace(REQUEST_ID)

    def test_reference_request_mismatch_rejected(self) -> None:
        path = self.root / REQUEST_ID / "v12" / "judge_result.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["evidence_refs"] = [
            "evidence://req-other/metrics/metrics-1"
        ]
        write_json(path, payload)
        with self.assertRaises(AgentTraceCorruptError):
            self.service.get_trace(REQUEST_ID)

    def test_symlink_trace_directory_rejected(self) -> None:
        target = self.root / REQUEST_ID / "v12"
        moved = self.root / REQUEST_ID / "real-v12"
        target.rename(moved)
        target.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(AgentTraceReadError):
            self.service.get_trace(REQUEST_ID)

    def test_optional_judge_file_may_be_missing(self) -> None:
        (self.root / REQUEST_ID / "v12" / "judge_result.json").unlink()
        self.assertIsNone(self.service.get_trace(REQUEST_ID)["judge"])

    def test_optional_rca_file_may_be_missing(self) -> None:
        (self.root / REQUEST_ID / "v12" / "rca_result.json").unlink()
        self.assertIsNone(self.service.get_trace(REQUEST_ID)["rca"])


class AgentTraceRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name) / "requests"
        create_trace(root)
        service = AgentTraceReadService(root)
        app = FastAPI()
        app.include_router(create_agent_trace_api_router(lambda: service))
        app.include_router(create_agent_trace_ui_router(lambda: service))
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_api_health_route(self) -> None:
        self.assertEqual(self.client.get("/agent/health").status_code, 200)

    def test_api_list_route(self) -> None:
        response = self.client.get("/agent/traces")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["total"], 1)

    def test_api_detail_route(self) -> None:
        response = self.client.get(f"/agent/traces/{REQUEST_ID}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["request_id"], REQUEST_ID)

    def test_api_missing_route_returns_404(self) -> None:
        response = self.client.get("/agent/traces/req-missing")
        self.assertEqual(response.status_code, 404)

    def test_api_invalid_id_returns_404_or_400(self) -> None:
        response = self.client.get("/agent/traces/%2E%2E")
        self.assertIn(response.status_code, {400, 404})

    def test_ui_index_route(self) -> None:
        response = self.client.get("/agent-ui")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Agent Trace Requests", response.text)

    def test_ui_detail_route(self) -> None:
        response = self.client.get(f"/agent-ui/{REQUEST_ID}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Agent execution order", response.text)

    def test_ui_displays_required_sections(self) -> None:
        text = self.client.get(f"/agent-ui/{REQUEST_ID}").text
        for value in (
            "Evidence source status",
            "Evidence Judge",
            "RCA candidates",
            "Shadow / fallback",
            "Artifact references",
            "Uncertainties",
        ):
            self.assertIn(value, text)

    def test_ui_uses_no_store(self) -> None:
        response = self.client.get("/agent-ui")
        self.assertEqual(response.headers.get("cache-control"), "no-store")

    def test_ui_detail_uses_no_store(self) -> None:
        response = self.client.get(f"/agent-ui/{REQUEST_ID}")
        self.assertEqual(response.headers.get("cache-control"), "no-store")

    def test_ui_missing_route_returns_404(self) -> None:
        response = self.client.get("/agent-ui/req-missing")
        self.assertEqual(response.status_code, 404)

    def test_ui_does_not_expose_marker(self) -> None:
        response = self.client.get(f"/agent-ui/{REQUEST_ID}")
        self.assertNotIn("DO-NOT-EXPOSE", response.text)

    def test_production_modules_have_no_external_clients(self) -> None:
        root = Path(__file__).resolve().parents[1]
        text = (
            (root / "netaiops/v12/api.py").read_text(encoding="utf-8")
            + (root / "netaiops/v12/ui.py").read_text(encoding="utf-8")
        ).lower()
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

    def test_app_registers_agent_routes(self) -> None:
        import app as production_app

        paths = {route.path for route in production_app.app.routes}
        for path in (
            "/agent/health",
            "/agent/traces",
            "/agent/traces/{request_id}",
            "/agent-ui",
            "/agent-ui/{request_id}",
        ):
            self.assertIn(path, paths)

    def test_portal_has_third_entry(self) -> None:
        from netaiops.ui_portal import _PORTAL_HTML

        self.assertIn('href="/agent-ui"', _PORTAL_HTML)
        self.assertIn("Agent Trace", _PORTAL_HTML)


if __name__ == "__main__":
    unittest.main()
