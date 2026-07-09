from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from netaiops.governance.api import create_governance_router
from netaiops.governance.contracts import GOVERNANCE_SCHEMA_VERSION
from netaiops.governance.service import GovernanceReadService, normalise_collection_name
from netaiops.governance.store import GovernanceStore

FIXED_TIME = "2026-07-08T00:00:00+00:00"
SHA = "a" * 64


def memory_payload(memory_id: str = "memory_test") -> dict:
    return {
        "schema_version": GOVERNANCE_SCHEMA_VERSION,
        "memory_id": memory_id,
        "request_id": "request_test",
        "created_at": FIXED_TIME,
        "source_type": "alertmanager",
        "alert_time": FIXED_TIME,
        "device": {"ip": "10.0.0.1", "name": "device-a"},
        "object": {"name": "Ethernet1/1"},
        "family": "interface_packet_loss_or_discards_high",
        "alert_summary": "packet loss high",
        "analysis_summary": "summary only",
        "evidence_status": {"metrics": "success", "device": "success", "logs": "not_available"},
        "command_summary": {"total": 2, "failed": 0, "readonly_only": True},
        "review_summary": {"status": "success"},
        "notification_result": {"status": "success"},
        "quality_flags": ["logs_not_available"],
        "git_metadata": {"commit": "abc123"},
        "artifact_refs": [{"kind": "analysis", "path": "data/analysis/request_test.analysis.json", "sha256": SHA, "exists": True, "size_bytes": 1}],
    }


def report_payload(report_id: str = "report_test") -> dict:
    return {"schema_version": GOVERNANCE_SCHEMA_VERSION, "report_id": report_id, "created_at": FIXED_TIME, "period": "daily", "summary": {"request_count": 1}}


class GovernanceApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "governance"
        self.store = GovernanceStore(self.root)
        self.service = GovernanceReadService(self.root)
        self.app = FastAPI()
        self.app.include_router(create_governance_router(lambda: self.service))
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_health_is_read_only_and_does_not_create_root(self) -> None:
        missing_root = Path(self.tempdir.name) / "missing-governance"
        service = GovernanceReadService(missing_root)
        result = service.health()
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["read_only"])
        self.assertFalse(result["external_calls"]["glm"])
        self.assertFalse(missing_root.exists())

    def test_collection_aliases_are_normalised(self) -> None:
        self.assertEqual(normalise_collection_name("memories"), "incident_memory")
        self.assertEqual(normalise_collection_name("learning-signals"), "signals")
        self.assertEqual(normalise_collection_name("audits"), "audits")

    def test_unknown_collection_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            normalise_collection_name("../../data")

    def test_collections_endpoint_lists_known_readonly_collections(self) -> None:
        data = self.client.get("/governance/collections").json()
        self.assertEqual(data["status"], "ok")
        names = {item["collection"] for item in data["collections"]}
        self.assertIn("incident_memory", names)
        self.assertIn("replays", names)
        self.assertTrue(data["read_only"])

    def test_list_empty_memories(self) -> None:
        response = self.client.get("/governance/memories")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["collection"]["collection"], "incident_memory")
        self.assertEqual(data["total"], 0)
        self.assertEqual(data["items"], [])

    def test_list_and_read_memory_record(self) -> None:
        self.store.write("incident_memory", "memory_test", memory_payload())
        listed = self.client.get("/governance/memories").json()
        self.assertEqual(listed["total"], 1)
        self.assertEqual(listed["items"][0]["memory_id"], "memory_test")
        detail = self.client.get("/governance/memories/memory_test").json()
        self.assertEqual(detail["data"]["family"], "interface_packet_loss_or_discards_high")
        self.assertEqual(detail["external_calls"]["device"], False)

    def test_generic_collections_endpoint_can_list_reports(self) -> None:
        self.store.write("reports", "report_test", report_payload())
        response = self.client.get("/governance/collections/reports")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["report_id"], "report_test")

    def test_generic_record_endpoint_can_read_report(self) -> None:
        self.store.write("reports", "report_test", report_payload())
        response = self.client.get("/governance/collections/reports/report_test")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"]["summary"]["request_count"], 1)

    def test_missing_record_returns_404(self) -> None:
        response = self.client.get("/governance/reports/no_such_report")
        self.assertEqual(response.status_code, 404)

    def test_invalid_collection_endpoint_returns_400(self) -> None:
        response = self.client.get("/governance/collections/no_such_collection")
        self.assertEqual(response.status_code, 400)

    def test_pagination_validation_is_enforced_by_fastapi(self) -> None:
        response = self.client.get("/governance/memories?page=0")
        self.assertEqual(response.status_code, 422)

    def test_governance_endpoints_are_read_only(self) -> None:
        response = self.client.post("/governance/memories", json={})
        self.assertEqual(response.status_code, 405)

    def test_summary_counts_records_without_external_calls(self) -> None:
        self.store.write("reports", "report_test", report_payload())
        response = self.client.get("/governance/summary")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total_records"], 1)
        self.assertFalse(data["external_calls"]["notification"])

    def test_corrupt_record_is_isolated_during_list(self) -> None:
        reports = self.root / "reports"
        reports.mkdir(parents=True)
        (reports / "report_bad.json").write_text("{bad json", encoding="utf-8")
        data = self.client.get("/governance/reports").json()
        self.assertEqual(data["total"], 0)
        self.assertEqual(data["corrupt_count"], 1)
        self.assertEqual(len(data["errors"]), 1)

    def test_health_reports_warning_for_corrupt_runtime_record(self) -> None:
        reports = self.root / "reports"
        reports.mkdir(parents=True)
        (reports / "report_bad.json").write_text("{bad json", encoding="utf-8")
        data = self.client.get("/governance/health").json()
        self.assertEqual(data["status"], "warning")
        self.assertEqual(data["corrupt_total"], 1)

    def test_service_list_rejects_bad_page_size(self) -> None:
        with self.assertRaises(ValueError):
            self.service.list_records("reports", page_size=501)

    def test_service_get_record_uses_aliases(self) -> None:
        self.store.write("reports", "report_test", report_payload())
        data = self.service.get_record("reports", "report_test")
        self.assertEqual(data["collection"]["id_field"], "report_id")
        self.assertEqual(data["data"]["report_id"], "report_test")

    def test_production_app_registers_governance_routes(self) -> None:
        from app import app as production_app
        paths = {getattr(route, "path", "") for route in production_app.routes}
        self.assertIn("/governance/health", paths)
        self.assertIn("/governance/memories", paths)
        self.assertIn("/governance/audits/{audit_id}", paths)

    def test_governance_routes_do_not_expose_mutation_methods(self) -> None:
        from app import app as production_app
        for route in production_app.routes:
            path = getattr(route, "path", "")
            methods = set(getattr(route, "methods", set()) or set())
            if path.startswith("/governance"):
                self.assertTrue(methods <= {"GET", "HEAD"}, (path, methods))

    def test_response_payloads_use_current_schema_version(self) -> None:
        data = self.client.get("/governance/health").json()
        self.assertEqual(data["schema_version"], GOVERNANCE_SCHEMA_VERSION)
        data = self.client.get("/governance/collections").json()
        self.assertEqual(data["schema_version"], GOVERNANCE_SCHEMA_VERSION)


if __name__ == "__main__":
    unittest.main()
