from __future__ import annotations

import unittest
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from netaiops.governance.ui import UI_VERSION, create_governance_ui_router


class FakeGovernanceService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []
        self.external_call_attempted = False
        self.records = {
            "incident_memory": [
                {
                    "memory_id": "memory_1",
                    "request_id": "req_1",
                    "created_at": "2026-07-09T00:00:00+00:00",
                    "device": {"hostname": "SW01", "ip": "10.0.0.1"},
                    "family": "interface_status_or_flap",
                    "quality_flags": ["command_failed"],
                }
            ],
            "signals": [
                {
                    "signal_id": "signal_1",
                    "signal_type": "cli_hard_error",
                    "severity": "error",
                    "proposal_eligible": True,
                    "created_at": "2026-07-09T00:01:00+00:00",
                }
            ],
            "proposals": [
                {
                    "proposal_id": "proposal_1",
                    "signal_type": "cli_hard_error",
                    "status": "draft",
                    "affected_family": "interface_status_or_flap",
                    "created_at": "2026-07-09T00:02:00+00:00",
                }
            ],
            "replays": [
                {
                    "replay_id": "replay_1",
                    "request_id": "req_1",
                    "quality_delta": {"outcome": "unchanged"},
                    "safety_delta": {"regression": False},
                    "created_at": "2026-07-09T00:03:00+00:00",
                }
            ],
            "reports": [
                {
                    "report_id": "report_1",
                    "period": "daily",
                    "summary": {"request_count": 1, "signal_count": 1},
                    "created_at": "2026-07-09T00:04:00+00:00",
                }
            ],
            "audits": [
                {
                    "audit_id": "audit_1",
                    "status": "PASS",
                    "branch": "main",
                    "commit": "a" * 40,
                    "created_at": "2026-07-09T00:05:00+00:00",
                }
            ],
            "backfill": [],
        }

    def health(self) -> dict[str, Any]:
        self.calls.append(("health", None))
        return {
            "status": "ok",
            "service": "netaiops-governance-api",
            "api_version": "11.0.0-governance-api-v1",
            "schema_version": "11.0.0-contract-v1",
            "root": "/tmp/governance",
            "read_only": True,
            "external_calls": {
                "glm": False,
                "prometheus": False,
                "device": False,
                "notification": False,
                "production_write": False,
            },
            "collections": {
                name: {"total": len(items), "corrupt_count": 0, "sample_count": min(1, len(items))}
                for name, items in self.records.items()
            },
            "corrupt_total": 0,
        }

    def summary(self) -> dict[str, Any]:
        self.calls.append(("summary", None))
        return {
            "status": "ok",
            "api_version": "11.0.0-governance-api-v1",
            "schema_version": "11.0.0-contract-v1",
            "read_only": True,
            "external_calls": {
                "glm": False,
                "prometheus": False,
                "device": False,
                "notification": False,
                "production_write": False,
            },
            "total_records": sum(len(items) for items in self.records.values()),
            "corrupt_total": 0,
            "by_collection": {name: len(items) for name, items in self.records.items()},
        }

    def list_records(self, collection: str, *, page: int = 1, page_size: int = 50, descending: bool = True) -> dict[str, Any]:
        self.calls.append(("list_records", collection))
        items = list(self.records[collection])
        return {
            "status": "ok",
            "read_only": True,
            "collection": {"collection": collection, "display_name": collection, "id_field": self.id_field(collection)},
            "page": page,
            "page_size": page_size,
            "total": len(items),
            "corrupt_count": 0,
            "items": items,
            "errors": [],
        }

    def get_record(self, collection: str, record_id: str) -> dict[str, Any]:
        self.calls.append(("get_record", (collection, record_id)))
        for item in self.records[collection]:
            if item.get(self.id_field(collection)) == record_id:
                return {
                    "status": "ok",
                    "read_only": True,
                    "collection": {"collection": collection, "id_field": self.id_field(collection)},
                    "record_id": record_id,
                    "data": item,
                }
        raise FileNotFoundError(record_id)

    @staticmethod
    def id_field(collection: str) -> str:
        return {
            "incident_memory": "memory_id",
            "signals": "signal_id",
            "proposals": "proposal_id",
            "replays": "replay_id",
            "reports": "report_id",
            "audits": "audit_id",
            "backfill": "backfill_id",
        }[collection]


class GovernanceUiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fake = FakeGovernanceService()
        app = FastAPI()
        app.include_router(create_governance_ui_router(lambda: self.fake))
        self.client = TestClient(app)

    def test_ui_version_is_frozen(self) -> None:
        self.assertEqual(UI_VERSION, "11.0.0-governance-ui-v1")

    def test_dashboard_returns_html(self) -> None:
        response = self.client.get("/governance-ui")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])
        self.assertIn("NetAIOps Governance UI", response.text)
        self.assertIn("read_only: True", response.text)
        self.assertIn("total_records", response.text)

    def test_dashboard_has_collection_links(self) -> None:
        response = self.client.get("/governance-ui")
        for section in ("memories", "signals", "proposals", "replays", "reports", "audits"):
            self.assertIn(f"/governance-ui/{section}", response.text)

    def test_dashboard_lists_external_call_policy(self) -> None:
        response = self.client.get("/governance-ui")
        self.assertIn("glm: False", response.text)
        self.assertIn("production_write: False", response.text)

    def test_slash_dashboard_route_works(self) -> None:
        response = self.client.get("/governance-ui/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Overview", response.text)

    def test_memories_page_renders_record(self) -> None:
        response = self.client.get("/governance-ui/memories")
        self.assertEqual(response.status_code, 200)
        self.assertIn("interface_status_or_flap", response.text)
        self.assertIn("command_failed", response.text)
        self.assertIn("/governance-ui/memories/memory_1", response.text)

    def test_signals_page_renders_record(self) -> None:
        response = self.client.get("/governance-ui/signals")
        self.assertEqual(response.status_code, 200)
        self.assertIn("cli_hard_error", response.text)
        self.assertIn("proposal_eligible=True", response.text)

    def test_proposals_page_renders_record(self) -> None:
        response = self.client.get("/governance-ui/proposals")
        self.assertEqual(response.status_code, 200)
        self.assertIn("proposal_1", response.text)
        self.assertIn("status=draft", response.text)

    def test_replays_page_renders_quality_summary(self) -> None:
        response = self.client.get("/governance-ui/replays")
        self.assertEqual(response.status_code, 200)
        self.assertIn("quality=unchanged", response.text)
        self.assertIn("safety_regression=False", response.text)

    def test_reports_page_renders_summary(self) -> None:
        response = self.client.get("/governance-ui/reports")
        self.assertEqual(response.status_code, 200)
        self.assertIn("requests=1", response.text)
        self.assertIn("signals=1", response.text)

    def test_audits_page_renders_commit(self) -> None:
        response = self.client.get("/governance-ui/audits")
        self.assertEqual(response.status_code, 200)
        self.assertIn("PASS", response.text)
        self.assertIn("commit=aaaaaaaaaaaa", response.text)

    def test_empty_backfill_page_renders_no_records(self) -> None:
        response = self.client.get("/governance-ui/backfill")
        self.assertEqual(response.status_code, 200)
        self.assertIn("No records found", response.text)

    def test_pagination_parameters_are_passed(self) -> None:
        response = self.client.get("/governance-ui/memories?page=2&page_size=1&descending=false")
        self.assertEqual(response.status_code, 200)
        self.assertIn("page=2", response.text)
        self.assertIn("page_size=1", response.text)

    def test_detail_page_renders_json(self) -> None:
        response = self.client.get("/governance-ui/memories/memory_1")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Record JSON", response.text)
        self.assertIn("&quot;memory_id&quot;: &quot;memory_1&quot;", response.text)

    def test_detail_page_escapes_html(self) -> None:
        self.fake.records["incident_memory"][0]["alert_summary"] = "<script>alert(1)</script>"
        response = self.client.get("/governance-ui/memories/memory_1")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("<script>alert(1)</script>", response.text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", response.text)

    def test_unknown_section_is_bad_request(self) -> None:
        response = self.client.get("/governance-ui/not-a-section")
        self.assertEqual(response.status_code, 400)

    def test_unknown_detail_section_is_bad_request(self) -> None:
        response = self.client.get("/governance-ui/not-a-section/x")
        self.assertEqual(response.status_code, 400)

    def test_detail_missing_record_is_404(self) -> None:
        response = self.client.get("/governance-ui/memories/missing")
        self.assertEqual(response.status_code, 404)

    def test_no_external_call_methods_exist_on_fake_service(self) -> None:
        response = self.client.get("/governance-ui")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.fake.external_call_attempted)


if __name__ == "__main__":
    unittest.main()
