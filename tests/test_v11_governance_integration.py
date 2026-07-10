from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from netaiops.governance.contracts import GOVERNANCE_SCHEMA_VERSION
from netaiops.governance.integration import (
    INTEGRATION_VERSION,
    GovernanceIntegrationError,
    build_governance_artifacts,
    build_governance_artifacts_safe,
    discover_request_ids,
    run_backfill,
)
from netaiops.governance.store import GovernanceStore

FIXED_TIME = datetime(2026, 7, 10, 1, 0, tzinfo=timezone.utc)


class GovernanceIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.project = Path(self.tempdir.name) / "project"
        self.project.mkdir()
        self.governance = Path(self.tempdir.name) / "governance"
        subprocess.run(["git", "init"], cwd=self.project, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=self.project, check=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=self.project, check=True)
        (self.project / "README.md").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=self.project, check=True)
        subprocess.run(["git", "commit", "-m", "fixture"], cwd=self.project, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def make_request(self, request_id: str, *, fallback: bool = False) -> None:
        normalized = self.project / "data" / "normalized" / f"alertmanager_{request_id}.json"
        normalized.parent.mkdir(parents=True, exist_ok=True)
        normalized.write_text(
            json.dumps(
                {
                    "request_id": request_id,
                    "source": "alertmanager",
                    "created_at": FIXED_TIME.isoformat(),
                    "events": [
                        {
                            "device_name": "fixture-device",
                            "device_ip": "10.0.0.1",
                            "interface": "Ethernet1/1",
                            "description": "fixture alert",
                            "timestamp": FIXED_TIME.isoformat(),
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        hub = self.project / "data" / "evidence_hub" / "requests" / request_id
        hub.mkdir(parents=True, exist_ok=True)
        (hub / "summary.json").write_text(
            json.dumps(
                {
                    "summary": {
                        "family": "generic_network_readonly" if fallback else "fixture_family",
                        "judgement": "fixture judgement",
                    }
                }
            ),
            encoding="utf-8",
        )
        if fallback:
            plan = self.project / "data" / "plans" / f"alertmanager_{request_id}.plan.json"
            plan.parent.mkdir(parents=True, exist_ok=True)
            plan.write_text(
                json.dumps(
                    {
                        "classification": {
                            "family": "generic_network_readonly",
                            "match_reason": "family_fallback",
                        },
                        "summary": "fixture plan",
                    }
                ),
                encoding="utf-8",
            )

    def build(self, request_id: str, **kwargs):
        generated_at = kwargs.pop("generated_at", FIXED_TIME)
        return build_governance_artifacts(
            request_id,
            project_root=self.project,
            governance_root=self.governance,
            generated_at=generated_at,
            **kwargs,
        )

    def test_build_writes_memory_and_logs_status_signal(self) -> None:
        self.make_request("req_001")
        result = self.build("req_001")
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["memory_id"], "memory_req_001")
        self.assertIn("logs_not_available", result["signal_summary"]["by_type"])
        store = GovernanceStore(self.governance)
        memory = store.read("incident_memory", "memory_req_001")
        self.assertEqual(memory["request_id"], "req_001")
        self.assertEqual(memory["evidence_status"]["logs"], "not_available")

    def test_build_is_idempotent_and_reuses_existing_records(self) -> None:
        self.make_request("req_002")
        first = self.build("req_002")
        store = GovernanceStore(self.governance)
        signal_count = store.list_records("signals").total
        second = self.build("req_002", generated_at=FIXED_TIME)
        self.assertGreater(first["created_count"], 0)
        self.assertEqual(second["created_count"], 0)
        self.assertGreaterEqual(second["reused_count"], 2)
        self.assertEqual(store.list_records("incident_memory").total, 1)
        self.assertEqual(store.list_records("signals").total, signal_count)

    def test_dry_run_does_not_create_governance_root(self) -> None:
        self.make_request("req_003")
        result = self.build("req_003", write=False)
        self.assertEqual(result["status"], "dry_run")
        self.assertTrue(result["dry_run"])
        self.assertFalse(self.governance.exists())

    def test_fallback_signal_generates_safe_draft_proposal(self) -> None:
        self.make_request("req_004", fallback=True)
        result = self.build("req_004")
        self.assertTrue(result["proposal_ids"])
        proposal = GovernanceStore(self.governance).read("proposals", result["proposal_ids"][0])
        self.assertEqual(proposal["status"], "draft")
        self.assertFalse(proposal["risk"]["auto_apply"])
        self.assertEqual(proposal["replay_scope"]["mode"], "offline")

    def test_no_proposals_option_suppresses_proposal_build(self) -> None:
        self.make_request("req_005", fallback=True)
        result = self.build("req_005", include_proposals=False)
        self.assertEqual(result["proposal_ids"], [])
        self.assertEqual(GovernanceStore(self.governance).list_records("proposals").total, 0)

    def test_safe_wrapper_isolates_missing_request(self) -> None:
        result = build_governance_artifacts_safe(
            "missing_request",
            project_root=self.project,
            governance_root=self.governance,
            generated_at=FIXED_TIME,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "failed")
        self.assertIn("no request artifacts", result["error"])

    def test_safe_wrapper_logs_failure_without_raising(self) -> None:
        logger = Mock()
        result = build_governance_artifacts_safe(
            "missing_request",
            project_root=self.project,
            governance_root=self.governance,
            generated_at=FIXED_TIME,
            logger=logger,
        )
        self.assertFalse(result["ok"])
        logger.exception.assert_called_once()

    def test_external_call_flags_are_false(self) -> None:
        self.make_request("req_006")
        result = self.build("req_006", write=False)
        for name in ("glm", "prometheus", "device", "notification", "elasticsearch"):
            self.assertFalse(result["external_calls"][name])

    def test_generated_at_requires_timezone(self) -> None:
        self.make_request("req_007")
        with self.assertRaises(GovernanceIntegrationError):
            build_governance_artifacts(
                "req_007",
                project_root=self.project,
                governance_root=self.governance,
                generated_at=datetime(2026, 7, 10, 1, 0),
            )

    def test_discover_request_ids_is_bounded_and_descending(self) -> None:
        for request_id in ("20260701_a", "20260703_c", "20260702_b"):
            self.make_request(request_id)
        self.assertEqual(
            discover_request_ids(self.project, limit=2),
            ("20260703_c", "20260702_b"),
        )

    def test_discover_request_ids_ignores_unsafe_and_symlink_entries(self) -> None:
        requests = self.project / "data" / "evidence_hub" / "requests"
        requests.mkdir(parents=True, exist_ok=True)
        (requests / "bad id").mkdir()
        target = Path(self.tempdir.name) / "outside"
        target.mkdir()
        (requests / "symlink_req").symlink_to(target, target_is_directory=True)
        self.assertEqual(discover_request_ids(self.project, limit=20), ())

    def test_discover_limit_validation(self) -> None:
        with self.assertRaises(GovernanceIntegrationError):
            discover_request_ids(self.project, limit=0)
        with self.assertRaises(GovernanceIntegrationError):
            discover_request_ids(self.project, limit=10001)

    def test_backfill_dry_run_processes_bounded_requests_without_writes(self) -> None:
        self.make_request("req_101")
        self.make_request("req_102")
        report = run_backfill(
            project_root=self.project,
            governance_root=self.governance,
            limit=1,
            dry_run=True,
            generated_at=FIXED_TIME,
        )
        self.assertEqual(report["mode"], "dry_run")
        self.assertEqual(report["request_count"], 1)
        self.assertEqual(report["success_count"], 1)
        self.assertFalse(self.governance.exists())

    def test_backfill_execute_persists_records_and_run_record(self) -> None:
        self.make_request("req_201", fallback=True)
        report = run_backfill(
            project_root=self.project,
            governance_root=self.governance,
            request_ids=["req_201"],
            limit=5,
            dry_run=False,
            generated_at=FIXED_TIME,
        )
        self.assertEqual(report["status"], "completed")
        self.assertIsNotNone(report["backfill_record"])
        store = GovernanceStore(self.governance)
        self.assertEqual(store.list_records("incident_memory").total, 1)
        self.assertEqual(store.list_records("backfill").total, 1)

    def test_backfill_isolates_one_bad_request(self) -> None:
        self.make_request("req_good")
        report = run_backfill(
            project_root=self.project,
            governance_root=self.governance,
            request_ids=["missing", "req_good"],
            limit=5,
            dry_run=True,
            generated_at=FIXED_TIME,
        )
        self.assertEqual(report["success_count"], 1)
        self.assertEqual(report["failure_count"], 1)
        self.assertEqual(report["status"], "partial")

    def test_backfill_schema_and_version_are_explicit(self) -> None:
        report = run_backfill(
            project_root=self.project,
            governance_root=self.governance,
            request_ids=[],
            limit=5,
            dry_run=True,
            generated_at=FIXED_TIME,
        )
        self.assertEqual(report["schema_version"], GOVERNANCE_SCHEMA_VERSION)
        self.assertEqual(report["integration_version"], INTEGRATION_VERSION)

    def test_cli_dry_run_writes_only_requested_json_report(self) -> None:
        self.make_request("req_cli")
        report_path = Path(self.tempdir.name) / "report.json"
        output_root = Path(self.tempdir.name) / "cli-governance"
        tool = Path(__file__).resolve().parents[1] / "tools" / "v11_governance_backfill.py"
        completed = subprocess.run(
            [
                sys.executable,
                str(tool),
                "--project-root",
                str(self.project),
                "--output-root",
                str(output_root),
                "--limit",
                "1",
                "--dry-run",
                "--json-report",
                str(report_path),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(report_path.is_file())
        self.assertFalse(output_root.exists())
        self.assertEqual(json.loads(report_path.read_text())["mode"], "dry_run")

    def test_force_rebuild_keeps_stable_record_counts(self) -> None:
        self.make_request("req_force", fallback=True)
        self.build("req_force")
        store = GovernanceStore(self.governance)
        proposal_count = store.list_records("proposals").total
        self.build("req_force", force=True)
        self.assertEqual(store.list_records("incident_memory").total, 1)
        self.assertEqual(store.list_records("proposals").total, proposal_count)

    def test_app_hook_is_after_notification_and_returned(self) -> None:
        app_source = (Path(__file__).resolve().parents[1] / "app.py").read_text(encoding="utf-8")
        notify_pos = app_source.index("notify_result = send_notification(request_id)")
        governance_pos = app_source.index(
            "governance_result = _v11_build_governance_artifacts_safe(request_id)"
        )
        self.assertGreater(governance_pos, notify_pos)
        self.assertIn('"governance_result": governance_result', app_source)

    def test_app_helper_has_import_failure_isolation(self) -> None:
        app_source = (Path(__file__).resolve().parents[1] / "app.py").read_text(encoding="utf-8")
        self.assertIn("def _v11_build_governance_artifacts_safe", app_source)
        self.assertIn("governance sidecar failed", app_source)
        self.assertIn("except Exception as exc", app_source)


if __name__ == "__main__":
    unittest.main()
