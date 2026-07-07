from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from netaiops.governance import (
    ArtifactRef,
    AuditStatus,
    CONTRACT_REQUIRED_FIELDS,
    DEFAULT_EXTERNAL_CALL_POLICY,
    EvidenceSourceStatus,
    ExternalCallPolicy,
    GovernanceStatus,
    LEARNING_SIGNAL_TYPES,
    LOGS_NOT_AVAILABLE_REASON,
    ProposalStatus,
    REAL_FIXTURE_MATRIX,
    ReplayMode,
    SYNTHETIC_FIXTURE_MATRIX,
    assert_contract_shape,
    enum_values,
    get_fixture_spec,
    missing_required_fields,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_TOOL = PROJECT_ROOT / "tools" / "v11_baseline_inventory.py"


class GovernanceContractTests(unittest.TestCase):
    def test_evidence_status_values_are_frozen(self) -> None:
        self.assertEqual(
            enum_values(EvidenceSourceStatus),
            (
                "success",
                "partial",
                "no_data",
                "failed",
                "not_configured",
                "not_available",
                "skipped",
            ),
        )

    def test_proposal_state_machine_is_frozen(self) -> None:
        self.assertEqual(
            enum_values(ProposalStatus),
            (
                "draft",
                "pending_review",
                "approved",
                "rejected",
                "implemented",
                "verified",
            ),
        )

    def test_replay_and_audit_values(self) -> None:
        self.assertEqual(ReplayMode.OFFLINE.value, "offline")
        self.assertEqual(
            enum_values(AuditStatus),
            ("PASS", "WARNING", "BLOCKED"),
        )
        self.assertIn("ready", enum_values(GovernanceStatus))

    def test_artifact_ref_accepts_safe_relative_metadata(self) -> None:
        ref = ArtifactRef(
            kind="execution",
            path="data/execution/request.execution.json",
            sha256="a" * 64,
            exists=True,
            size_bytes=123,
        )
        self.assertEqual(ref.to_dict()["kind"], "execution")
        self.assertEqual(ref.to_dict()["size_bytes"], 123)

    def test_artifact_ref_rejects_unsafe_paths_and_bad_digests(self) -> None:
        for path in ("", "/tmp/x", "../x", "data/../x", "data\\..\\x"):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    ArtifactRef(kind="execution", path=path)
        with self.assertRaises(ValueError):
            ArtifactRef(
                kind="execution",
                path="data/execution/x.json",
                sha256="bad",
            )
        with self.assertRaises(ValueError):
            ArtifactRef(
                kind="execution",
                path="data/execution/x.json",
                exists=True,
            )

    def test_external_call_policy_is_default_deny(self) -> None:
        self.assertTrue(DEFAULT_EXTERNAL_CALL_POLICY.offline_safe)
        self.assertEqual(
            DEFAULT_EXTERNAL_CALL_POLICY.to_dict(),
            {
                "real_glm": False,
                "real_prometheus": False,
                "real_device": False,
                "real_notification": False,
                "write_production_data": False,
            },
        )
        DEFAULT_EXTERNAL_CALL_POLICY.assert_offline()
        with self.assertRaises(ValueError):
            ExternalCallPolicy(real_device=True).assert_offline()

    def test_minimum_contract_fields_are_present(self) -> None:
        expected = {
            "incident_memory",
            "learning_signal",
            "proposal",
            "replay",
            "audit",
        }
        self.assertEqual(set(CONTRACT_REQUIRED_FIELDS), expected)
        for name, fields in CONTRACT_REQUIRED_FIELDS.items():
            with self.subTest(contract=name):
                self.assertTrue(fields)
                self.assertEqual(len(fields), len(set(fields)))
                payload = {field: None for field in fields}
                self.assertEqual(missing_required_fields(name, payload), ())
                assert_contract_shape(name, payload)

    def test_contract_shape_reports_missing_fields(self) -> None:
        missing = missing_required_fields("learning_signal", {})
        self.assertIn("signal_id", missing)
        self.assertIn("evidence_refs", missing)
        with self.assertRaisesRegex(ValueError, "missing required fields"):
            assert_contract_shape("learning_signal", {})
        with self.assertRaisesRegex(ValueError, "unknown governance contract"):
            missing_required_fields("unknown", {})

    def test_learning_signal_types_include_logs_state(self) -> None:
        self.assertIn("command_failed", LEARNING_SIGNAL_TYPES)
        self.assertIn("cli_hard_error", LEARNING_SIGNAL_TYPES)
        self.assertIn("logs_not_available", LEARNING_SIGNAL_TYPES)
        self.assertEqual(
            LOGS_NOT_AVAILABLE_REASON,
            "elasticsearch_query_interface_pending",
        )

    def test_fixture_matrix_is_unique_and_contains_three_real_requests(self) -> None:
        all_specs = (*REAL_FIXTURE_MATRIX, *SYNTHETIC_FIXTURE_MATRIX)
        fixture_ids = [item.fixture_id for item in all_specs]
        self.assertEqual(len(fixture_ids), len(set(fixture_ids)))
        self.assertEqual(len(REAL_FIXTURE_MATRIX), 3)
        self.assertEqual(
            get_fixture_spec("20260706_141707_915316_11eef8e7").role,
            "glm52_analysis_success_cli_failure",
        )

    def test_logs_not_available_fixture_is_not_proposal_eligible(self) -> None:
        fixture = get_fixture_spec("synthetic-logs-not-available")
        self.assertIsNotNone(fixture)
        self.assertFalse(fixture.proposal_eligible)
        self.assertEqual(fixture.expected_signals, ("logs_not_available",))


class BaselineInventoryToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "project"
        self.root.mkdir(parents=True)
        self.request_id = "fixture-request-001"
        self._build_fixture()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _write_json(self, relative: str, payload: object) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def _build_fixture(self) -> None:
        rid = self.request_id
        self._write_json(
            f"data/raw/alertmanager_{rid}.json",
            {"status": "firing", "secret": "must-not-be-copied"},
        )
        self._write_json(
            f"data/normalized/alertmanager_{rid}.json",
            {"request_id": rid, "events": [{"hostname": "SW01"}]},
        )
        self._write_json(
            f"data/analysis/alertmanager_{rid}.analysis.json",
            {
                "request_id": rid,
                "analysis_status": "success",
                "model": "glm-5.2",
                "result": {"summary": "not copied"},
            },
        )
        self._write_json(
            f"data/analysis/alertmanager_{rid}.pipeline.json",
            {"request_id": rid, "pipeline_result": {"status": "ok"}},
        )
        self._write_json(
            f"data/plans/alertmanager_{rid}.plan.json",
            {
                "request_id": rid,
                "plan_status": "confirmed",
                "readonly_only": True,
                "target_scope": {
                    "hostname": "SW01",
                    "device_ip": "10.0.0.1",
                    "interface": "Ethernet1/1",
                },
            },
        )
        self._write_json(
            f"data/prometheus_evidence/alertmanager_{rid}.prometheus_evidence.json",
            {
                "request_id": rid,
                "status": "success",
                "ok": True,
                "profile": "interface_utilization",
                "query_names": ["in", "out"],
                "evidences": [{"samples": [1, 2, 3]}],
            },
        )
        self._write_json(
            f"data/execution/alertmanager_{rid}.execution.json",
            {
                "request_id": rid,
                "execution_status": "completed",
                "readonly_only": True,
                "command_results": [
                    {"command": "show interface", "raw_output": "secret output"}
                ],
                "stats": {"success_count": 1, "failed_count": 0},
            },
        )
        self._write_json(
            f"data/reviews/alertmanager_{rid}.review.json",
            {
                "request_id": rid,
                "review_status": "completed",
                "execution_status": "completed",
                "family": "interface_or_link_utilization_high",
            },
        )
        evidence_root = f"data/evidence_hub/requests/{rid}"
        self._write_json(
            f"{evidence_root}/meta.json",
            {"request_id": rid, "family": "interface_or_link_utilization_high"},
        )
        self._write_json(
            f"{evidence_root}/summary.json",
            {
                "request_id": rid,
                "status": "ok",
                "summary": {
                    "evidence_status": {
                        "metrics": "success",
                        "device": "success",
                        "review": "success",
                    }
                },
                "missing_sections": [],
                "read_error_sections": [],
            },
        )

    def _run_tool(self, request_id: str | None = None) -> subprocess.CompletedProcess[str]:
        output = Path(self.tempdir.name) / "inventory.json"
        return subprocess.run(
            [
                sys.executable,
                str(INVENTORY_TOOL),
                "--project-root",
                str(self.root),
                "--request-id",
                request_id or self.request_id,
                "--json-out",
                str(output),
            ],
            cwd=PROJECT_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

    def test_inventory_reads_local_artifacts_without_copying_sensitive_content(self) -> None:
        result = self._run_tool()
        self.assertEqual(result.returncode, 0, result.stdout)
        output = Path(self.tempdir.name) / "inventory.json"
        payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "ready")
        self.assertEqual(payload["request_id"], self.request_id)
        self.assertEqual(payload["request_summary"]["analysis"]["model"], "glm-5.2")
        self.assertEqual(
            payload["request_summary"]["prometheus"]["status"],
            "success",
        )
        self.assertEqual(
            payload["request_summary"]["execution"]["status"],
            "completed",
        )
        self.assertTrue(payload["external_call_policy"])
        self.assertFalse(any(payload["external_calls_performed"].values()))
        encoded = json.dumps(payload, ensure_ascii=False).lower()
        self.assertNotIn("must-not-be-copied", encoded)
        self.assertNotIn("secret output", encoded)
        self.assertNotIn('"samples": [1, 2, 3]', encoded)

    def test_inventory_marks_missing_required_artifacts_partial(self) -> None:
        review = (
            self.root
            / "data"
            / "reviews"
            / f"alertmanager_{self.request_id}.review.json"
        )
        review.unlink()
        result = self._run_tool()
        self.assertEqual(result.returncode, 0, result.stdout)
        output = Path(self.tempdir.name) / "inventory.json"
        payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "partial")
        self.assertIn(
            "review",
            payload["artifact_summary"]["missing_required_kinds"],
        )

    def test_inventory_rejects_unsafe_request_id(self) -> None:
        result = self._run_tool("../etc/passwd")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("invalid request_id", result.stdout)


if __name__ == "__main__":
    unittest.main()
