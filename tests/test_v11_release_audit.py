from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from netaiops.governance.contracts import AuditStatus, GOVERNANCE_SCHEMA_VERSION
from netaiops.governance.release_audit import RELEASE_AUDIT_VERSION, audit_safety_summary, build_release_audit, determine_audit_status, governance_data_integrity, sensitive_file_check
from netaiops.governance.schemas import AuditRecord
from netaiops.governance.store import GovernanceStore

FIXED_TIME = datetime(2026, 7, 7, 12, 0, tzinfo=timezone.utc)

class ReleaseAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "project"
        self.root.mkdir()
        subprocess.run(["git", "init"], cwd=self.root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=self.root, check=True)
        (self.root / "README.md").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=self.root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.governance = Path(self.tempdir.name) / "governance"
    def tearDown(self) -> None:
        self.tempdir.cleanup()
    def build(self, **kwargs):
        return build_release_audit(self.root, governance_root=self.governance, created_at=FIXED_TIME, test_results={"status": "passed", "count": 1}, replay_results={"status": "passed", "safety_regression": False}, smoke_results={"status": "not_run"}, **kwargs)
    def test_build_release_audit_passes_for_clean_repo(self) -> None:
        audit = self.build(); self.assertIsInstance(audit, AuditRecord); self.assertEqual(audit.schema_version, GOVERNANCE_SCHEMA_VERSION); self.assertEqual(audit.status, AuditStatus.PASS); self.assertEqual(audit.problems, []); self.assertFalse(audit.external_calls["glm"]); self.assertFalse(audit.external_calls["production_write"])
    def test_dirty_development_worktree_is_warning_not_blocked(self) -> None:
        (self.root / "candidate.py").write_text("print('candidate')\n", encoding="utf-8"); audit = self.build(mode="development"); self.assertEqual(audit.status, AuditStatus.WARNING); self.assertIn("worktree_has_planned_or_uncommitted_changes", audit.warnings); self.assertIn("candidate.py", audit.changed_files)
    def test_sensitive_file_check_rejects_config_and_env(self) -> None:
        result = sensitive_file_check(["config.yaml", "config/light_alert.env", "netaiops/x.py"]); self.assertFalse(result["passed"]); self.assertIn("config.yaml", result["forbidden_paths"]); self.assertIn("config/light_alert.env", result["forbidden_paths"])
    def test_sensitive_file_check_rejects_secret_named_path(self) -> None:
        result = sensitive_file_check(["docs/api_token_notes.md"]); self.assertFalse(result["passed"]); self.assertIn("docs/api_token_notes.md", result["suspicious_secret_named_paths"])
    def test_governance_integrity_empty_root_passes(self) -> None:
        result = governance_data_integrity(self.governance); self.assertTrue(result["passed"]); self.assertEqual(result["total_corrupt_records"], 0); self.assertIn("incident_memory", result["collections"])
    def test_governance_integrity_reports_corrupt_json(self) -> None:
        target = self.governance / "reports"; target.mkdir(parents=True); (target / "report_bad.json").write_text("{bad json", encoding="utf-8"); result = governance_data_integrity(self.governance); self.assertFalse(result["passed"]); self.assertGreaterEqual(result["total_corrupt_records"], 1)
    def test_determine_status_blocks_sensitive_path(self) -> None:
        status, problems, warnings = determine_audit_status(worktree={"available": True, "dirty": False}, sensitive={"passed": False}, governance_integrity={"passed": True}, test_results={"status": "passed"}, replay_results={"status": "passed", "safety_regression": False}, smoke_results={"status": "not_run"}); self.assertEqual(status, AuditStatus.BLOCKED); self.assertIn("sensitive_or_forbidden_path_detected", problems); self.assertEqual(warnings, [])
    def test_determine_status_blocks_failed_tests(self) -> None:
        status, problems, _ = determine_audit_status(worktree={"available": True, "dirty": False}, sensitive={"passed": True}, governance_integrity={"passed": True}, test_results={"status": "failed"}, replay_results={"status": "passed", "safety_regression": False}, smoke_results={"status": "not_run"}); self.assertEqual(status, AuditStatus.BLOCKED); self.assertIn("tests_not_passed", problems)
    def test_determine_status_blocks_replay_safety_regression(self) -> None:
        status, problems, _ = determine_audit_status(worktree={"available": True, "dirty": False}, sensitive={"passed": True}, governance_integrity={"passed": True}, test_results={"status": "passed"}, replay_results={"status": "passed", "safety_regression": True}, smoke_results={"status": "not_run"}); self.assertEqual(status, AuditStatus.BLOCKED); self.assertIn("replay_safety_regression", problems)
    def test_corrupt_governance_records_are_warning(self) -> None:
        status, problems, warnings = determine_audit_status(worktree={"available": True, "dirty": False}, sensitive={"passed": True}, governance_integrity={"passed": False}, test_results={"status": "passed"}, replay_results={"status": "passed", "safety_regression": False}, smoke_results={"status": "not_run"}); self.assertEqual(status, AuditStatus.WARNING); self.assertEqual(problems, []); self.assertIn("governance_store_has_corrupt_records", warnings)
    def test_audit_safety_summary_is_safe(self) -> None:
        summary = audit_safety_summary(self.build()); self.assertTrue(summary["safe"]); self.assertFalse(summary["production_write"]); self.assertEqual(summary["release_audit_version"], RELEASE_AUDIT_VERSION)
    def test_audit_safety_summary_detects_external_call(self) -> None:
        payload = self.build().to_payload(); payload["external_calls"]["glm"] = True; summary = audit_safety_summary(payload); self.assertFalse(summary["safe"]); self.assertIn("glm", summary["enabled_external_calls"])
    def test_audit_id_is_stable_for_same_inputs(self) -> None:
        self.assertEqual(self.build().audit_id, self.build().audit_id)
    def test_audit_id_changes_with_changed_files(self) -> None:
        clean = self.build(); (self.root / "candidate.py").write_text("x = 1\n", encoding="utf-8"); dirty = self.build(); self.assertNotEqual(clean.audit_id, dirty.audit_id)
    def test_cli_writes_json_report(self) -> None:
        output = Path(self.tempdir.name) / "audit.json"; proc = subprocess.run(["python", str(Path(__file__).resolve().parents[1] / "tools" / "v11_release_audit.py"), "--project-root", str(self.root), "--mode", "development", "--governance-root", str(self.governance), "--json-out", str(output)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False); self.assertEqual(proc.returncode, 0, proc.stderr); payload = json.loads(output.read_text(encoding="utf-8")); self.assertEqual(payload["schema_version"], GOVERNANCE_SCHEMA_VERSION); self.assertIn(payload["status"], {"PASS", "WARNING"}); self.assertTrue(payload["safety"]["safe"])
    def test_cli_does_not_write_governance_store(self) -> None:
        output = Path(self.tempdir.name) / "audit.json"; subprocess.run(["python", str(Path(__file__).resolve().parents[1] / "tools" / "v11_release_audit.py"), "--project-root", str(self.root), "--governance-root", str(self.governance), "--json-out", str(output)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE); self.assertTrue(output.is_file()); self.assertFalse((self.governance / "audits").exists())
    def test_audit_record_can_be_written_to_non_production_store(self) -> None:
        audit = self.build(); store = GovernanceStore(self.governance); result = store.write("audits", audit.audit_id, audit, overwrite=True); self.assertTrue(Path(result.path).is_file()); loaded = store.read("audits", audit.audit_id); self.assertEqual(loaded["audit_id"], audit.audit_id)
    def test_unknown_git_root_becomes_blocked_problem(self) -> None:
        nongit = Path(self.tempdir.name) / "nongit"; nongit.mkdir(); audit = build_release_audit(nongit, governance_root=self.governance, created_at=FIXED_TIME, test_results={"status": "passed"}, replay_results={"status": "passed", "safety_regression": False}, smoke_results={"status": "not_run"}); self.assertEqual(audit.status, AuditStatus.BLOCKED); self.assertIn("git_metadata_unavailable", audit.problems)
    def test_report_payload_contains_required_sections(self) -> None:
        payload = self.build().to_payload(); [self.assertIn(field, payload) for field in ("worktree", "test_results", "replay_results", "smoke_results", "sensitive_file_check", "governance_data_integrity")]
    def test_production_write_never_enabled_by_builder(self) -> None:
        self.assertFalse(self.build().external_calls["production_write"])
    def test_mode_and_target_version_are_preserved(self) -> None:
        audit = self.build(mode="release", target_version="v11.0.0-test"); self.assertEqual(audit.worktree["mode"], "release"); self.assertEqual(audit.target_version, "v11.0.0-test")
    def test_created_at_must_be_aware(self) -> None:
        with self.assertRaises(Exception): build_release_audit(self.root, governance_root=self.governance, created_at=datetime(2026, 7, 7, 12, 0))

if __name__ == "__main__":
    unittest.main()
