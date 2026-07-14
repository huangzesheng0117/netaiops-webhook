from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "tools"
    / "v11_release_acceptance.py"
)
SPEC = importlib.util.spec_from_file_location(
    "v11_release_acceptance",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


class ReleaseAcceptanceParserTests(unittest.TestCase):
    def test_historical_failure_set_is_resolved_and_empty(self) -> None:
        self.assertEqual(acceptance.KNOWN_HISTORICAL_FAILURES, ())
        self.assertEqual(
            acceptance.RESOLVED_HISTORICAL_FAILURE_COUNT,
            28,
        )

    def test_known_failure_policy_name(self) -> None:
        self.assertEqual(
            acceptance.KNOWN_FAILURE_POLICY,
            "strict-zero-regressions-v2",
        )

    def test_parse_unittest_output_extracts_fail_and_error(self) -> None:
        text = "\n".join(
            [
                "FAIL: test_a (test_mod.Case)",
                "ERROR: test_b (test_mod.Case)",
                "Ran 10 tests in 1.0s",
                "FAILED (failures=1, errors=1)",
            ]
        )
        result = acceptance.parse_unittest_output(text)
        self.assertEqual(result["failure_count"], 2)
        self.assertEqual(result["ran"]["count"], 10)
        self.assertIn("failures=1", result["failed_summary"])

    def test_parse_unittest_output_deduplicates_headers(self) -> None:
        line = "FAIL: test_a (test_mod.Case)"
        result = acceptance.parse_unittest_output(f"{line}\n{line}\n")
        self.assertEqual(result["failures"], [line])

    def test_parse_success_output(self) -> None:
        result = acceptance.parse_unittest_output(
            "Ran 5 tests in 0.1s\n\nOK\n"
        )
        self.assertEqual(result["failure_count"], 0)
        self.assertEqual(result["ran"]["count"], 5)
        self.assertEqual(result["failed_summary"], "")

    def test_zero_failure_set_is_accepted(self) -> None:
        result = acceptance.compare_failure_set([])
        self.assertTrue(result["exact_match"])
        self.assertEqual(result["expected_count"], 0)
        self.assertEqual(result["observed_count"], 0)
        self.assertEqual(result["new_failure_count"], 0)
        self.assertEqual(result["missing_failure_count"], 0)

    def test_any_failure_is_blocking(self) -> None:
        result = acceptance.compare_failure_set(
            ["FAIL: test_new (test_new.Case)"]
        )
        self.assertFalse(result["exact_match"])
        self.assertEqual(result["new_failure_count"], 1)

    def test_compare_failure_set_reports_observed_count(self) -> None:
        observed = [
            "FAIL: test_a (test_mod.Case)",
            "ERROR: test_b (test_mod.Case)",
        ]
        result = acceptance.compare_failure_set(observed)
        self.assertEqual(result["observed_count"], 2)
        self.assertEqual(result["expected_count"], 0)


class ReleaseAcceptanceOfflineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "project"
        self.root.mkdir()
        self.output = Path(self.tempdir.name) / "output"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def fake_replay(self):
        record = SimpleNamespace(
            external_calls={
                "glm": False,
                "prometheus": False,
                "device": False,
                "notification": False,
                "production_write": False,
            },
            warnings=["logs_evidence_not_available"],
        )
        return SimpleNamespace(
            record=record,
            summary=lambda: {
                "request_id": "request_1",
                "quality_outcome": "unchanged",
                "safety_regression": False,
            },
        )

    def test_offline_requires_all_no_real_flags(self) -> None:
        with self.assertRaises(acceptance.ReleaseAcceptanceError):
            acceptance.run_offline_acceptance(
                project_root=self.root,
                request_id="request_1",
                output_dir=self.output,
                no_notify=True,
                no_real_glm=True,
                no_real_prometheus=False,
                no_real_device=True,
            )

    @patch.object(acceptance, "replay_safety_summary")
    @patch.object(acceptance, "run_offline_replay")
    @patch.object(acceptance, "build_governance_artifacts_safe")
    def test_offline_writes_pass_report(
        self,
        build_sidecar,
        run_replay,
        replay_safety,
    ) -> None:
        build_sidecar.return_value = {
            "ok": True,
            "external_calls": {
                "glm": False,
                "prometheus": False,
                "device": False,
                "notification": False,
                "production_write": False,
            },
        }
        run_replay.return_value = self.fake_replay()
        replay_safety.return_value = {"safe": True}

        report = acceptance.run_offline_acceptance(
            project_root=self.root,
            request_id="request_1",
            output_dir=self.output,
            no_notify=True,
            no_real_glm=True,
            no_real_prometheus=True,
            no_real_device=True,
        )
        self.assertEqual(report["overall_status"], "PASS")
        self.assertTrue(
            (self.output / "v11_acceptance_report.json").is_file()
        )
        loaded = json.loads(
            (self.output / "v11_acceptance_report.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(loaded["request_id"], "request_1")

    @patch.object(acceptance, "build_governance_artifacts_safe")
    def test_offline_rejects_sidecar_failure(self, build_sidecar) -> None:
        build_sidecar.return_value = {
            "ok": False,
            "error": "fixture failure",
        }
        with self.assertRaises(acceptance.ReleaseAcceptanceError):
            acceptance.run_offline_acceptance(
                project_root=self.root,
                request_id="request_1",
                output_dir=self.output,
                no_notify=True,
                no_real_glm=True,
                no_real_prometheus=True,
                no_real_device=True,
            )

    def test_external_call_guard_accepts_all_false(self) -> None:
        acceptance._assert_zero_external_calls(
            {"glm": False, "notification": False},
            context="test",
        )

    def test_external_call_guard_rejects_true(self) -> None:
        with self.assertRaises(acceptance.ReleaseAcceptanceError):
            acceptance._assert_zero_external_calls(
                {"glm": True},
                context="test",
            )


class ReleaseAcceptanceRepositoryGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "project"
        self.root.mkdir()
        (self.root / "VERSION").write_text(
            acceptance.EXPECTED_SERVICE_VERSION + "\n",
            encoding="utf-8",
        )
        self.output = Path(self.tempdir.name) / "output"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def command_result(
        self,
        *,
        returncode: int,
        failures: list[str],
        count: int,
    ) -> dict:
        return {
            "args": [],
            "returncode": returncode,
            "log": "fixture.log",
            "failures": failures,
            "failure_count": len(failures),
            "ran": {"count": count, "duration": "0.1s"},
            "failed_summary": "",
        }

    @patch.object(acceptance, "_final_pass_audit")
    @patch.object(acceptance, "_run_command")
    def test_repository_gate_accepts_clean_zero_failure_suite(
        self,
        run_command,
        final_audit,
    ) -> None:
        run_command.side_effect = [
            self.command_result(returncode=0, failures=[], count=20),
            self.command_result(returncode=0, failures=[], count=269),
            self.command_result(returncode=0, failures=[], count=549),
        ]
        final_audit.return_value = SimpleNamespace(
            to_payload=lambda: {
                "status": "pass",
                "warnings": [],
                "problems": [],
            }
        )
        report = acceptance.run_repository_gate(
            project_root=self.root,
            output_dir=self.output,
            expected_version=acceptance.EXPECTED_SERVICE_VERSION,
        )
        self.assertEqual(report["overall_status"], "PASS")
        self.assertEqual(report["release_audit_status"], "pass")
        self.assertEqual(report["known_historical_failure_count"], 0)
        self.assertEqual(report["resolved_historical_failure_count"], 28)
        self.assertEqual(report["new_failure_count"], 0)
        self.assertTrue(
            (self.output / "v11_release_audit.json").is_file()
        )

    @patch.object(acceptance, "_run_command")
    def test_repository_gate_rejects_full_repository_failure(
        self,
        run_command,
    ) -> None:
        run_command.side_effect = [
            self.command_result(returncode=0, failures=[], count=20),
            self.command_result(returncode=0, failures=[], count=269),
            self.command_result(
                returncode=1,
                failures=["FAIL: new (new.Case)"],
                count=549,
            ),
        ]
        with self.assertRaises(acceptance.ReleaseAcceptanceError):
            acceptance.run_repository_gate(
                project_root=self.root,
                output_dir=self.output,
                expected_version=acceptance.EXPECTED_SERVICE_VERSION,
            )

    @patch.object(acceptance, "_run_command")
    def test_repository_gate_rejects_v11_failure(
        self,
        run_command,
    ) -> None:
        run_command.side_effect = [
            self.command_result(returncode=0, failures=[], count=20),
            self.command_result(
                returncode=1,
                failures=["FAIL: v11 (v11.Case)"],
                count=269,
            ),
        ]
        with self.assertRaises(acceptance.ReleaseAcceptanceError):
            acceptance.run_repository_gate(
                project_root=self.root,
                output_dir=self.output,
                expected_version=acceptance.EXPECTED_SERVICE_VERSION,
            )

    def test_repository_gate_rejects_version_mismatch(self) -> None:
        (self.root / "VERSION").write_text(
            "10.0.0-old\n",
            encoding="utf-8",
        )
        with self.assertRaises(acceptance.ReleaseAcceptanceError):
            acceptance.run_repository_gate(
                project_root=self.root,
                output_dir=self.output,
                expected_version=acceptance.EXPECTED_SERVICE_VERSION,
            )

    def test_parser_supports_both_modes_and_strict_policy(self) -> None:
        parser = acceptance.build_parser()
        offline = parser.parse_args(
            [
                "--project-root",
                str(self.root),
                "--mode",
                "offline",
                "--baseline-request-id",
                "request_1",
                "--output-dir",
                str(self.output),
                "--no-notify",
                "--no-real-glm",
                "--no-real-prometheus",
                "--no-real-device",
            ]
        )
        self.assertEqual(offline.mode, "offline")

        gate = parser.parse_args(
            [
                "--project-root",
                str(self.root),
                "--mode",
                "repository-gate",
                "--output-dir",
                str(self.output),
                "--known-failure-policy",
                "strict-zero-regressions-v2",
            ]
        )
        self.assertEqual(gate.mode, "repository-gate")
        self.assertEqual(
            gate.known_failure_policy,
            "strict-zero-regressions-v2",
        )


if __name__ == "__main__":
    unittest.main()
