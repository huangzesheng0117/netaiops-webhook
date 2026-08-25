from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = PROJECT_ROOT / "tools" / "v12_release_acceptance.py"
SPEC = importlib.util.spec_from_file_location("v12_release_acceptance", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


class V12ReleaseAcceptanceTests(unittest.TestCase):
    def test_initial_release_contract_is_preserved_and_current_version_is_dynamic(self):
        self.assertEqual(
            acceptance.INITIAL_RELEASE_VERSION,
            "12.0.0-v12-controlled-multi-agent",
        )
        current = (PROJECT_ROOT / "VERSION").read_text(encoding="utf-8").strip()
        self.assertEqual(
            acceptance.expected_service_version(PROJECT_ROOT),
            current,
        )

    def test_unittest_output_parser_records_count_and_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tool = root / "ok.py"
            tool.write_text(
                "print('FAIL: synthetic.failure')\n"
                "print('Ran 42 tests in 1.23s')\n",
                encoding="utf-8",
            )
            result = acceptance.run_command(
                [acceptance.sys.executable, str(tool)],
                cwd=root,
                log_path=root / "result.log",
            )
            self.assertEqual(result["ran"]["count"], 42)
            self.assertEqual(result["failure_count"], 1)

    def test_release_markdown_contains_required_gates(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "audit.md"
            report = {
                "created_at": "2026-08-03T00:00:00+00:00",
                "release_audit_status": "pass",
                "runtime": {
                    "version": acceptance.expected_service_version(PROJECT_ROOT),
                    "mode": "primary",
                    "fail_open_to_legacy": True,
                    "notifications_use_v12": False,
                    "logs_enabled": False,
                    "knowledge_enabled": False,
                    "allowed_families": ["interface_status_or_flap"],
                },
                "tests": {
                    "all_v12": {"ran": {"count": 800}, "returncode": 0},
                    "full_repository": {
                        "ran": {"count": 1400},
                        "returncode": 0,
                    },
                },
                "health": [
                    {"path": "/health", "code": 200},
                    {"path": "/evidence-ui", "code": 200},
                    {"path": "/governance-ui", "code": 200},
                    {"path": "/agent-ui", "code": 200},
                ],
                "problems": [],
                "warnings": [],
            }
            acceptance.write_release_markdown(path, report=report)
            text = path.read_text(encoding="utf-8")
            self.assertIn("release_audit=PASS", text)
            self.assertIn("historical_failures=0", text)
            self.assertIn("new_failures=0", text)
            self.assertIn("/agent-ui=200", text)

    def test_pre_activation_skip_health_flag_exists(self):
        parser = acceptance.build_parser()
        args = parser.parse_args(
            [
                "--output-dir",
                "/tmp/v12-q-test",
                "--skip-health",
                "--expected-service-version",
                acceptance.expected_service_version(PROJECT_ROOT),
                "--expected-commit-subject",
                "synthetic-subject",
                "--markdown-path",
                "/tmp/synthetic-audit.md",
            ]
        )
        self.assertTrue(args.skip_health)
        self.assertEqual(
            args.expected_service_version,
            acceptance.expected_service_version(PROJECT_ROOT),
        )
        self.assertEqual(args.expected_commit_subject, "synthetic-subject")
        self.assertEqual(args.markdown_path, "/tmp/synthetic-audit.md")

    def test_release_audit_filename_uses_actual_release_date(self):
        moment = acceptance.datetime(
            2026,
            8,
            18,
            tzinfo=acceptance.timezone.utc,
        )
        path = acceptance.release_audit_markdown_path(
            Path("/tmp/synthetic-project"),
            created_at=moment,
        )
        self.assertEqual(path.name, "V12_RELEASE_AUDIT_2026-08-18.md")

    def test_acceptance_source_has_no_real_external_clients(self):
        text = MODULE_PATH.read_text(encoding="utf-8").lower()
        for token in (
            "call_llm(",
            "collect_prometheus_evidence(",
            "run_mcp_commands_placeholder(",
            "from netaiops.notifier import",
            "from netaiops.dongdong_card_sender import",
            "collect_log_evidence(",
        ):
            self.assertNotIn(token, text)

    def test_required_runtime_paths_are_frozen(self):
        text = MODULE_PATH.read_text(encoding="utf-8")
        for path in (
            "/health",
            "/evidence-ui",
            "/governance-ui",
            "/agent-ui",
        ):
            self.assertIn(path, text)


if __name__ == "__main__":
    unittest.main()
