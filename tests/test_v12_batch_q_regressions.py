from __future__ import annotations

import unittest
from pathlib import Path

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TARGET_VERSION = "12.0.0-v12-controlled-multi-agent"


class BatchQRegressionTests(unittest.TestCase):
    def test_config_example_remains_safe_by_default(self):
        raw = yaml.safe_load(
            (PROJECT_ROOT / "config.example.yaml").read_text(encoding="utf-8")
        )
        cfg = raw["v12_multi_agent"]
        self.assertFalse(cfg["enabled"])
        self.assertEqual(cfg["mode"], "shadow")
        self.assertFalse(cfg["rca"]["enabled"])
        self.assertFalse(cfg["notifications_use_v12"])

    def test_runtime_example_is_primary_but_disabled(self):
        raw = yaml.safe_load(
            (PROJECT_ROOT / "config" / "v12_primary.example.yaml").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(raw["enabled"])
        self.assertEqual(raw["mode"], "primary")
        self.assertTrue(raw["fail_open_to_legacy"])
        self.assertFalse(raw["notifications_use_v12"])

    def test_version_is_batch_q_target(self):
        self.assertEqual(
            (PROJECT_ROOT / "VERSION").read_text(encoding="utf-8").strip(),
            TARGET_VERSION,
        )

    def test_runtime_config_is_gitignored(self):
        text = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("config/v12_primary.yaml", text)

    def test_release_readmes_have_exact_single_final_newline(self):
        for relative in ("README.md", "README_STATUS.md"):
            raw = (PROJECT_ROOT / relative).read_bytes()
            self.assertTrue(raw.endswith(b"\n"), relative)
            self.assertFalse(raw.endswith(b"\n\n"), relative)

    def test_v10_baseline_hygiene_tracks_current_release(self):
        text = (
            PROJECT_ROOT / "tests" / "test_v10_baseline_hygiene.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'EXPECTED_VERSION = "12.0.0-v12-controlled-multi-agent"',
            text,
        )
        self.assertIn('self.assertIn("v12", text.lower())', text)

    def test_historical_replay_boundary_is_migrated_to_batch_q(self):
        text = (
            PROJECT_ROOT / "tests" / "test_v12_historical_replay.py"
        ).read_text(encoding="utf-8")
        self.assertIn("test_version_is_promoted_by_batch_q_release", text)
        self.assertIn(TARGET_VERSION, text)
        self.assertNotIn(
            'def test_version_is_not_modified(self)',
            text,
        )

    def test_master_runner_is_incremental_not_replaced(self):
        text = (
            PROJECT_ROOT / "tools" / "v12_master_runner.txt"
        ).read_text(encoding="utf-8")
        self.assertIn("NetAIOps Webhook v12 master runner scaffold", text)
        self.assertIn("# BEGIN BATCH Q RELEASE DISPATCH", text)
        self.assertIn('SUPPORTED_BATCHES="A"', text)

    def test_issue_ledger_contains_batch_q_v1_failures(self):
        text = (
            PROJECT_ROOT
            / "docs"
            / "V12_IMPLEMENTATION_ISSUES_2026-08-04.md"
        ).read_text(encoding="utf-8")
        for expected in (
            "README 和 README_STATUS 末尾空行",
            "config.example 被错误改为 primary",
            "Master Runner 被错误归类为新增文件",
            "Preflight 失败后自动回退",
        ):
            self.assertIn(expected, text)


if __name__ == "__main__":
    unittest.main()
