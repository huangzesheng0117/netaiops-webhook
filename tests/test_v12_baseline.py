import re
import unittest
from pathlib import Path
from typing import Any

import yaml

from netaiops.v12 import (
    V12_BATCH_ORDER,
    V12_CONFIG_SECTION,
    V12_DEFAULT_MODE,
    V12_TARGET_VERSION,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BASELINE_HEAD = "e83dcc526389a420df435e2d6e8a671e81ee5f30"
BASELINE_VERSION = "11.0.0-v11-learning-governance"
TARGET_VERSION = "12.0.0-v12-controlled-multi-agent"


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: UniqueKeyLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key: {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


class V12BaselineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config_path = PROJECT_ROOT / "config.example.yaml"
        self.config = yaml.load(
            self.config_path.read_text(encoding="utf-8"),
            Loader=UniqueKeyLoader,
        )

    def test_namespace_metadata_is_stable_and_side_effect_free(self) -> None:
        self.assertEqual(V12_TARGET_VERSION, TARGET_VERSION)
        self.assertEqual(V12_CONFIG_SECTION, "v12_multi_agent")
        self.assertEqual(V12_DEFAULT_MODE, "shadow")
        self.assertEqual(V12_BATCH_ORDER, tuple("ABCDEFGHIJKLMNOPQ"))

        init_text = (PROJECT_ROOT / "netaiops/v12/__init__.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("requests.", init_text)
        self.assertNotIn("httpx.", init_text)
        self.assertNotIn("include_router", init_text)

    def test_config_example_has_unique_top_level_v12_sections(self) -> None:
        self.assertIsInstance(self.config, dict)
        self.assertIn("v12_multi_agent", self.config)
        self.assertIn("logs_evidence", self.config)
        self.assertIn("knowledge_context", self.config)

    def test_v12_feature_flags_are_safe_by_default(self) -> None:
        cfg = self.config["v12_multi_agent"]
        self.assertFalse(cfg["enabled"])
        self.assertEqual(cfg["mode"], "shadow")
        self.assertTrue(cfg["fail_open_to_legacy"])
        self.assertTrue(cfg["reuse_existing_evidence"])
        self.assertFalse(cfg["notifications_use_v12"])
        self.assertFalse(cfg["rca"]["enabled"])
        self.assertEqual(cfg["rca"]["provider"], "glm-5.2")
        self.assertTrue(cfg["rca"]["require_evidence_refs"])
        self.assertTrue(cfg["traces"]["enabled"])
        self.assertTrue(cfg["traces"]["redact_sensitive_fields"])

    def test_v12_budgets_match_the_frozen_batch_a_contract(self) -> None:
        budgets = self.config["v12_multi_agent"]["budgets"]
        self.assertEqual(
            budgets,
            {
                "total_timeout_seconds": 90,
                "triage_timeout_seconds": 5,
                "planner_timeout_seconds": 5,
                "metrics_timeout_seconds": 30,
                "device_timeout_seconds": 45,
                "logs_timeout_seconds": 5,
                "knowledge_timeout_seconds": 5,
                "judge_timeout_seconds": 5,
                "rca_timeout_seconds": 30,
                "report_timeout_seconds": 5,
            },
        )

    def test_logs_and_knowledge_are_disabled_placeholders(self) -> None:
        logs = self.config["logs_evidence"]
        knowledge = self.config["knowledge_context"]

        self.assertFalse(logs["enabled"])
        self.assertEqual(logs["reason"], "logs_evidence_not_approved")
        self.assertFalse(knowledge["enabled"])
        self.assertEqual(
            knowledge["reason"],
            "local_knowledge_base_not_built",
        )

    def test_existing_runtime_defaults_remain_unchanged(self) -> None:
        self.assertTrue(self.config["pipeline"]["enabled"])
        self.assertFalse(self.config["llm"]["enabled"])
        self.assertEqual(self.config["llm"]["model"], "glm-5.2")
        self.assertFalse(self.config["notify"]["enabled"])
        self.assertEqual(self.config["prometheus"]["rate_window"], "1m")
        self.assertEqual(self.config["prometheus"]["step"], "60s")

    def test_baseline_manifest_records_the_verified_starting_point(self) -> None:
        text = (
            PROJECT_ROOT / "docs/v12/V12_BASELINE_2026-07-14.md"
        ).read_text(encoding="utf-8")

        for expected in (
            BASELINE_HEAD,
            BASELINE_VERSION,
            TARGET_VERSION,
            "549 OK",
            "strict-zero-regressions-v2",
            "logs_evidence_not_approved",
            "local_knowledge_base_not_built",
        ):
            self.assertIn(expected, text)

    def test_master_runner_has_exact_batch_a_safety_controls(self) -> None:
        text = (
            PROJECT_ROOT / "tools/v12_master_runner.txt"
        ).read_text(encoding="utf-8")

        for expected in (
            'SUPPORTED_BATCHES="A"',
            'PLANNED_BATCHES="A B C D E F G H I J K L M N O P Q"',
            "CONFIRM_COMMIT=YES",
            "CONFIRM_ROLLBACK=YES",
            "RUN_FULL_REPOSITORY=YES",
            "v12: freeze baseline and add controlled multi-agent flags",
            "LC_ALL=C sort -u",
        ):
            self.assertIn(expected, text)

        forbidden_patterns = (
            r"git\s+add\s+\.(?:\s|$)",
            r"git\s+add\s+-A(?:\s|$)",
            r"git\s+reset\s+--hard",
            r"git\s+clean\s+-fd",
        )
        for pattern in forbidden_patterns:
            self.assertIsNone(re.search(pattern, text))

    def test_master_runner_sanitizes_confirmation_environment(self) -> None:
        text = (
            PROJECT_ROOT / "tools/v12_master_runner.txt"
        ).read_text(encoding="utf-8")

        command = (
            "python -m unittest discover "
            "-s tests -p 'test*.py' -v"
        )
        position = text.find(command)
        self.assertGreaterEqual(position, 0)

        prefix = text[max(0, position - 400):position]
        for variable in (
            "CONFIRM_COMMIT",
            "CONFIRM_PUSH",
            "CONFIRM_ROLLBACK",
            "CONFIRM_REPREPARE",
        ):
            self.assertIn(f"-u {variable}", prefix)

    def test_batch_a_file_set_exists(self) -> None:
        expected = (
            "config.example.yaml",
            "docs/v12/V12_BASELINE_2026-07-14.md",
            "netaiops/v12/__init__.py",
            "tests/test_v12_baseline.py",
            "tools/v12_master_runner.txt",
        )
        for relative in expected:
            self.assertTrue((PROJECT_ROOT / relative).is_file(), relative)


if __name__ == "__main__":
    unittest.main()
