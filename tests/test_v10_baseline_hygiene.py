import re
import unittest
from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "11.0.0-v11-learning-governance"
EXPECTED_REQUIREMENTS = {
    "fastapi==0.135.1",
    "httpx==0.28.1",
    "openpyxl==3.1.5",
    "pydantic==2.12.5",
    "PyYAML==6.0.3",
    "requests==2.33.1",
    "uvicorn==0.41.0",
}


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


class V10BaselineHygieneTests(unittest.TestCase):
    def test_version_and_current_documents_are_aligned(self) -> None:
        version = (PROJECT_ROOT / "VERSION").read_text(encoding="utf-8").strip()
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
        status = (PROJECT_ROOT / "README_STATUS.md").read_text(encoding="utf-8")

        self.assertEqual(version, EXPECTED_VERSION)
        for text in (readme, status):
            self.assertIn(EXPECTED_VERSION, text)
            self.assertIn("glm-5.2", text)
            self.assertIn("v11", text.lower())

        self.assertNotIn("当前主线已经演进到 V7", readme)
        self.assertNotIn("5.0.0-v5-batch1", status)

    def test_config_example_is_valid_and_has_unique_keys(self) -> None:
        config_path = PROJECT_ROOT / "config.example.yaml"
        config = yaml.load(
            config_path.read_text(encoding="utf-8"),
            Loader=UniqueKeyLoader,
        )

        self.assertIsInstance(config, dict)
        self.assertEqual(config["llm"]["model"], "glm-5.2")
        self.assertGreaterEqual(int(config["llm"]["max_tokens"]), 1200)
        self.assertFalse(bool(config["llm"]["enabled"]))
        self.assertFalse(bool(config["notify"]["enabled"]))
        self.assertEqual(config["prometheus"]["rate_window"], "1m")
        self.assertEqual(config["prometheus"]["step"], "60s")

        patterns = config["safety_policy"]["deny_command_patterns"]
        self.assertTrue(any(re.search(pattern, " configure terminal") for pattern in patterns))
        self.assertTrue(any(re.search(pattern, "reload") for pattern in patterns))
        self.assertTrue(any(re.search(pattern, "a || b") for pattern in patterns))

    def test_config_example_contains_no_embedded_secret_values(self) -> None:
        text = (PROJECT_ROOT / "config.example.yaml").read_text(encoding="utf-8")
        lowered = text.lower()

        self.assertNotRegex(lowered, r"bearer\s+[a-z0-9._-]{12,}")
        self.assertNotRegex(lowered, r"token\s*:\s*[^\s#]{8,}")
        self.assertNotRegex(lowered, r"password\s*:\s*[^\s#]{4,}")
        self.assertNotRegex(lowered, r"secret\s*:\s*[^\s#]{8,}")

    def test_requirements_file_has_expected_direct_dependencies(self) -> None:
        lines = {
            line.strip()
            for line in (PROJECT_ROOT / "requirements.txt")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        self.assertEqual(lines, EXPECTED_REQUIREMENTS)

    def test_runtime_paths_remain_gitignored(self) -> None:
        ignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
        for expected in ("config.yaml", "data/", "logs/", "backup/", "venv/"):
            self.assertIn(expected, ignore)


if __name__ == "__main__":
    unittest.main()
