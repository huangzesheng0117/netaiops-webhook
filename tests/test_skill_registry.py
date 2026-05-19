import json
import tempfile
import unittest
from pathlib import Path

from netaiops.skill_registry import get_skill_by_family, list_skills, load_skill, validate_all_skills, validate_skill_package


class TestSkillRegistry(unittest.TestCase):
    def test_interface_skill_can_be_loaded(self):
        skill = load_skill("interface_utilization_high", ".")
        self.assertEqual(skill["name"], "interface_utilization_high")
        self.assertEqual(skill["family"], "interface_or_link_utilization_high")
        self.assertEqual(skill["risk_level"], "readonly")
        self.assertEqual(skill["stage"], "v6.3")
        self.assertIn("output_schema", skill)

    def test_get_skill_by_family(self):
        skill = get_skill_by_family("interface_or_link_utilization_high", ".")
        self.assertIsNotNone(skill)
        self.assertEqual(skill["name"], "interface_utilization_high")

    def test_validate_interface_skill_package(self):
        result = validate_skill_package("interface_utilization_high", ".")
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["violations"], [])

    def test_validate_all_skills(self):
        result = validate_all_skills(".")
        self.assertEqual(result["verdict"], "pass")
        self.assertGreaterEqual(result["skill_count"], 1)

    def test_temp_skill_validation_detects_missing_files(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            d = base / "skills" / "bad_skill"
            d.mkdir(parents=True)
            (d / "SKILL.md").write_text(
                "---\nname: bad_skill\nversion: v6.3.0\nfamily: bad\nrisk_level: readonly\nstage: v6.3\n---\n",
                encoding="utf-8",
            )

            result = validate_skill_package("bad_skill", base)
            self.assertEqual(result["verdict"], "fail")
            self.assertTrue(any("missing required file" in item for item in result["violations"]))


if __name__ == "__main__":
    unittest.main()
