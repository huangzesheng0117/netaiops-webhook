import unittest

from netaiops.skill_runtime import (
    build_runtime_context_for_family,
    build_skill_index,
    list_skill_metadata,
    load_skill_runtime_context,
    validate_skill_runtime,
)


class TestSkillRuntime(unittest.TestCase):
    def test_list_skill_metadata_only(self):
        skills = list_skill_metadata(".")
        names = {item["name"] for item in skills}

        self.assertIn("interface_utilization_high", names)

        item = [x for x in skills if x["name"] == "interface_utilization_high"][0]
        self.assertEqual(item["load_level"], "metadata")
        self.assertEqual(item["family"], "interface_or_link_utilization_high")
        self.assertEqual(item["risk_level"], "readonly")
        self.assertNotIn("content", item)

    def test_build_skill_index(self):
        index = build_skill_index(".")

        self.assertGreaterEqual(index["skill_count"], 1)
        self.assertEqual(index["load_strategy"], "progressive_loading")
        self.assertIn("interface_utilization_high", index["by_name"])
        self.assertIn("interface_or_link_utilization_high", index["by_family"])

    def test_load_metadata_runtime_context(self):
        context = load_skill_runtime_context(
            "interface_utilization_high",
            ".",
            levels=["metadata"],
        )

        self.assertEqual(context["skill_name"], "interface_utilization_high")
        self.assertEqual(context["loaded_levels"], ["metadata"])
        self.assertIn("metadata", context)
        self.assertNotIn("instructions", context)
        self.assertNotIn("commands", context)
        self.assertNotIn("evidence", context)
        self.assertNotIn("schema", context)

    def test_load_full_runtime_context(self):
        context = load_skill_runtime_context(
            "interface_utilization_high",
            ".",
            levels=["metadata", "instructions", "commands", "evidence", "schema"],
        )

        self.assertEqual(context["skill_name"], "interface_utilization_high")
        self.assertIn("metadata", context["loaded_levels"])
        self.assertIn("instructions", context["loaded_levels"])
        self.assertIn("commands", context["loaded_levels"])
        self.assertIn("evidence", context["loaded_levels"])
        self.assertIn("schema", context["loaded_levels"])
        self.assertIn("interface_utilization_high", context["instructions"]["content"])
        self.assertIn("allowed_tools", context["commands"]["content"])
        self.assertIn("required_facts", context["evidence"]["content"])
        self.assertEqual(context["schema"]["schema"]["skill_name"], "interface_utilization_high")

    def test_build_runtime_context_for_family(self):
        context = build_runtime_context_for_family(
            "interface_or_link_utilization_high",
            ".",
            levels=["metadata", "commands"],
        )

        self.assertTrue(context["matched"])
        self.assertEqual(context["family"], "interface_or_link_utilization_high")
        self.assertEqual(context["skill_name"], "interface_utilization_high")
        self.assertEqual(context["loaded_levels"], ["metadata", "commands"])

    def test_validate_skill_runtime(self):
        result = validate_skill_runtime(".")

        self.assertEqual(result["verdict"], "pass")
        self.assertGreaterEqual(result["skill_count"], 1)
        self.assertEqual(result["violations"], [])


if __name__ == "__main__":
    unittest.main()
