import unittest

from netaiops.skill_runtime_api import (
    build_runtime_family_response,
    build_runtime_index_response,
    build_runtime_skill_response,
    build_runtime_validate_response,
    parse_runtime_levels,
)


class TestSkillRuntimeApi(unittest.TestCase):
    def test_parse_runtime_levels(self):
        self.assertEqual(parse_runtime_levels(None), ["metadata"])
        self.assertEqual(parse_runtime_levels(""), ["metadata"])
        self.assertEqual(parse_runtime_levels("metadata,commands,commands"), ["metadata", "commands"])

        with self.assertRaises(ValueError):
            parse_runtime_levels("metadata,badlevel")

    def test_index_response(self):
        result = build_runtime_index_response(".")

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["stage"], "v6.4_skill_runtime_index")
        self.assertGreaterEqual(result["skill_count"], 1)
        self.assertIn("interface_or_link_utilization_high", result["by_family"])

    def test_validate_response(self):
        result = build_runtime_validate_response(".")

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["result"]["verdict"], "pass")

    def test_family_metadata_response(self):
        result = build_runtime_family_response(
            family="interface_or_link_utilization_high",
            base_dir=".",
            levels="metadata",
        )

        ctx = result["runtime_context"]

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["stage"], "v6.4_skill_runtime_family")
        self.assertTrue(ctx["matched"])
        self.assertEqual(ctx["skill_name"], "interface_utilization_high")
        self.assertEqual(ctx["loaded_levels"], ["metadata"])
        self.assertFalse(ctx["runtime_api"]["content_embedded"])

    def test_family_commands_response_embeds_content_on_demand(self):
        result = build_runtime_family_response(
            family="interface_or_link_utilization_high",
            base_dir=".",
            levels="metadata,commands",
        )

        ctx = result["runtime_context"]

        self.assertEqual(result["status"], "ok")
        self.assertEqual(ctx["loaded_levels"], ["metadata", "commands"])
        self.assertTrue(ctx["runtime_api"]["content_embedded"])
        self.assertIn("commands", ctx["runtime_api"]["loaded_files"])
        self.assertIn("commands", ctx)

    def test_skill_full_response(self):
        result = build_runtime_skill_response(
            skill_name="interface_utilization_high",
            base_dir=".",
            levels="metadata,instructions,commands,evidence,schema",
        )

        ctx = result["runtime_context"]

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["stage"], "v6.4_skill_runtime_skill")
        self.assertEqual(ctx["skill_name"], "interface_utilization_high")
        self.assertEqual(ctx["loaded_levels"], ["metadata", "instructions", "commands", "evidence", "schema"])
        self.assertTrue(ctx["runtime_api"]["content_embedded"])
        self.assertIn("instructions", ctx)
        self.assertIn("commands", ctx)
        self.assertIn("evidence", ctx)
        self.assertIn("schema", ctx)


if __name__ == "__main__":
    unittest.main()
