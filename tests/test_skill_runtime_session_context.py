import unittest

from netaiops.skill_runtime_session_context import (
    attach_skill_runtime_context_to_session,
    build_skill_runtime_context_for_session,
    compact_runtime_context,
    infer_family_for_runtime,
)
from netaiops.skill_runtime import load_skill_runtime_context


class TestSkillRuntimeSessionContext(unittest.TestCase):
    def test_infer_family_from_skill_context(self):
        session = {
            "skill_context": {
                "family": "interface_or_link_utilization_high",
            }
        }

        self.assertEqual(infer_family_for_runtime(session), "interface_or_link_utilization_high")

    def test_build_metadata_runtime_context_for_session(self):
        session = {
            "skill_context": {
                "family": "interface_or_link_utilization_high",
            }
        }

        context = build_skill_runtime_context_for_session(session, ".")

        self.assertTrue(context["matched"])
        self.assertEqual(context["stage"], "v6.4")
        self.assertEqual(context["runtime_version"], "v6.4.0")
        self.assertEqual(context["load_strategy"], "progressive_loading")
        self.assertEqual(context["skill_name"], "interface_utilization_high")
        self.assertEqual(context["loaded_levels"], ["metadata"])
        self.assertFalse(context["content_embedded"])
        self.assertEqual(context["content_policy"], "metadata_only_in_investigation_session")
        self.assertIn("metadata", context)

    def test_compact_context_does_not_embed_content(self):
        full = load_skill_runtime_context(
            "interface_utilization_high",
            ".",
            levels=["metadata", "instructions", "commands", "evidence", "schema"],
        )

        compact = compact_runtime_context(full)

        self.assertFalse(compact["content_embedded"])
        self.assertIn("instructions", compact["loaded_files"])
        self.assertIn("commands", compact["loaded_files"])
        self.assertIn("evidence", compact["loaded_files"])
        self.assertIn("schema", compact["loaded_files"])
        self.assertNotIn("instructions", compact)
        self.assertNotIn("commands", compact)
        self.assertNotIn("evidence", compact)
        self.assertNotIn("schema", compact)

    def test_attach_skill_runtime_context_to_session(self):
        session = {
            "skill_context": {
                "family": "interface_or_link_utilization_high",
            }
        }

        result = attach_skill_runtime_context_to_session(session, ".")

        self.assertIn("skill_runtime_context", result)
        self.assertTrue(result["skill_runtime_context"]["matched"])
        self.assertEqual(result["skill_runtime_context"]["skill_name"], "interface_utilization_high")


if __name__ == "__main__":
    unittest.main()
