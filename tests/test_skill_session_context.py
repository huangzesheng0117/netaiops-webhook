import unittest

from netaiops.skill_session_context import (
    attach_skill_context_to_session,
    build_skill_context_for_session,
    infer_family_from_session,
)


class TestSkillSessionContext(unittest.TestCase):
    def test_infer_family_from_classification(self):
        session = {
            "request_id": "rid",
            "classification": {
                "family": "interface_or_link_utilization_high",
            },
        }

        self.assertEqual(infer_family_from_session(session), "interface_or_link_utilization_high")

    def test_build_skill_context_for_interface_family(self):
        session = {
            "request_id": "rid",
            "classification": {
                "family": "interface_or_link_utilization_high",
            },
        }

        context = build_skill_context_for_session(session, ".")

        self.assertTrue(context["matched"])
        self.assertEqual(context["stage"], "v6.3")
        self.assertEqual(context["family"], "interface_or_link_utilization_high")
        self.assertEqual(context["skill_name"], "interface_utilization_high")
        self.assertEqual(context["risk_level"], "readonly")
        self.assertEqual(context["binding_verdict"], "pass")
        self.assertIn("mcp_netmiko_run_show", context["allowed_tools"])
        self.assertIn("show_interface_detail", context["allowed_capabilities"])
        self.assertIn("cisco_show_interfaces", context["parsers"])
        self.assertEqual(context["missing_tools"], [])
        self.assertEqual(context["missing_parsers"], [])

    def test_attach_skill_context_to_session(self):
        session = {
            "request_id": "rid",
            "classification": {
                "family": "interface_or_link_utilization_high",
            },
        }

        result = attach_skill_context_to_session(session, ".")

        self.assertIn("skill_context", result)
        self.assertTrue(result["skill_context"]["matched"])
        self.assertEqual(result["skill_context"]["skill_name"], "interface_utilization_high")


if __name__ == "__main__":
    unittest.main()
