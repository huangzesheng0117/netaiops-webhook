import unittest

from netaiops.skill_binding_validator import (
    load_skill_binding_graph,
    validate_all_skill_bindings,
    validate_skill_binding,
)


class TestSkillBindingValidator(unittest.TestCase):
    def test_interface_skill_binding_graph(self):
        graph = load_skill_binding_graph("interface_utilization_high", ".")

        self.assertEqual(graph["skill_name"], "interface_utilization_high")
        self.assertEqual(graph["family"], "interface_or_link_utilization_high")
        self.assertEqual(graph["risk_level"], "readonly")
        self.assertEqual(graph["stage"], "v6.3")

        self.assertIn("mcp_netmiko_run_show", graph["allowed_tools"])
        self.assertIn("prometheus_range_query", graph["allowed_tools"])
        self.assertIn("parser_parse_cli_output", graph["allowed_tools"])

        self.assertIn("show_interface_detail", graph["allowed_capabilities"])
        self.assertIn("show_interface_error_counters", graph["allowed_capabilities"])
        self.assertIn("show_interface_aggregation", graph["allowed_capabilities"])

        self.assertIn("cisco_show_interfaces", graph["parsers"])
        self.assertIn("cisco_show_interfaces_counters_errors", graph["parsers"])
        self.assertIn("cisco_etherchannel_summary", graph["parsers"])

    def test_interface_skill_binding_validation_passes(self):
        result = validate_skill_binding("interface_utilization_high", ".")

        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["violations"], [])
        self.assertEqual(result["graph"]["missing_tools"], [])
        self.assertEqual(result["graph"]["missing_parsers"], [])

    def test_all_skill_bindings_validation_passes(self):
        result = validate_all_skill_bindings(".")

        self.assertEqual(result["verdict"], "pass")
        self.assertGreaterEqual(result["skill_count"], 1)


if __name__ == "__main__":
    unittest.main()
