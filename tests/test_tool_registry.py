import unittest

from netaiops.tool_registry import get_tool, list_tools_for_family, validate_tool_registry


class TestToolRegistry(unittest.TestCase):
    def test_tool_registry_valid(self):
        result = validate_tool_registry()
        self.assertEqual(result["verdict"], "pass")
        self.assertGreaterEqual(result["enabled_tool_count"], 1)

    def test_mcp_netmiko_tool_is_readonly(self):
        tool = get_tool("mcp_netmiko_run_show")
        self.assertIsNotNone(tool)
        self.assertEqual(tool["risk_level"], "readonly")
        self.assertTrue(tool["enabled"])

    def test_interface_family_has_required_tools(self):
        tools = list_tools_for_family("interface_or_link_utilization_high")
        names = {item["tool_name"] for item in tools}
        self.assertIn("mcp_netmiko_run_show", names)
        self.assertIn("prometheus_range_query", names)
        self.assertIn("parser_parse_cli_output", names)


if __name__ == "__main__":
    unittest.main()
