import unittest

from netaiops.skill_compliance_validator import (
    load_skill_contract,
    validate_execution_against_skill,
    validate_review_against_skill,
    validate_session_skill_context,
)


class TestSkillComplianceValidator(unittest.TestCase):
    def test_load_interface_skill_contract(self):
        contract = load_skill_contract("interface_utilization_high", ".")

        self.assertEqual(contract["skill_name"], "interface_utilization_high")
        self.assertEqual(contract["family"], "interface_or_link_utilization_high")
        self.assertIn("show interfaces {interface}", contract["command_templates"])
        self.assertIn("show interfaces {interface} counters errors", contract["command_templates"])
        self.assertIn("show etherchannel summary", contract["command_templates"])
        self.assertIn("cisco_show_interfaces", contract["parsers"])
        self.assertIn("interface", contract["required_facts"])

    def test_session_skill_context_passes(self):
        session = {
            "skill_context": {
                "matched": True,
                "family": "interface_or_link_utilization_high",
                "skill_name": "interface_utilization_high",
                "binding_verdict": "pass",
                "violations": [],
                "warnings": [],
                "allowed_tools": ["mcp_netmiko_run_show"],
                "allowed_capabilities": ["show_interface_detail"],
                "parsers": ["cisco_show_interfaces"],
            }
        }

        result = validate_session_skill_context(session)
        self.assertEqual(result["verdict"], "pass")

    def test_execution_against_skill_passes(self):
        contract = load_skill_contract("interface_utilization_high", ".")
        execution_data = {
            "command_results": [
                {
                    "command": "show interfaces TenGigabitEthernet1/0/1",
                    "parsed": {
                        "status": "parsed",
                        "parser": "cisco_show_interfaces",
                        "parsed": {"interface": "TenGigabitEthernet1/0/1"},
                    },
                },
                {
                    "command": "show interfaces TenGigabitEthernet1/0/1 counters errors",
                    "parsed": {
                        "status": "parsed",
                        "parser": "cisco_show_interfaces_counters_errors",
                        "parsed": {"interface": "Te1/0/1"},
                    },
                },
                {
                    "command": "show etherchannel summary",
                    "parsed": {
                        "status": "parsed",
                        "parser": "cisco_etherchannel_summary",
                        "parsed": {"port_channel_count": 1},
                    },
                },
            ]
        }

        result = validate_execution_against_skill(execution_data, contract)
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["violations"], [])

    def test_execution_rejects_unallowed_command(self):
        contract = load_skill_contract("interface_utilization_high", ".")
        execution_data = {
            "command_results": [
                {
                    "command": "show version",
                    "parsed": {
                        "status": "skipped",
                        "parser": "",
                        "parsed": {},
                    },
                }
            ]
        }

        result = validate_execution_against_skill(execution_data, contract)
        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(any("command not allowed" in item for item in result["violations"]))

    def test_review_against_skill_passes(self):
        contract = load_skill_contract("interface_utilization_high", ".")
        review_data = {
            "evidence_summary": {
                "facts": {
                    "interface": "TenGigabitEthernet1/0/1",
                    "admin_status": "up",
                    "oper_status": "up",
                    "bandwidth_bps": 10000000000,
                    "input_rate_bps": 13385000,
                    "output_rate_bps": 24636000,
                    "parsed_facts_enabled": True,
                    "facts_source_preference": "parsed_first_raw_fallback",
                    "parsed_fact_sources": [
                        "cisco_show_interfaces",
                        "cisco_show_interfaces_counters_errors",
                        "cisco_etherchannel_summary",
                    ],
                },
                "notify_lines": [
                    "接口状态：TenGigabitEthernet1/0/1 oper=up admin=up",
                    "告警方向：出向",
                    "接口物理带宽：10.00 Gbps",
                    "告警口径带宽：300.00 Mbps",
                    "设备侧实时速率：input=13.38 Mbps，output=24.64 Mbps",
                    "设备侧估算利用率：input=0.13%，output=0.25%",
                    "接口错误/丢弃计数：CRC=5733",
                    "综合执行结果判断：只读取证完成",
                ],
            }
        }

        result = validate_review_against_skill(review_data, contract, strict_notification=True)
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["violations"], [])


if __name__ == "__main__":
    unittest.main()
