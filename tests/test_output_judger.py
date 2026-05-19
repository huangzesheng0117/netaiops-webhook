import unittest
from pathlib import Path

from netaiops.output_judger import judge_command_result


FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


def load_fixture(name: str) -> str:
    return (FIXTURE_DIR / name).read_text(encoding="utf-8")


class TestOutputJudger(unittest.TestCase):
    def test_nxos_show_interface_ok_with_error_counters_is_not_hard_error(self):
        output = load_fixture("nxos_show_interface_ok.txt")
        result = judge_command_result(
            command="show interface Ethernet1/1",
            output=output,
            error="",
            judge_profile="network_cli_generic",
            dispatch_status="completed",
        )

        self.assertEqual(result["final_status"], "completed")
        self.assertFalse(result["hard_error"])

    def test_nxos_incorrect_command_is_hard_error(self):
        output = load_fixture("nxos_invalid_command.txt")
        result = judge_command_result(
            command="show interfaces Ethernet1/1",
            output=output,
            error="",
            judge_profile="network_cli_generic",
            dispatch_status="completed",
        )

        self.assertEqual(result["final_status"], "failed")
        self.assertTrue(result["hard_error"])
        self.assertEqual(result["matched_rule_id"], "incorrect_command")

    def test_huawei_unrecognized_command_is_hard_error(self):
        output = load_fixture("huawei_invalid_command.txt")
        result = judge_command_result(
            command="display fake command",
            output=output,
            error="",
            judge_profile="network_cli_generic",
            dispatch_status="completed",
        )

        self.assertEqual(result["final_status"], "failed")
        self.assertTrue(result["hard_error"])
        self.assertEqual(result["matched_rule_id"], "unrecognized_command")

    def test_f5_object_not_found_is_hard_error(self):
        output = load_fixture("f5_object_not_found.txt")
        result = judge_command_result(
            command="tmsh show ltm pool /Common/test_pool",
            output=output,
            error="",
            judge_profile="f5_tmsh",
            dispatch_status="completed",
        )

        self.assertEqual(result["final_status"], "failed")
        self.assertTrue(result["hard_error"])
        self.assertEqual(result["matched_rule_id"], "object_not_found")

    def test_mcp_no_device_named_is_hard_error(self):
        output = load_fixture("mcp_no_device_named.txt")
        result = judge_command_result(
            command="show interface Ethernet1/1",
            output=output,
            error="",
            judge_profile="network_cli_generic",
            dispatch_status="completed",
        )

        self.assertEqual(result["final_status"], "failed")
        self.assertTrue(result["hard_error"])
        self.assertEqual(result["matched_rule_id"], "no_device_named")

    def test_shell_command_not_found_is_hard_error(self):
        output = load_fixture("shell_command_not_found.txt")
        result = judge_command_result(
            command="show logging logfile | last 50",
            output=output,
            error="",
            judge_profile="network_cli_generic",
            dispatch_status="completed",
        )

        self.assertEqual(result["final_status"], "failed")
        self.assertTrue(result["hard_error"])
        self.assertEqual(result["matched_rule_id"], "shell_command_not_found")


    def test_cisco_show_interfaces_with_arp_timeout_is_not_hard_error(self):
        output = """TenGigabitEthernet1/0/1 is up, line protocol is up (connected)
  Hardware is Ten Gigabit Ethernet
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input 00:00:00, output 00:00:00, output hang never
"""
        result = judge_command_result(
            command="show interfaces TenGigabitEthernet1/0/1",
            output=output,
            error="",
            judge_profile="network_cli_generic",
            dispatch_status="completed",
        )

        self.assertEqual(result["final_status"], "completed")
        self.assertFalse(result["hard_error"])

    def test_wrapper_timeout_error_is_hard_error(self):
        result = judge_command_result(
            command="show interfaces TenGigabitEthernet1/0/1",
            output="",
            error="wrapper timeout: command timed out",
            judge_profile="network_cli_generic",
            dispatch_status="failed",
        )

        self.assertEqual(result["final_status"], "failed")
        self.assertTrue(result["hard_error"])
        self.assertEqual(result["matched_rule_id"], "timeout")


if __name__ == "__main__":
    unittest.main()
