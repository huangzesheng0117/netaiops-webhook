import unittest

from netaiops.evidence_facts import build_interface_evidence_summary


class TestEvidenceFacts(unittest.TestCase):
    def test_cisco_show_interfaces_status_line_uses_parsed_oper_admin(self):
        execution_data = {
            "family_result": {"family": "interface_or_link_utilization_high"},
            "classification": {"family": "interface_or_link_utilization_high"},
            "target_scope": {
                "interface": "Te1/0/1",
                "alarm_type": "SH8-GDS利用率-出向",
            },
            "command_results": [
                {
                    "capability": "show_interface_detail",
                    "command": "show interfaces TenGigabitEthernet1/0/1",
                    "dispatch_status": "completed",
                    "output": """TenGigabitEthernet1/0/1 is up, line protocol is up (connected)
  Hardware is Ten Gigabit Ethernet
  MTU 1500 bytes, BW 10000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  ARP type: ARPA, ARP Timeout 04:00:00
  5 minute input rate 13385000 bits/sec, 7094 packets/sec
  5 minute output rate 24636000 bits/sec, 7561 packets/sec
     5856 input errors, 5733 CRC, 0 frame, 0 overrun, 0 ignored
""",
                }
            ],
        }

        summary = build_interface_evidence_summary(execution_data)
        facts = summary.get("facts", {})
        joined = "\n".join((summary.get("notify_lines") or []) + (summary.get("key_findings") or []))

        self.assertEqual(facts.get("interface"), "TenGigabitEthernet1/0/1")
        self.assertEqual(facts.get("oper_status"), "up")
        self.assertEqual(facts.get("admin_status"), "up")
        self.assertIn("接口状态：TenGigabitEthernet1/0/1 oper=up admin=up", joined)
        self.assertNotIn("oper=未知", joined)
        self.assertNotIn("admin=未知", joined)

    def test_evidence_prefers_parsed_show_interface_facts(self):
        execution_data = {
            "family_result": {"family": "interface_or_link_utilization_high"},
            "classification": {"family": "interface_or_link_utilization_high"},
            "target_scope": {
                "interface": "Te1/0/1",
                "alarm_type": "SH8-GDS利用率-出向",
            },
            "command_results": [
                {
                    "command": "show interfaces TenGigabitEthernet1/0/1",
                    "dispatch_status": "completed",
                    "output": "",
                    "parsed": {
                        "status": "parsed",
                        "parser": "cisco_show_interfaces",
                        "parsed": {
                            "matched": True,
                            "interface": "TenGigabitEthernet1/0/1",
                            "admin_status": "up",
                            "oper_status": "up",
                            "bandwidth_bps": 10000000000,
                            "input_rate_bps": 13385000,
                            "output_rate_bps": 24636000,
                            "input_utilization_percent_estimated": 0.13,
                            "output_utilization_percent_estimated": 0.25,
                            "crc": 5733,
                            "output_errors": 0,
                            "output_drops": 0,
                        },
                    },
                }
            ],
        }

        summary = build_interface_evidence_summary(execution_data)
        facts = summary.get("facts", {})

        self.assertTrue(facts.get("parsed_facts_enabled"))
        self.assertEqual(facts.get("facts_source_preference"), "parsed_first_raw_fallback")
        self.assertEqual(facts.get("interface"), "TenGigabitEthernet1/0/1")
        self.assertEqual(facts.get("oper_status"), "up")
        self.assertEqual(facts.get("admin_status"), "up")
        self.assertEqual(facts.get("bandwidth_bps"), 10000000000)
        self.assertEqual(facts.get("output_rate_bps"), 24636000)
        self.assertEqual(facts.get("output_utilization_percent_estimated"), 0.25)

    def test_evidence_merges_parsed_counters_and_etherchannel(self):
        execution_data = {
            "family_result": {"family": "interface_or_link_utilization_high"},
            "classification": {"family": "interface_or_link_utilization_high"},
            "target_scope": {
                "interface": "Te1/0/1",
                "alarm_type": "SH8-GDS利用率-出向",
            },
            "command_results": [
                {
                    "command": "show interfaces TenGigabitEthernet1/0/1 counters errors",
                    "dispatch_status": "completed",
                    "output": "",
                    "parsed": {
                        "status": "parsed",
                        "parser": "cisco_show_interfaces_counters_errors",
                        "parsed": {
                            "matched": True,
                            "interface": "Te1/0/1",
                            "command_interface": "TenGigabitEthernet1/0/1",
                            "crc": 5733,
                            "fcs_err": 5733,
                            "rcv_err": 5856,
                            "xmit_err": 0,
                            "out_discards": 0,
                            "runts": 0,
                        },
                    },
                },
                {
                    "command": "show etherchannel summary",
                    "dispatch_status": "completed",
                    "output": "",
                    "parsed": {
                        "status": "parsed",
                        "parser": "cisco_etherchannel_summary",
                        "parsed": {
                            "matched": True,
                            "channel_group_count": 3,
                            "aggregator_count": 3,
                            "port_channel_count": 3,
                            "member_count": 6,
                            "bundled_member_count": 4,
                            "down_member_count": 2,
                            "port_channels": [],
                            "members": [],
                        },
                    },
                },
            ],
        }

        summary = build_interface_evidence_summary(execution_data)
        facts = summary.get("facts", {})

        self.assertTrue(facts.get("parsed_facts_enabled"))
        self.assertEqual(facts.get("crc"), 5733)
        self.assertEqual(facts.get("fcs_err"), 5733)
        self.assertEqual(facts.get("rcv_err"), 5856)
        self.assertEqual(facts.get("out_discards"), 0)
        self.assertEqual(facts.get("channel_group_count"), 3)
        self.assertEqual(facts.get("etherchannel_member_count"), 6)
        self.assertEqual(facts.get("etherchannel_bundled_member_count"), 4)
        self.assertEqual(facts.get("etherchannel_down_member_count"), 2)
        self.assertIn("cisco_show_interfaces_counters_errors", facts.get("parsed_fact_sources"))
        self.assertIn("cisco_etherchannel_summary", facts.get("parsed_fact_sources"))


if __name__ == "__main__":
    unittest.main()
