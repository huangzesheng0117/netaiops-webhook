import unittest

from netaiops.adaptive_evidence_planner import build_adaptive_evidence_plan


def make_session():
    return {
        "request_id": "rid",
        "skill_context": {
            "family": "interface_or_link_utilization_high",
            "skill_name": "interface_utilization_high",
            "binding_verdict": "pass",
        },
        "target_scope": {
            "interface": "TenGigabitEthernet1/0/1",
            "platform": "cisco_iosxe",
        },
    }


class TestAdaptiveEvidencePlanner(unittest.TestCase):
    def test_missing_required_facts_creates_detail_candidate(self):
        session = make_session()
        execution_data = {"command_results": []}
        review_data = {"evidence_summary": {"facts": {}}}

        plan = build_adaptive_evidence_plan(session, execution_data, review_data, ".")

        self.assertEqual(plan["stage"], "v6.5")
        self.assertEqual(plan["mode"], "skill_constrained_dry_run")
        self.assertFalse(plan["dispatch_enabled"])
        self.assertEqual(plan["policy_result"]["verdict"], "pass")
        self.assertGreaterEqual(plan["candidate_count"], 1)

        commands = [x["command"] for x in plan["candidates"]]
        self.assertIn("show interfaces TenGigabitEthernet1/0/1", commands)

    def test_existing_detail_command_is_not_duplicated(self):
        session = make_session()
        execution_data = {
            "command_results": [
                {"command": "show interfaces TenGigabitEthernet1/0/1"}
            ]
        }
        review_data = {"evidence_summary": {"facts": {}}}

        plan = build_adaptive_evidence_plan(session, execution_data, review_data, ".")

        commands = [x["command"] for x in plan["candidates"]]
        self.assertNotIn("show interfaces TenGigabitEthernet1/0/1", commands)

    def test_missing_counter_facts_create_counter_candidate(self):
        session = make_session()
        execution_data = {
            "command_results": [
                {"command": "show interfaces TenGigabitEthernet1/0/1"}
            ]
        }
        review_data = {
            "evidence_summary": {
                "facts": {
                    "interface": "TenGigabitEthernet1/0/1",
                    "admin_status": "up",
                    "oper_status": "up",
                    "bandwidth_bps": 10000000000,
                    "input_rate_bps": 1000,
                    "output_rate_bps": 2000,
                }
            }
        }

        plan = build_adaptive_evidence_plan(session, execution_data, review_data, ".")

        commands = [x["command"] for x in plan["candidates"]]
        self.assertIn("show interfaces counters errors", commands)
        self.assertNotIn("show interfaces TenGigabitEthernet1/0/1 counters errors", commands)

    def test_complete_facts_need_no_extra_command_when_existing_commands_cover(self):
        session = make_session()
        execution_data = {
            "command_results": [
                {"command": "show interfaces TenGigabitEthernet1/0/1"},
                {"command": "show interfaces counters errors"},
                {"command": "show etherchannel summary"},
            ]
        }
        review_data = {
            "evidence_summary": {
                "facts": {
                    "interface": "TenGigabitEthernet1/0/1",
                    "admin_status": "up",
                    "oper_status": "up",
                    "bandwidth_bps": 10000000000,
                    "input_rate_bps": 1000,
                    "output_rate_bps": 2000,
                    "crc": 0,
                    "fcs_err": 0,
                    "rcv_err": 0,
                    "xmit_err": 0,
                    "out_discards": 0,
                    "output_discards": 0,
                    "channel_group_count": 1,
                    "port_channel_count": 1,
                    "etherchannel_member_count": 2,
                    "etherchannel_bundled_member_count": 2,
                    "etherchannel_down_member_count": 0,
                }
            }
        }

        plan = build_adaptive_evidence_plan(session, execution_data, review_data, ".")

        self.assertEqual(plan["policy_result"]["verdict"], "pass")
        self.assertEqual(plan["candidate_count"], 0)


if __name__ == "__main__":
    unittest.main()
