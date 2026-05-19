import unittest

from netaiops.adaptive_session_context import (
    attach_adaptive_evidence_context_to_session,
    build_adaptive_evidence_context_for_session,
    compact_adaptive_plan,
)


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


class TestAdaptiveSessionContext(unittest.TestCase):
    def test_compact_plan(self):
        plan = {
            "stage": "v6.5",
            "mode": "skill_constrained_dry_run",
            "request_id": "rid",
            "family": "interface_or_link_utilization_high",
            "skill_name": "interface_utilization_high",
            "matched_skill": True,
            "extra_round": 1,
            "dispatch_enabled": False,
            "dispatch_reason": "dry_run",
            "candidate_count": 0,
            "suppressed_candidate_count": 0,
            "gaps": {"required_missing": [], "preferred_missing": []},
            "limits": {
                "adaptive_execution_enabled": False,
                "readonly_only": True,
                "max_extra_rounds": 1,
                "max_extra_commands": 3,
            },
            "policy_result": {
                "verdict": "pass",
                "violations": [],
                "warnings": [],
            },
            "candidates": [],
        }

        context = compact_adaptive_plan(plan)

        self.assertEqual(context["stage"], "v6.5")
        self.assertEqual(context["mode"], "skill_constrained_dry_run")
        self.assertFalse(context["dispatch_enabled"])
        self.assertFalse(context["adaptive_execution_enabled"])
        self.assertEqual(context["policy_verdict"], "pass")

    def test_context_complete_facts_has_no_candidate(self):
        session = make_session()
        execution_data = {
            "command_results": [
                {"command": "show interfaces TenGigabitEthernet1/0/1"},
                {"command": "show interfaces TenGigabitEthernet1/0/1 counters errors"},
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

        context = build_adaptive_evidence_context_for_session(
            session=session,
            base_dir=".",
            execution_data=execution_data,
            review_data=review_data,
        )

        self.assertEqual(context["policy_verdict"], "pass")
        self.assertEqual(context["candidate_count"], 0)
        self.assertFalse(context["dispatch_enabled"])

    def test_context_missing_facts_has_candidate(self):
        session = make_session()
        execution_data = {"command_results": []}
        review_data = {"evidence_summary": {"facts": {}}}

        context = build_adaptive_evidence_context_for_session(
            session=session,
            base_dir=".",
            execution_data=execution_data,
            review_data=review_data,
        )

        self.assertEqual(context["policy_verdict"], "pass")
        self.assertGreaterEqual(context["candidate_count"], 1)
        self.assertFalse(context["dispatch_enabled"])
        self.assertTrue(context["candidates"])

    def test_attach_adaptive_context_to_session(self):
        session = make_session()
        result = attach_adaptive_evidence_context_to_session(session, ".")

        self.assertIn("adaptive_evidence_context", result)
        self.assertEqual(result["adaptive_evidence_context"]["stage"], "v6.5")
        self.assertFalse(result["adaptive_evidence_context"]["dispatch_enabled"])


if __name__ == "__main__":
    unittest.main()
