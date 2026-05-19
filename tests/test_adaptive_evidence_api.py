import unittest

from netaiops.adaptive_evidence_api import (
    build_missing_facts_simulation_response,
    compact_adaptive_plan_for_api,
)


class TestAdaptiveEvidenceApi(unittest.TestCase):
    def test_compact_adaptive_plan_for_api(self):
        plan = {
            "stage": "v6.5",
            "mode": "skill_constrained_dry_run",
            "request_id": "rid",
            "family": "interface_or_link_utilization_high",
            "skill_name": "interface_utilization_high",
            "matched_skill": True,
            "dispatch_enabled": False,
            "dispatch_reason": "dry_run",
            "candidate_count": 1,
            "candidates": [
                {
                    "command": "show interfaces TenGigabitEthernet1/0/1",
                    "readonly": True,
                    "dispatch_status": "not_dispatched_dry_run",
                }
            ],
            "policy_result": {
                "verdict": "pass",
                "violations": [],
                "warnings": [],
            },
        }

        compact = compact_adaptive_plan_for_api(plan)

        self.assertEqual(compact["stage"], "v6.5")
        self.assertFalse(compact["dispatch_enabled"])
        self.assertTrue(compact["dry_run_only"])
        self.assertTrue(compact["readonly_only"])
        self.assertEqual(compact["policy_verdict"], "pass")
        self.assertEqual(compact["commands"], ["show interfaces TenGigabitEthernet1/0/1"])

    def test_missing_facts_simulation_response_ok(self):
        result = build_missing_facts_simulation_response(".", strict=True)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["stage"], "v6.5_adaptive_missing_facts_simulation")
        self.assertEqual(result["validation_errors"], [])

    def test_missing_facts_simulation_has_three_candidates(self):
        result = build_missing_facts_simulation_response(".", strict=True)
        plan = result["adaptive_plan"]

        self.assertEqual(plan["candidate_count"], 3)
        self.assertFalse(plan["dispatch_enabled"])
        self.assertTrue(plan["dry_run_only"])
        self.assertTrue(plan["readonly_only"])

    def test_missing_facts_simulation_commands(self):
        result = build_missing_facts_simulation_response(".", strict=True)
        commands = set(result["adaptive_plan"]["commands"])

        self.assertIn("show interfaces TenGigabitEthernet1/0/1", commands)
        self.assertIn("show interfaces TenGigabitEthernet1/0/1 counters errors", commands)
        self.assertIn("show etherchannel summary", commands)

    def test_missing_facts_simulation_policy_passes(self):
        result = build_missing_facts_simulation_response(".", strict=True)
        plan = result["adaptive_plan"]

        self.assertEqual(plan["policy_verdict"], "pass")
        self.assertEqual(plan["policy_violations"], [])


if __name__ == "__main__":
    unittest.main()
