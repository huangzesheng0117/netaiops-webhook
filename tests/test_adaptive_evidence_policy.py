import unittest

from netaiops.adaptive_evidence_policy import (
    command_has_forbidden_pattern,
    command_matches_any_template,
    load_adaptive_skill_constraints,
    validate_adaptive_candidate,
    validate_adaptive_plan,
)


class TestAdaptiveEvidencePolicy(unittest.TestCase):
    def test_load_constraints(self):
        constraints = load_adaptive_skill_constraints("interface_utilization_high", ".")

        self.assertEqual(constraints["stage"], "v6.5")
        self.assertEqual(constraints["mode"], "skill_constrained_dry_run")
        self.assertEqual(constraints["risk_level"], "readonly")
        self.assertIn("mcp_netmiko_run_show", constraints["allowed_tools"])
        self.assertIn("show_interface_detail", constraints["allowed_capabilities"])
        self.assertIn("show interfaces {interface}", constraints["command_templates"])
        self.assertIn("configure terminal", constraints["forbidden_patterns"])
        self.assertFalse(constraints["limits"]["adaptive_execution_enabled"])

    def test_command_template_match(self):
        constraints = load_adaptive_skill_constraints("interface_utilization_high", ".")

        self.assertTrue(command_matches_any_template(
            "show interfaces TenGigabitEthernet1/0/1",
            constraints["command_templates"],
        ))

        self.assertTrue(command_matches_any_template(
            "show etherchannel summary",
            constraints["command_templates"],
        ))

        self.assertFalse(command_matches_any_template(
            "show version",
            constraints["command_templates"],
        ))

    def test_forbidden_pattern_detection(self):
        forbidden = ["shutdown", "clear counters"]
        self.assertEqual(command_has_forbidden_pattern("show interfaces Te1/0/1", forbidden), "")
        self.assertEqual(command_has_forbidden_pattern("clear counters Te1/0/1", forbidden), "clear counters")

    def test_validate_allowed_candidate_passes(self):
        constraints = load_adaptive_skill_constraints("interface_utilization_high", ".")
        candidate = {
            "tool_name": "mcp_netmiko_run_show",
            "capability": "show_interface_detail",
            "command": "show interfaces TenGigabitEthernet1/0/1",
            "parser": "cisco_show_interfaces",
            "readonly": True,
        }

        result = validate_adaptive_candidate(candidate, constraints)

        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["violations"], [])

    def test_validate_bad_candidate_fails(self):
        constraints = load_adaptive_skill_constraints("interface_utilization_high", ".")
        candidate = {
            "tool_name": "mcp_netmiko_run_show",
            "capability": "show_interface_detail",
            "command": "shutdown",
            "parser": "cisco_show_interfaces",
            "readonly": False,
        }

        result = validate_adaptive_candidate(candidate, constraints)

        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(result["violations"])

    def test_validate_plan_limit(self):
        constraints = load_adaptive_skill_constraints("interface_utilization_high", ".")
        candidates = []
        for idx in range(5):
            candidates.append({
                "tool_name": "mcp_netmiko_run_show",
                "capability": "show_interface_detail",
                "command": f"show interfaces Te1/0/{idx}",
                "parser": "cisco_show_interfaces",
                "readonly": True,
            })

        plan = {
            "stage": "v6.5",
            "mode": "skill_constrained_dry_run",
            "dispatch_enabled": False,
            "extra_round": 1,
            "candidates": candidates,
        }

        result = validate_adaptive_plan(plan, constraints)

        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(any("candidate count exceeds" in item for item in result["violations"]))


if __name__ == "__main__":
    unittest.main()
