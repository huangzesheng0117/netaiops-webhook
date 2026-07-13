import unittest

from netaiops.adaptive_evidence_planner import build_adaptive_evidence_plan
from netaiops.adaptive_evidence_policy import load_adaptive_skill_constraints
from netaiops.skill_binding_validator import (
    load_skill_binding_graph,
    validate_all_skill_bindings,
    validate_skill_binding,
)
from netaiops.skill_compliance_validator import load_skill_contract
from netaiops.skill_registry import (
    load_skill,
    validate_all_skills,
    validate_skill_package,
)
from netaiops.skill_session_context import build_skill_context_for_session


class TestV111SkillSchemaCompatibility(unittest.TestCase):
    def test_current_v9_skill_preserves_authoritative_stage(self):
        skill = load_skill("interface_utilization_high", ".")
        self.assertEqual(skill["stage"], "v9")
        self.assertEqual(skill["schema_generation"], "current")

    def test_legacy_v63_skill_remains_legacy(self):
        skill = load_skill("device_cpu_high", ".")
        self.assertEqual(skill["stage"], "v6.3")
        self.assertEqual(skill["schema_generation"], "legacy")

    def test_all_real_skill_packages_validate_by_their_schema(self):
        result = validate_all_skills(".")
        self.assertEqual(result["verdict"], "pass", result["violations"])
        self.assertEqual(result["violations"], [])
        self.assertGreaterEqual(result["skill_count"], 50)

    def test_current_json_schema_properties_are_accepted(self):
        result = validate_skill_package("device_cpu_utilization_high", ".")
        self.assertEqual(result["verdict"], "pass", result["violations"])

    def test_current_bucket_schema_projects_semantic_capabilities(self):
        graph = load_skill_binding_graph("interface_utilization_high", ".")
        self.assertEqual(graph["stage"], "v9")
        self.assertIn("current_command_buckets", graph["command_schema_shapes"])
        self.assertIn("show_interface_detail", graph["allowed_capabilities"])
        self.assertIn(
            "show_interface_error_counters",
            graph["allowed_capabilities"],
        )
        self.assertIn(
            "show_interface_aggregation",
            graph["allowed_capabilities"],
        )
        self.assertIn("cisco_show_interfaces", graph["parsers"])
        self.assertEqual(graph["missing_tools"], [])
        self.assertEqual(graph["missing_parsers"], [])

    def test_current_binding_validation_passes_without_legacy_fields(self):
        result = validate_skill_binding("interface_utilization_high", ".")
        self.assertEqual(result["verdict"], "pass", result["violations"])
        self.assertEqual(result["violations"], [])

    def test_all_real_skill_bindings_pass(self):
        result = validate_all_skill_bindings(".")
        self.assertEqual(result["verdict"], "pass", result["violations"])
        self.assertEqual(result["violations"], [])

    def test_current_contract_contains_only_real_current_commands(self):
        contract = load_skill_contract("interface_utilization_high", ".")
        templates = set(contract["command_templates"])
        self.assertIn("show interfaces {interface}", templates)
        self.assertIn("show interfaces counters errors", templates)
        self.assertIn("show etherchannel summary", templates)
        self.assertNotIn(
            "show interfaces {interface} counters errors",
            templates,
        )

    def test_current_adaptive_constraints_use_real_commands(self):
        constraints = load_adaptive_skill_constraints(
            "interface_utilization_high",
            ".",
        )
        iosxe = constraints["platform_commands"]["cisco_iosxe"]
        self.assertEqual(
            iosxe["show_interface_detail"]["template"],
            "show interfaces {interface}",
        )
        self.assertEqual(
            iosxe["show_interface_error_counters"]["template"],
            "show interfaces counters errors",
        )
        self.assertEqual(
            iosxe["show_interface_aggregation"]["template"],
            "show etherchannel summary",
        )

    def test_current_adaptive_plan_is_readonly_and_not_dispatched(self):
        session = {
            "request_id": "v11-1-current-schema",
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
        plan = build_adaptive_evidence_plan(
            session,
            {"command_results": []},
            {"evidence_summary": {"facts": {}}},
            ".",
        )
        commands = {item["command"] for item in plan["candidates"]}
        self.assertEqual(plan["policy_result"]["verdict"], "pass")
        self.assertEqual(plan["candidate_count"], 3)
        self.assertFalse(plan["dispatch_enabled"])
        self.assertEqual(
            commands,
            {
                "show interfaces TenGigabitEthernet1/0/1",
                "show interfaces counters errors",
                "show etherchannel summary",
            },
        )
        for item in plan["candidates"]:
            self.assertTrue(item["readonly"])
            self.assertEqual(
                item["dispatch_status"],
                "not_dispatched_dry_run",
            )

    def test_session_context_reports_current_skill_stage(self):
        session = {
            "request_id": "rid",
            "classification": {
                "family": "interface_or_link_utilization_high",
            },
        }
        context = build_skill_context_for_session(session, ".")
        self.assertEqual(context["stage"], "v9")
        self.assertEqual(context["schema_generation"], "current")
        self.assertEqual(context["binding_verdict"], "pass")

    def test_legacy_contract_still_exposes_legacy_capabilities(self):
        contract = load_skill_contract("device_cpu_high", ".")
        self.assertEqual(contract["stage"], "v6.3")
        self.assertEqual(contract["schema_generation"], "legacy")
        self.assertTrue(contract["allowed_capabilities"])
        self.assertTrue(contract["command_templates"])


if __name__ == "__main__":
    unittest.main()
