import json
import unittest
from pathlib import Path

from netaiops.adaptive_evidence_planner import build_adaptive_evidence_plan


FIXTURE_DIR = Path("tests/fixtures/adaptive_missing_facts")


def load_json(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


class TestAdaptiveMissingFactsSample(unittest.TestCase):
    def test_fixture_files_exist(self):
        self.assertTrue((FIXTURE_DIR / "session.missing_facts.json").exists())
        self.assertTrue((FIXTURE_DIR / "execution.empty.json").exists())
        self.assertTrue((FIXTURE_DIR / "review.missing_facts.json").exists())

    def test_missing_facts_generates_expected_candidates(self):
        session = load_json("session.missing_facts.json")
        execution_data = load_json("execution.empty.json")
        review_data = load_json("review.missing_facts.json")

        plan = build_adaptive_evidence_plan(
            session=session,
            execution_data=execution_data,
            review_data=review_data,
            base_dir=".",
        )

        commands = {item["command"] for item in plan["candidates"]}

        self.assertEqual(plan["stage"], "v6.5")
        self.assertEqual(plan["mode"], "skill_constrained_dry_run")
        self.assertEqual(plan["policy_result"]["verdict"], "pass")
        self.assertEqual(plan["candidate_count"], 3)

        self.assertIn("show interfaces TenGigabitEthernet1/0/1", commands)
        self.assertIn("show interfaces TenGigabitEthernet1/0/1 counters errors", commands)
        self.assertIn("show etherchannel summary", commands)

    def test_candidates_are_readonly_and_not_dispatched(self):
        session = load_json("session.missing_facts.json")
        execution_data = load_json("execution.empty.json")
        review_data = load_json("review.missing_facts.json")

        plan = build_adaptive_evidence_plan(
            session=session,
            execution_data=execution_data,
            review_data=review_data,
            base_dir=".",
        )

        self.assertFalse(plan["dispatch_enabled"])

        for item in plan["candidates"]:
            self.assertTrue(item["readonly"])
            self.assertEqual(item["tool_name"], "mcp_netmiko_run_show")
            self.assertEqual(item["dispatch_status"], "not_dispatched_dry_run")
            self.assertNotIn("shutdown", item["command"].lower())
            self.assertNotIn("clear counters", item["command"].lower())
            self.assertNotIn("configure terminal", item["command"].lower())

    def test_candidate_count_respects_limit(self):
        session = load_json("session.missing_facts.json")
        execution_data = load_json("execution.empty.json")
        review_data = load_json("review.missing_facts.json")

        plan = build_adaptive_evidence_plan(
            session=session,
            execution_data=execution_data,
            review_data=review_data,
            base_dir=".",
        )

        self.assertLessEqual(plan["candidate_count"], plan["limits"]["max_extra_commands"])
        self.assertEqual(plan["limits"]["max_extra_commands"], 3)


if __name__ == "__main__":
    unittest.main()
