import unittest

from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


class TestV711HillstoneHaResourceAssets(unittest.TestCase):
    def test_hillstone_ha_resource_playbooks_match_net_hillstone_alertnames(self):
        cases = [
            ("主备状态变化", "hillstone_ha_status_change", "show ha cluster"),
            ("CPU利用率", "hillstone_cpu_high", "show system resource"),
            ("内存利用率", "hillstone_memory_high", "show system resource"),
        ]

        for alertname, expected_playbook_id, command_hint in cases:
            with self.subTest(alertname=alertname):
                event = {
                    "source": "alertmanager",
                    "vendor": "hillstone",
                    "platform": "stoneos",
                    "device_ip": "10.0.0.50",
                    "hostname": "test-hillstone",
                    "alarm_type": alertname,
                    "raw_text": alertname + " 山石防火墙",
                    "labels": {
                        "severity": "critical",
                        "job": "FW-HILLSTONE-V8-INT",
                        "vendor": "hillstone",
                    },
                    "annotations": {"description": alertname},
                }
                classification = classify_event(event)
                playbook = find_best_playbook(event, classification)
                self.assertIsNotNone(playbook)
                self.assertEqual(playbook.get("playbook_id"), expected_playbook_id)

                candidates = build_execution_candidates_from_playbook(playbook, event)
                self.assertTrue(candidates)
                self.assertTrue(all(x.get("readonly") for x in candidates))

                commands = " ".join(x.get("command", "") for x in candidates).lower()
                self.assertIn(command_hint.lower(), commands)

    def test_hillstone_ha_resource_skills_are_loadable_by_family(self):
        families = [
            "hillstone_ha_status_change",
            "hillstone_cpu_high",
            "hillstone_memory_high",
        ]

        for family in families:
            with self.subTest(family=family):
                ctx = build_runtime_context_for_family(
                    family,
                    base_dir="/opt/netaiops-webhook",
                    levels=["metadata", "instructions", "commands", "evidence", "schema"],
                )
                self.assertTrue(ctx.get("matched"))
                self.assertEqual(ctx.get("family"), family)
                self.assertIn("commands", ctx)
                self.assertIn("evidence", ctx)
                self.assertIn("schema", ctx)


if __name__ == "__main__":
    unittest.main()
