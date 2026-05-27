import unittest

from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


class TestV711HillstoneConnectionAssets(unittest.TestCase):
    def test_hillstone_connection_playbook_matches_net_hillstone_alertnames(self):
        cases = [
            ("活动连接数", "hillstone_connection_capacity_high", "show session generic"),
            ("新建连接数(TCP)", "hillstone_connection_capacity_high", "show session generic"),
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

    def test_hillstone_connection_skill_is_loadable_by_family(self):
        ctx = build_runtime_context_for_family(
            "hillstone_connection_capacity_high",
            base_dir="/opt/netaiops-webhook",
            levels=["metadata", "instructions", "commands", "evidence", "schema"],
        )
        self.assertTrue(ctx.get("matched"))
        self.assertEqual(ctx.get("family"), "hillstone_connection_capacity_high")
        self.assertIn("commands", ctx)
        self.assertIn("evidence", ctx)
        self.assertIn("schema", ctx)


if __name__ == "__main__":
    unittest.main()
