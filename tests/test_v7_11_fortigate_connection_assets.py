import unittest

from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


class TestV711FortigateConnectionAssets(unittest.TestCase):
    def test_fortigate_connection_playbooks_match_net_feita_alertnames(self):
        cases = [
            ("活动连接数", "fortigate_connection_capacity_high", "diagnose sys session stat"),
            ("新建连接数(TCP)", "fortigate_connection_capacity_high", "diagnose sys session stat"),
            ("活动连接数突增", "fortigate_connection_anomaly", "diagnose sys session stat"),
            ("活动连接数突降", "fortigate_connection_anomaly", "diagnose sys session stat"),
            ("新建连接数突增", "fortigate_connection_anomaly", "diagnose sys session stat"),
            ("新建连接数突降", "fortigate_connection_anomaly", "diagnose sys session stat"),
        ]

        for alertname, expected_playbook_id, command_hint in cases:
            with self.subTest(alertname=alertname):
                event = {
                    "source": "alertmanager",
                    "vendor": "fortigate",
                    "platform": "fortios",
                    "device_ip": "10.0.0.30",
                    "hostname": "test-fortigate",
                    "alarm_type": alertname,
                    "raw_text": alertname + " 飞塔防火墙",
                    "labels": {
                        "severity": "critical",
                        "job": "FW-FORTIGATE-400",
                        "vendor": "fortigate",
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

    def test_fortigate_connection_skills_are_loadable_by_family(self):
        families = [
            "fortigate_connection_capacity_high",
            "fortigate_connection_anomaly",
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
