import unittest

from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


class TestV711F5OpticalInterfaceAssets(unittest.TestCase):
    def test_f5_optical_playbooks_match_net_f5_alertnames(self):
        cases = [
            ("收光功率", "f5_optical_power_abnormal", "tmsh show net interface"),
            ("发光功率", "f5_optical_power_abnormal", "tmsh show net interface"),
        ]

        for alertname, expected_playbook_id, command_hint in cases:
            with self.subTest(alertname=alertname):
                event = {
                    "source": "alertmanager",
                    "vendor": "f5",
                    "platform": "tmos",
                    "device_ip": "10.0.0.10",
                    "hostname": "test-f5",
                    "alarm_type": alertname,
                    "object_name": "1.1",
                    "raw_text": alertname + " 1.1",
                    "labels": {
                        "severity": "critical",
                        "job": "LTM-F5",
                        "sysSwitchDdmStatName": "1.1",
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

    def test_f5_interface_status_playbook_matches_net_f5_alertname(self):
        event = {
            "source": "alertmanager",
            "vendor": "f5",
            "platform": "tmos",
            "device_ip": "10.0.0.10",
            "hostname": "test-f5",
            "alarm_type": "f5端口状态",
            "object_name": "1.1",
            "raw_text": "f5端口状态 1.1",
            "labels": {
                "severity": "critical",
                "job": "LTM-F5",
                "ifName": "1.1",
            },
            "annotations": {"description": "F5设备端口down"},
        }
        classification = classify_event(event)
        playbook = find_best_playbook(event, classification)
        self.assertIsNotNone(playbook)
        self.assertEqual(playbook.get("playbook_id"), "f5_interface_status_abnormal")

        candidates = build_execution_candidates_from_playbook(playbook, event)
        self.assertTrue(candidates)
        self.assertTrue(all(x.get("readonly") for x in candidates))
        commands = " ".join(x.get("command", "") for x in candidates).lower()
        self.assertIn("tmsh show net interface", commands)
        self.assertIn("tmsh show net trunk", commands)

    def test_f5_optical_and_interface_skills_are_loadable_by_family(self):
        families = [
            "f5_optical_power_abnormal",
            "f5_interface_status_abnormal",
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
