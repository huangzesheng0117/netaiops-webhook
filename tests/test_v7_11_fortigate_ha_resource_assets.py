import unittest

from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


class TestV711FortigateHaResourceAssets(unittest.TestCase):
    def test_fortigate_ha_resource_playbooks_match_net_feita_alertnames(self):
        cases = [
            ("主备状态切换", "fortigate_ha_status_change", "get sys ha status"),
            ("同步状态", "fortigate_ha_sync_abnormal", "diagnose sys ha checksum show"),
            ("CPU平均利用率", "fortigate_cpu_high", "get system performance status"),
            ("CPU单核利用率", "fortigate_cpu_high", "diagnose sys top"),
            ("内存利用率", "fortigate_memory_high", "diagnose hardware sysinfo memory"),
            ("硬件传感器状态", "fortigate_hardware_sensor_abnormal", "get hardware status"),
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

    def test_fortigate_ha_resource_skills_are_loadable_by_family(self):
        families = [
            "fortigate_ha_status_change",
            "fortigate_ha_sync_abnormal",
            "fortigate_cpu_high",
            "fortigate_memory_high",
            "fortigate_hardware_sensor_abnormal",
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
