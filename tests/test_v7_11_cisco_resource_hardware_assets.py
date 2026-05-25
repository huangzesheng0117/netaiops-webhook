import unittest

from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


class TestV711CiscoResourceHardwareAssets(unittest.TestCase):
    def test_cisco_resource_playbooks_match_net_cisco_alertnames(self):
        cases = [
            ("全局CPU利用率", "cisco_device_cpu_high"),
            ("全局内存利用率", "cisco_device_memory_high"),
            ("磁盘利用率", "cisco_device_disk_high"),
            ("电源状态", "cisco_hardware_component_fault"),
            ("风扇状态", "cisco_hardware_component_fault"),
            ("非路由器温度", "cisco_temperature_high"),
            ("路由器温度", "cisco_temperature_high"),
        ]

        for alertname, expected_playbook_id in cases:
            with self.subTest(alertname=alertname):
                event = {
                    "source": "alertmanager",
                    "vendor": "cisco",
                    "platform": "nxos",
                    "device_ip": "10.0.0.1",
                    "hostname": "test-device",
                    "alarm_type": alertname,
                    "raw_text": alertname,
                    "labels": {"severity": "critical"},
                    "annotations": {"description": alertname},
                }
                classification = classify_event(event)
                playbook = find_best_playbook(event, classification)
                self.assertIsNotNone(playbook)
                self.assertEqual(playbook.get("playbook_id"), expected_playbook_id)

                candidates = build_execution_candidates_from_playbook(playbook, event)
                self.assertTrue(candidates)
                self.assertTrue(all(x.get("readonly") for x in candidates))

    def test_cisco_resource_skills_are_loadable_by_family(self):
        families = [
            "device_cpu_high",
            "device_memory_high",
            "device_disk_high",
            "hardware_power_abnormal",
            "hardware_fan_abnormal",
            "hardware_temperature_high",
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
