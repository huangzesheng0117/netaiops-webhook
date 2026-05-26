import unittest

from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


class TestV711F5SystemHardwareAssets(unittest.TestCase):
    def test_f5_system_hardware_playbooks_match_net_f5_alertnames(self):
        cases = [
            ("主备状态变化", "f5_ha_status_change", "tmsh show sys failover"),
            ("全局CPU利用率", "f5_cpu_high", "tmsh show sys cpu"),
            ("数据平面CPU利用率", "f5_cpu_high", "tmsh show sys cpu"),
            ("控制平面CPU利用率", "f5_cpu_high", "tmsh show sys cpu"),
            ("全局内存利用率", "f5_memory_high", "tmsh show sys memory"),
            ("TMM内存利用率", "f5_memory_high", "tmsh show sys memory"),
            ("磁盘利用率", "f5_disk_high", "tmsh show sys disk"),
            ("机框风扇状态", "f5_hardware_component_abnormal", "tmsh show sys hardware"),
            ("机框电源状态", "f5_hardware_component_abnormal", "tmsh show sys hardware"),
            ("机框板卡状态", "f5_hardware_component_abnormal", "tmsh show sys hardware"),
            ("CPU温度", "f5_temperature_high", "tmsh show sys hardware"),
            ("机框温度", "f5_temperature_high", "tmsh show sys hardware"),
            ("机框板卡温度", "f5_temperature_high", "tmsh show sys hardware"),
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
                    "raw_text": alertname,
                    "labels": {"severity": "critical", "job": "LTM-F5"},
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

    def test_f5_system_hardware_skills_are_loadable_by_family(self):
        families = [
            "f5_ha_status_change",
            "f5_cpu_high",
            "f5_memory_high",
            "f5_disk_high",
            "f5_hardware_component_abnormal",
            "f5_temperature_high",
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
