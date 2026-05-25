import unittest

from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


class TestV711CiscoOpticalPacketAssets(unittest.TestCase):
    def test_cisco_optical_power_playbook_matches_net_cisco_alertnames(self):
        cases = [
            ("NXOS光功率", "Ethernet1/10"),
            ("Catalyst光功率", "TenGigabitEthernet1/0/1"),
        ]

        for alertname, iface in cases:
            with self.subTest(alertname=alertname):
                event = {
                    "source": "alertmanager",
                    "vendor": "cisco",
                    "platform": "nxos",
                    "device_ip": "10.0.0.1",
                    "hostname": "test-device",
                    "alarm_type": alertname,
                    "object_name": iface,
                    "interface": iface,
                    "raw_text": alertname + " " + iface,
                    "labels": {
                        "severity": "critical",
                        "interface": iface,
                    },
                    "annotations": {"description": alertname},
                }
                classification = classify_event(event)
                playbook = find_best_playbook(event, classification)
                self.assertIsNotNone(playbook)
                self.assertEqual(playbook.get("playbook_id"), "cisco_optical_power_abnormal")

                candidates = build_execution_candidates_from_playbook(playbook, event)
                self.assertTrue(candidates)
                self.assertTrue(all(x.get("readonly") for x in candidates))
                commands = " ".join(x.get("command", "") for x in candidates).lower()
                self.assertIn("transceiver", commands)

    def test_cisco_packet_error_playbook_matches_5m_aliases(self):
        cases = [
            ("5m错包数-入向", "port-channel45"),
            ("5m错包数-出向", "port-channel45"),
            ("端口CRC错包", "Ethernet1/1"),
        ]

        for alertname, iface in cases:
            with self.subTest(alertname=alertname):
                event = {
                    "source": "alertmanager",
                    "vendor": "cisco",
                    "platform": "nxos",
                    "device_ip": "10.0.0.1",
                    "hostname": "test-device",
                    "alarm_type": alertname,
                    "object_name": iface,
                    "interface": iface,
                    "raw_text": alertname + " " + iface,
                    "labels": {
                        "severity": "critical",
                        "interface": iface,
                    },
                    "annotations": {"description": alertname},
                }
                classification = classify_event(event)
                playbook = find_best_playbook(event, classification)
                self.assertIsNotNone(playbook)
                self.assertEqual(playbook.get("playbook_id"), "cisco_interface_packet_loss_or_discards_high")

                candidates = build_execution_candidates_from_playbook(playbook, event)
                self.assertTrue(candidates)
                self.assertTrue(all(x.get("readonly") for x in candidates))
                commands = " ".join(x.get("command", "") for x in candidates).lower()
                self.assertIn("counters errors", commands)

    def test_optical_and_packet_skills_are_loadable_by_family(self):
        for family in [
            "optical_power_abnormal",
            "interface_packet_loss_or_discards_high",
        ]:
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
