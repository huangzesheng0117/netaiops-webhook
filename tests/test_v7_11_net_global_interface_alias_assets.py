import unittest

from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


VENDOR_CASES = [
    ("cisco", "nxos", "SW-CISCO-NXOS-CORE", "Ethernet1/1"),
    ("f5", "tmos", "LTM-F5", "1.1"),
    ("fortigate", "fortios", "FW-FORTIGATE-400", "port1"),
    ("h3c", "h3c", "SW-H3C-CORE", "Ten-GigabitEthernet1/0/1"),
]


PACKET_ALERTS = [
    "丢包率-入向",
    "丢包率-出向",
    "错包率-入向",
    "错包率-出向",
    "5m错包数-入向",
    "5m错包数-出向",
]

UTIL_ALERTS = [
    "利用率-入向",
    "利用率-出向",
]


class TestV711NetGlobalInterfaceAliasAssets(unittest.TestCase):
    def _event(self, alertname, vendor, platform, job, interface):
        return {
            "source": "alertmanager",
            "vendor": vendor,
            "platform": platform,
            "device_ip": "10.255.255.1",
            "hostname": "test-" + vendor,
            "alarm_type": alertname,
            "object_name": interface,
            "interface": interface,
            "raw_text": f"{alertname} {interface} net-global",
            "labels": {
                "alertname": alertname,
                "severity": "critical",
                "job": job,
                "vendor": vendor,
                "interface": interface,
                "ifName": interface,
            },
            "annotations": {"description": alertname},
        }

    def test_packet_loss_error_aliases_match_all_target_vendors(self):
        expected = {
            "cisco": "cisco_interface_packet_loss_or_discards_high",
            "f5": "f5_interface_packet_loss_or_discards_high",
            "fortigate": "fortigate_interface_packet_loss_or_discards_high",
            "h3c": "h3c_interface_packet_loss_or_discards_high",
        }

        for alertname in PACKET_ALERTS:
            for vendor, platform, job, interface in VENDOR_CASES:
                with self.subTest(alertname=alertname, vendor=vendor):
                    event = self._event(alertname, vendor, platform, job, interface)
                    classification = classify_event(event)
                    playbook = find_best_playbook(event, classification)
                    self.assertIsNotNone(playbook)
                    self.assertEqual(playbook.get("playbook_id"), expected[vendor])

                    candidates = build_execution_candidates_from_playbook(playbook, event)
                    self.assertTrue(candidates)
                    self.assertTrue(all(x.get("readonly") for x in candidates))

                    commands = " ".join(x.get("command", "") for x in candidates).lower()
                    if vendor == "cisco":
                        self.assertIn("counters errors", commands)
                    elif vendor == "f5":
                        self.assertIn("tmsh show net interface", commands)
                    elif vendor == "fortigate":
                        self.assertIn("get system interface physical", commands)
                    elif vendor == "h3c":
                        self.assertIn("display interface", commands)

    def test_utilization_aliases_match_all_target_vendors(self):
        expected = {
            "cisco": "cisco_interface_or_link_utilization_high",
            "f5": "f5_interface_or_link_utilization_high",
            "fortigate": "fortigate_interface_or_link_utilization_high",
            "h3c": "h3c_interface_or_link_utilization_high",
        }

        for alertname in UTIL_ALERTS:
            for vendor, platform, job, interface in VENDOR_CASES:
                with self.subTest(alertname=alertname, vendor=vendor):
                    event = self._event(alertname, vendor, platform, job, interface)
                    classification = classify_event(event)
                    playbook = find_best_playbook(event, classification)
                    self.assertIsNotNone(playbook)
                    self.assertEqual(playbook.get("playbook_id"), expected[vendor])

                    candidates = build_execution_candidates_from_playbook(playbook, event)
                    self.assertTrue(candidates)
                    self.assertTrue(all(x.get("readonly") for x in candidates))

    def test_existing_packet_and_utilization_skills_are_loadable(self):
        families = [
            "interface_packet_loss_or_discards_high",
            "interface_or_link_utilization_high",
        ]

        for family in families:
            with self.subTest(family=family):
                ctx = build_runtime_context_for_family(
                    family,
                    base_dir="/opt/netaiops-webhook",
                    levels=["metadata", "instructions", "commands", "evidence", "schema"],
                )
                self.assertTrue(ctx.get("matched"))
                self.assertIn("commands", ctx)
                self.assertIn("evidence", ctx)
                self.assertIn("schema", ctx)


if __name__ == "__main__":
    unittest.main()
