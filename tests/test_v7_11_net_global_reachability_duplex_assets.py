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


class TestV711NetGlobalReachabilityDuplexAssets(unittest.TestCase):
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

    def test_up_ping_duplex_playbooks_match_all_target_vendors(self):
        expected = {
            "up": {
                "cisco": "cisco_device_reachability_down",
                "f5": "f5_device_reachability_down",
                "fortigate": "fortigate_device_reachability_down",
                "h3c": "h3c_device_reachability_down",
            },
            "Ping": {
                "cisco": "cisco_device_ping_abnormal",
                "f5": "f5_device_ping_abnormal",
                "fortigate": "fortigate_device_ping_abnormal",
                "h3c": "h3c_device_ping_abnormal",
            },
            "双工模式": {
                "cisco": "cisco_interface_duplex_mismatch",
                "f5": "f5_interface_duplex_mismatch",
                "fortigate": "fortigate_interface_duplex_mismatch",
                "h3c": "h3c_interface_duplex_mismatch",
            },
        }

        for alertname, per_vendor in expected.items():
            for vendor, platform, job, interface in VENDOR_CASES:
                with self.subTest(alertname=alertname, vendor=vendor):
                    event = self._event(alertname, vendor, platform, job, interface)
                    classification = classify_event(event)
                    playbook = find_best_playbook(event, classification)
                    self.assertIsNotNone(playbook)
                    self.assertEqual(playbook.get("playbook_id"), per_vendor[vendor])

                    candidates = build_execution_candidates_from_playbook(playbook, event)
                    self.assertTrue(candidates)
                    self.assertTrue(all(x.get("readonly") for x in candidates))

    def test_net_global_new_skills_are_loadable_by_family(self):
        families = [
            "device_reachability_down",
            "device_ping_abnormal",
            "interface_duplex_mismatch",
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
