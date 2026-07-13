import unittest

from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


class TestV711NetInternetLatencyDownAnomalyAssets(unittest.TestCase):
    def _event(self, alertname, interface="Te1/0/1"):
        return {
            "source": "alertmanager",
            "vendor": "cisco",
            "platform": "iosxe",
            "device_ip": "10.192.251.95",
            "hostname": "test-internet-edge",
            "alarm_type": alertname,
            "object_name": interface,
            "interface": interface,
            "raw_text": f"{alertname} {interface} net-internet",
            "labels": {
                "alertname": alertname,
                "severity": "critical",
                "job": "SW-CISCO-CATALYST-INT",
                "vendor": "cisco",
                "interface": interface,
                "ifName": interface,
                "ifAlias": "internet-line-test",
            },
            "annotations": {"description": alertname},
        }

    def test_internet_latency_playbook_matches(self):
        event = self._event("互联网线路延迟")
        classification = classify_event(event)
        playbook = find_best_playbook(event, classification)
        self.assertIsNotNone(playbook)
        self.assertEqual(playbook.get("playbook_id"), "cisco_internet_line_latency_high")

        candidates = build_execution_candidates_from_playbook(playbook, event)
        self.assertTrue(candidates)
        self.assertTrue(all(x.get("readonly") for x in candidates))

        commands = " ".join(x.get("command", "") for x in candidates).lower()
        self.assertIn("show ip sla statistics", commands)
        self.assertIn("show interface te1/0/1", commands)

    def test_internet_port_down_alias_matches_existing_interface_status_playbook(self):
        event = self._event("互联网边界交换机-互联网线路端口down")
        classification = classify_event(event)
        playbook = find_best_playbook(event, classification)
        self.assertIsNotNone(playbook)
        self.assertEqual(playbook.get("playbook_id"), "cisco_interface_down_or_oper_status")

        candidates = build_execution_candidates_from_playbook(playbook, event)
        self.assertTrue(candidates)
        self.assertTrue(all(x.get("readonly") for x in candidates))

        commands = " ".join(x.get("command", "") for x in candidates).lower()
        self.assertIn("show interface te1/0/1", commands)

    def test_internet_traffic_anomaly_playbook_matches(self):
        cases = {
            "互联网线路流量突增": "cisco_interface_traffic_anomaly",
            "互联网线路流量突降": "cisco_interface_or_link_traffic_drop",
        }
        for alertname, expected_playbook_id in cases.items():
            with self.subTest(alertname=alertname):
                event = self._event(alertname)
                classification = classify_event(event)
                playbook = find_best_playbook(event, classification)
                self.assertIsNotNone(playbook)
                self.assertEqual(playbook.get("playbook_id"), expected_playbook_id)

                candidates = build_execution_candidates_from_playbook(playbook, event)
                self.assertTrue(candidates)
                self.assertTrue(all(x.get("readonly") for x in candidates))

                commands = " ".join(x.get("command", "") for x in candidates).lower()
                self.assertIn("show interface te1/0/1", commands)

    def test_new_internet_skills_are_loadable_by_family(self):
        for family in ["internet_line_latency_high", "interface_traffic_anomaly"]:
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
