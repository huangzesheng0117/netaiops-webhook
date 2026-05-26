import unittest

from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


class TestV711F5TrafficCapacityAssets(unittest.TestCase):
    def test_f5_traffic_capacity_playbooks_match_net_f5_alertnames(self):
        cases = [
            ("活动连接数", "f5_connection_capacity_high", "tmsh show sys performance connections"),
            ("新建连接数(TCP)", "f5_connection_capacity_high", "tmsh show sys performance connections"),
            ("新建HTTP请求数", "f5_http_request_rate_high", "tmsh show ltm virtual"),
            ("新建连接数(SSL)", "f5_ssl_connection_rate_high", "tmsh show ltm virtual"),
            ("吞吐量-入向", "f5_throughput_high", "tmsh show sys performance throughput"),
            ("吞吐量-出向", "f5_throughput_high", "tmsh show sys performance throughput"),
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

    def test_f5_traffic_capacity_skills_are_loadable_by_family(self):
        families = [
            "f5_connection_capacity_high",
            "f5_http_request_rate_high",
            "f5_ssl_connection_rate_high",
            "f5_throughput_high",
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
