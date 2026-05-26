import unittest

from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


class TestV711F5DnsAnomalyAssets(unittest.TestCase):
    def test_f5_dns_quality_and_rate_playbooks_match_net_f5_alertnames(self):
        cases = [
            ("DNS请求率", "f5_dns_request_rate_high", "tmsh show gtm wideip"),
            ("DNS解析率", "f5_dns_resolution_quality_low", "tmsh show gtm wideip"),
            ("DNS优选解析率", "f5_dns_resolution_quality_low", "tmsh show gtm wideip"),
            ("DNS每秒请求率突增", "f5_dns_rate_anomaly", "tmsh show gtm wideip"),
            ("DNS每秒请求率突降", "f5_dns_rate_anomaly", "tmsh show gtm wideip"),
            ("DNS每秒响应率突增", "f5_dns_rate_anomaly", "tmsh show gtm wideip"),
            ("DNS每秒响应率突降", "f5_dns_rate_anomaly", "tmsh show gtm wideip"),
        ]

        for alertname, expected_playbook_id, command_hint in cases:
            with self.subTest(alertname=alertname):
                event = {
                    "source": "alertmanager",
                    "vendor": "f5",
                    "platform": "tmos",
                    "device_ip": "10.0.0.10",
                    "hostname": "test-f5-dns",
                    "alarm_type": alertname,
                    "raw_text": alertname,
                    "labels": {"severity": "critical", "job": "DNS-F5"},
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

    def test_f5_connection_anomaly_playbook_matches_net_f5_alertnames(self):
        cases = [
            "F5活跃连接数突增",
            "F5活跃连接数突降",
            "F5新建连接数突增",
            "F5新建连接数突降",
        ]

        for alertname in cases:
            with self.subTest(alertname=alertname):
                event = {
                    "source": "alertmanager",
                    "vendor": "f5",
                    "platform": "tmos",
                    "device_ip": "10.0.0.10",
                    "hostname": "test-f5-ltm",
                    "alarm_type": alertname,
                    "raw_text": alertname,
                    "labels": {"severity": "critical", "job": "LTM-F5"},
                    "annotations": {"description": alertname},
                }
                classification = classify_event(event)
                playbook = find_best_playbook(event, classification)
                self.assertIsNotNone(playbook)
                self.assertEqual(playbook.get("playbook_id"), "f5_connection_anomaly")

                candidates = build_execution_candidates_from_playbook(playbook, event)
                self.assertTrue(candidates)
                self.assertTrue(all(x.get("readonly") for x in candidates))
                commands = " ".join(x.get("command", "") for x in candidates).lower()
                self.assertIn("tmsh show sys performance connections", commands)

    def test_f5_dns_and_anomaly_skills_are_loadable_by_family(self):
        families = [
            "f5_dns_request_rate_high",
            "f5_dns_resolution_quality_low",
            "f5_connection_anomaly",
            "f5_dns_rate_anomaly",
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
