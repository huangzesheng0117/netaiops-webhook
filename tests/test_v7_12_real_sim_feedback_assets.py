import unittest
from pathlib import Path
import yaml

from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


ROOT = Path("/opt/netaiops-webhook")


class TestV712RealSimFeedbackAssets(unittest.TestCase):
    def _event(self, alertname, vendor, platform, job, interface="Ethernet1/1"):
        return {
            "source": "alertmanager",
            "vendor": vendor,
            "platform": platform,
            "device_ip": "10.255.255.1",
            "hostname": "test-" + vendor,
            "alarm_type": alertname,
            "object_name": interface,
            "interface": interface,
            "raw_text": f"{alertname} {vendor} {interface}",
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

    def test_up_alert_uses_vendor_specific_playbooks(self):
        cases = [
            ("cisco", "nxos", "SW-CISCO-NXOS-CORE", "cisco_device_reachability_down"),
            ("fortigate", "fortios", "FW-FORTIGATE-400", "fortigate_device_reachability_down"),
            ("f5", "tmos", "LTM-F5", "f5_device_reachability_down"),
            ("hillstone", "stoneos", "FW-HILLSTONE-V8-INT", "hillstone_device_reachability_down"),
        ]

        for vendor, platform, job, expected_playbook_id in cases:
            with self.subTest(vendor=vendor):
                event = self._event("up", vendor, platform, job)
                classification = classify_event(event)
                playbook = find_best_playbook(event, classification)
                self.assertIsNotNone(playbook)
                self.assertEqual(playbook.get("playbook_id"), expected_playbook_id)
                self.assertIn("reachability_precheck", playbook)
                self.assertTrue(playbook["reachability_precheck"]["stop_if_ping_failed"])
                self.assertTrue(playbook["reachability_precheck"]["stop_if_ssh_failed"])

                candidates = build_execution_candidates_from_playbook(playbook, event)
                self.assertTrue(candidates)
                self.assertTrue(all(x.get("readonly") for x in candidates))

    def test_vendor_specific_reachability_skills_load(self):
        families = [
            "cisco_device_reachability_down",
            "fortigate_device_reachability_down",
            "f5_device_reachability_down",
            "hillstone_device_reachability_down",
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

    def test_packet_error_playbook_requires_delayed_second_sample(self):
        p = ROOT / "playbooks/cisco_interface_packet_loss_or_discards_high.yaml"
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
        self.assertIn("delayed_second_sample", data)
        self.assertTrue(data["delayed_second_sample"]["enabled"])
        self.assertGreaterEqual(int(data["delayed_second_sample"]["delay_seconds"]), 120)

        skill_text = (ROOT / "skills/interface_packet_loss_or_discards_high/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("two-sample error-counter", skill_text)
        self.assertIn("still increasing", skill_text)

    def test_traffic_anomaly_prometheus_first_rules_exist(self):
        for rel in [
            "playbooks/cisco_interface_traffic_anomaly.yaml",
        ]:
            data = yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))
            self.assertIn("prometheus_evidence_first", data)
            self.assertTrue(data["prometheus_evidence_first"]["enabled"])

        drop_playbook = ROOT / "playbooks/cisco_interface_or_link_traffic_drop.yaml"
        if drop_playbook.exists():
            data = yaml.safe_load(drop_playbook.read_text(encoding="utf-8"))
            self.assertIn("prometheus_evidence_first", data)
            self.assertTrue(data["prometheus_evidence_first"]["enabled"])

        skill_text = (ROOT / "skills/interface_traffic_anomaly/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("Prometheus-first traffic anomaly", skill_text)
        self.assertIn("Query Prometheus first", skill_text)

    def test_latency_skill_prometheus_first_rule_exists(self):
        skill_text = (ROOT / "skills/internet_line_latency_high/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("Prometheus-first latency", skill_text)
        self.assertIn("query prometheus", skill_text.lower())


if __name__ == "__main__":
    unittest.main()
