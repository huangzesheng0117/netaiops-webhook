import unittest
from pathlib import Path

import yaml

from netaiops.classifier import classify_event
from netaiops.family_registry import classify_family
from netaiops.plan_builder import build_plan_from_analysis_data
from netaiops.playbook_loader import (
    build_execution_candidates_from_playbook,
    find_best_playbook,
)


ROOT = Path("/opt/netaiops-webhook")
DCI_CASES = {
    "DCI线路流量突增": ("spike", "cisco_interface_traffic_anomaly"),
    "DCI线路流量突降": ("drop", "cisco_interface_or_link_traffic_drop"),
    "DCI专线流量突增": ("spike", "cisco_interface_traffic_anomaly"),
    "DCI专线流量突降": ("drop", "cisco_interface_or_link_traffic_drop"),
}


def build_event(alertname):
    return {
        "source": "alertmanager",
        "vendor": "cisco",
        "platform": "nxos",
        "device_ip": "192.0.2.40",
        "hostname": "SIM-DCI-SW01",
        "alarm_type": alertname,
        "interface": "Ethernet1/1",
        "object_name": "Ethernet1/1",
        "raw_text": f"{alertname} SIM-DCI-SW01 Ethernet1/1",
        "labels": {
            "alertname": alertname,
            "vendor": "cisco",
            "interface": "Ethernet1/1",
            "ifName": "Ethernet1/1",
            "severity": "critical",
        },
        "annotations": {"description": alertname},
    }


class TestV111DciTrafficPlaybookCoverage(unittest.TestCase):
    def test_dci_alerts_classify_as_traffic_anomaly(self):
        for alertname, (change_type, _) in DCI_CASES.items():
            with self.subTest(alertname=alertname):
                result = classify_family(build_event(alertname))
                self.assertEqual(result["family"], "interface_traffic_anomaly")
                self.assertEqual(result["match_source"], "v9_interface_traffic_anomaly_classifier")
                self.assertEqual(
                    result["target_scope"]["traffic_change_type"],
                    change_type,
                )

    def test_dci_alerts_select_explicit_playbooks(self):
        for alertname, (_, expected_playbook_id) in DCI_CASES.items():
            with self.subTest(alertname=alertname):
                event = build_event(alertname)
                playbook = find_best_playbook(event, classify_event(event))
                self.assertIsNotNone(playbook)
                self.assertEqual(playbook["playbook_id"], expected_playbook_id)
                self.assertEqual(playbook["family"], "interface_traffic_anomaly")

    def test_dci_playbook_candidates_are_readonly_and_bounded(self):
        for alertname in DCI_CASES:
            with self.subTest(alertname=alertname):
                event = build_event(alertname)
                playbook = find_best_playbook(event, classify_event(event))
                candidates = build_execution_candidates_from_playbook(playbook, event)
                self.assertTrue(candidates)
                self.assertLessEqual(len(candidates), 14)
                self.assertTrue(all(item["readonly"] for item in candidates))
                commands = " ".join(item["command"] for item in candidates).lower()
                self.assertIn("show interface ethernet1/1", commands)

    def test_dci_pipeline_uses_playbook_not_capability_registry(self):
        for alertname, (_, expected_playbook_id) in DCI_CASES.items():
            with self.subTest(alertname=alertname):
                event = build_event(alertname)
                analysis = {
                    "request_id": "v11-1-batch-d-dci",
                    "source": "alertmanager",
                    "analysis_status": "success",
                    "result": {
                        "summary": "offline DCI regression",
                        "recommended_next_step": "readonly diagnosis",
                        "confidence": "medium",
                    },
                    "event": event,
                }
                plan = build_plan_from_analysis_data(analysis)
                self.assertEqual(plan["execution_source"], "playbook")
                self.assertEqual(plan["playbook"]["playbook_id"], expected_playbook_id)
                self.assertTrue(plan["policy_result"]["auto_confirm_allowed"])
                self.assertTrue(plan["guard_result"]["all_readonly"])

    def test_both_traffic_playbooks_are_prometheus_first(self):
        for rel in (
            "playbooks/cisco_interface_traffic_anomaly.yaml",
            "playbooks/cisco_interface_or_link_traffic_drop.yaml",
        ):
            with self.subTest(rel=rel):
                data = yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))
                self.assertTrue(data["prometheus_evidence_first"]["enabled"])
                self.assertEqual(
                    data["prometheus_evidence_first"]["step_seconds"],
                    60,
                )
                self.assertEqual(data["family"], "interface_traffic_anomaly")

    def test_skill_documents_dci_scope_and_prometheus_first(self):
        text = (ROOT / "skills/interface_traffic_anomaly/SKILL.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("Prometheus-first traffic anomaly", text)
        self.assertIn("Query Prometheus first", text)
        for alertname in DCI_CASES:
            self.assertIn(alertname, text)

    def test_non_traffic_dci_alert_does_not_match_traffic_playbooks(self):
        event = build_event("DCI专线延迟")
        result = classify_family(event)
        self.assertNotEqual(result["family"], "interface_traffic_anomaly")
        playbook = find_best_playbook(event, classify_event(event))
        self.assertIsNotNone(playbook)
        self.assertNotIn(
            playbook["playbook_id"],
            {
                "cisco_interface_traffic_anomaly",
                "cisco_interface_or_link_traffic_drop",
            },
        )


if __name__ == "__main__":
    unittest.main()
