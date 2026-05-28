import json
import unittest
from datetime import datetime, timezone

from netaiops.normalizers import normalize_alertmanager
from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


NET_LINE_E2E_CASES = [
    {
        "alertname": "DCI专线利用率-入向",
        "interface": "Ethernet1/1",
        "expected_playbook_ids": ["cisco_interface_or_link_utilization_high"],
        "expected_families": ["interface_or_link_utilization_high"],
        "command_hint": "show interface",
    },
    {
        "alertname": "DCI专线利用率-出向",
        "interface": "Ethernet1/1",
        "expected_playbook_ids": ["cisco_interface_or_link_utilization_high"],
        "expected_families": ["interface_or_link_utilization_high"],
        "command_hint": "show interface",
    },
    {
        "alertname": "DCI专线延迟",
        "interface": "Ethernet1/1",
        "expected_playbook_ids": ["cisco_internet_line_latency_high"],
        "expected_families": ["internet_line_latency_high"],
        "command_hint": "show ip sla statistics",
    },
    {
        "alertname": "DCI线路流量突增",
        "interface": "Ethernet1/1",
        "expected_playbook_ids": ["cisco_interface_traffic_anomaly"],
        "expected_families": ["interface_traffic_anomaly"],
        "command_hint": "show interface",
    },
    {
        "alertname": "DCI线路流量突降",
        "interface": "Ethernet1/1",
        "expected_playbook_ids": [
            "cisco_interface_traffic_anomaly",
            "cisco_interface_or_link_traffic_drop",
        ],
        "expected_families": [
            "interface_traffic_anomaly",
            "interface_or_link_traffic_drop",
            "interface_or_link_traffic_anomaly",
        ],
        "command_hint": "show interface",
    },
]


def build_payload(case):
    alertname = case["alertname"]
    interface = case["interface"]
    device_ip = "10.255.255.60"

    return {
        "receiver": "netaiops-net-line-e2e-dryrun",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": alertname,
                    "severity": "critical",
                    "group": "netdev",
                    "vendor": "cisco",
                    "job": "SW-CISCO-NXOS-DCI-BN",
                    "instance": device_ip,
                    "ip": device_ip,
                    "interface": interface,
                    "ifName": interface,
                    "ifAlias": "DWDM-DCI-test-line",
                    "sysName": "test-dci-edge",
                },
                "annotations": {
                    "summary": alertname,
                    "description": f"test-dci-edge {alertname} {interface} net-line e2e dry-run",
                },
                "startsAt": datetime.now(timezone.utc).isoformat(),
                "endsAt": "0001-01-01T00:00:00Z",
                "generatorURL": "http://prometheus.example.local/graph?g0.expr=net_line_e2e_dryrun",
            }
        ],
        "commonLabels": {
            "alertname": alertname,
            "severity": "critical",
            "vendor": "cisco",
        },
        "commonAnnotations": {
            "summary": alertname,
        },
        "externalURL": "http://alertmanager.example.local",
        "version": "4",
        "groupKey": f"net-line-e2e:{alertname}",
    }


def load_any_skill(families):
    for family in families:
        ctx = build_runtime_context_for_family(
            family,
            base_dir="/opt/netaiops-webhook",
            levels=["metadata", "instructions", "commands", "evidence", "schema"],
        )
        if ctx.get("matched"):
            return family, ctx
    return None, {}


class TestV711NetLineEndToEndDryrun(unittest.TestCase):
    def test_alertmanager_payload_to_playbook_and_skill_for_each_net_line_alert(self):
        summary = []

        for case in NET_LINE_E2E_CASES:
            with self.subTest(alertname=case["alertname"]):
                payload = build_payload(case)
                events = normalize_alertmanager(payload)
                self.assertEqual(len(events), 1)

                event = events[0]
                event["vendor"] = "cisco"
                event["platform"] = "nxos"
                event["interface"] = case["interface"]
                event["object_name"] = case["interface"]

                self.assertEqual(event.get("source"), "alertmanager")
                self.assertEqual(event.get("status"), "firing")
                self.assertEqual(event.get("alarm_type"), case["alertname"])

                classification = classify_event(event)
                playbook = find_best_playbook(event, classification)
                self.assertIsNotNone(playbook)
                self.assertIn(playbook.get("playbook_id"), case["expected_playbook_ids"])

                candidates = build_execution_candidates_from_playbook(playbook, event)
                self.assertTrue(candidates)
                self.assertTrue(all(x.get("readonly") for x in candidates))

                commands = [x.get("command", "") for x in candidates]
                commands_joined = " ".join(commands).lower()
                self.assertIn(case["command_hint"].lower(), commands_joined)

                matched_family, skill_ctx = load_any_skill(case["expected_families"])
                self.assertIsNotNone(matched_family)
                self.assertTrue(skill_ctx.get("matched"))
                self.assertIn("commands", skill_ctx)
                self.assertIn("evidence", skill_ctx)
                self.assertIn("schema", skill_ctx)

                summary.append(
                    {
                        "alertname": case["alertname"],
                        "matched_family": matched_family,
                        "playbook_id": playbook.get("playbook_id"),
                        "command_count": len(commands),
                        "first_command": commands[0] if commands else "",
                        "skill_matched": bool(skill_ctx.get("matched")),
                    }
                )

        print()
        print("===== NET_LINE_E2E_DRYRUN_SUMMARY =====")
        print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    unittest.main()
