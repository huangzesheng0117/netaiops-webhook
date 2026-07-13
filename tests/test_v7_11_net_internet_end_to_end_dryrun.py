import json
import unittest
from datetime import datetime, timezone

from netaiops.normalizers import normalize_alertmanager
from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


NET_INTERNET_E2E_CASES = [
    # net-internet.yml utilization rules
    {
        "source_file": "net-internet.yml",
        "alertname": "SH8-GDS利用率-入向",
        "interface": "Te1/0/1",
        "device_ip": "10.192.251.95",
        "expected_playbook_id": "cisco_interface_or_link_utilization_high",
        "expected_family": "interface_or_link_utilization_high",
        "command_hint": "show interface",
    },
    {
        "source_file": "net-internet.yml",
        "alertname": "SH8-GDS利用率-出向",
        "interface": "Te1/0/1",
        "device_ip": "10.192.251.95",
        "expected_playbook_id": "cisco_interface_or_link_utilization_high",
        "expected_family": "interface_or_link_utilization_high",
        "command_hint": "show interface",
    },
    {
        "source_file": "net-internet.yml",
        "alertname": "SH8-CTC利用率-入向",
        "interface": "Te1/0/2",
        "device_ip": "10.192.251.95",
        "expected_playbook_id": "cisco_interface_or_link_utilization_high",
        "expected_family": "interface_or_link_utilization_high",
        "command_hint": "show interface",
    },
    {
        "source_file": "net-internet.yml",
        "alertname": "SH8-CTC利用率-出向",
        "interface": "Te1/0/2",
        "device_ip": "10.192.251.95",
        "expected_playbook_id": "cisco_interface_or_link_utilization_high",
        "expected_family": "interface_or_link_utilization_high",
        "command_hint": "show interface",
    },
    {
        "source_file": "net-internet.yml",
        "alertname": "SH16-GDS利用率-入向",
        "interface": "Te1/0/1",
        "device_ip": "10.187.251.95",
        "expected_playbook_id": "cisco_interface_or_link_utilization_high",
        "expected_family": "interface_or_link_utilization_high",
        "command_hint": "show interface",
    },
    {
        "source_file": "net-internet.yml",
        "alertname": "SH16-GDS利用率-出向",
        "interface": "Te1/0/1",
        "device_ip": "10.187.251.95",
        "expected_playbook_id": "cisco_interface_or_link_utilization_high",
        "expected_family": "interface_or_link_utilization_high",
        "command_hint": "show interface",
    },
    {
        "source_file": "net-internet.yml",
        "alertname": "SH16-CTC利用率-入向",
        "interface": "Te1/0/2",
        "device_ip": "10.187.251.95",
        "expected_playbook_id": "cisco_interface_or_link_utilization_high",
        "expected_family": "interface_or_link_utilization_high",
        "command_hint": "show interface",
    },
    {
        "source_file": "net-internet.yml",
        "alertname": "SH16-CTC利用率-出向",
        "interface": "Te1/0/2",
        "device_ip": "10.187.251.95",
        "expected_playbook_id": "cisco_interface_or_link_utilization_high",
        "expected_family": "interface_or_link_utilization_high",
        "command_hint": "show interface",
    },

    # net-internet.yml special rules
    {
        "source_file": "net-internet.yml",
        "alertname": "互联网线路延迟",
        "interface": "Te1/0/1",
        "device_ip": "10.192.251.95",
        "expected_playbook_id": "cisco_internet_line_latency_high",
        "expected_family": "internet_line_latency_high",
        "command_hint": "show ip sla statistics",
    },
    {
        "source_file": "net-internet.yml",
        "alertname": "互联网边界交换机-互联网线路端口down",
        "interface": "Te1/0/1",
        "device_ip": "10.192.251.95",
        "expected_playbook_id": "cisco_interface_down_or_oper_status",
        "expected_family": "interface_down_or_oper_status",
        "command_hint": "show interface",
    },
    {
        "source_file": "net-internet.yml",
        "alertname": "互联网线路流量突增",
        "interface": "Te1/0/1",
        "device_ip": "10.192.251.95",
        "expected_playbook_id": "cisco_interface_traffic_anomaly",
        "expected_family": "interface_traffic_anomaly",
        "command_hint": "show interface",
    },
    {
        "source_file": "net-internet.yml",
        "alertname": "互联网线路流量突降",
        "interface": "Te1/0/1",
        "device_ip": "10.192.251.95",
        "expected_playbook_id": "cisco_interface_or_link_traffic_drop",
        "expected_family": "interface_traffic_anomaly",
        "command_hint": "show interface",
    },

    # net-internet-wg88.yml utilization rules
    {
        "source_file": "net-internet-wg88.yml",
        "alertname": "WG88互联网线路_电信利用率-入向",
        "interface": "Te1/0/1",
        "device_ip": "10.189.250.8",
        "expected_playbook_id": "cisco_interface_or_link_utilization_high",
        "expected_family": "interface_or_link_utilization_high",
        "command_hint": "show interface",
    },
    {
        "source_file": "net-internet-wg88.yml",
        "alertname": "WG88互联网线路_电信_100M_利用率-出向",
        "interface": "Te1/0/1",
        "device_ip": "10.189.250.8",
        "expected_playbook_id": "cisco_interface_or_link_utilization_high",
        "expected_family": "interface_or_link_utilization_high",
        "command_hint": "show interface",
    },
    {
        "source_file": "net-internet-wg88.yml",
        "alertname": "WG88互联网线路_电信BGP_200M_利用率-入向",
        "interface": "Te1/0/2",
        "device_ip": "10.189.250.8",
        "expected_playbook_id": "cisco_interface_or_link_utilization_high",
        "expected_family": "interface_or_link_utilization_high",
        "command_hint": "show interface",
    },
    {
        "source_file": "net-internet-wg88.yml",
        "alertname": "WG88互联网线路_电信BGP_200M_利用率-出向",
        "interface": "Te1/0/2",
        "device_ip": "10.189.250.8",
        "expected_playbook_id": "cisco_interface_or_link_utilization_high",
        "expected_family": "interface_or_link_utilization_high",
        "command_hint": "show interface",
    },
]


def build_payload(case):
    alertname = case["alertname"]
    interface = case["interface"]
    device_ip = case["device_ip"]

    labels = {
        "alertname": alertname,
        "severity": "critical",
        "vendor": "cisco",
        "job": "SW-CISCO-CATALYST-INT",
        "instance": device_ip,
        "ip": device_ip,
        "interface": interface,
        "ifName": interface,
        "ifAlias": f"{alertname} {interface}",
        "sysName": "test-internet-edge",
    }

    return {
        "receiver": "netaiops-net-internet-e2e-dryrun",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": labels,
                "annotations": {
                    "summary": alertname,
                    "description": f"{alertname} {interface} {case['source_file']} 端到端 dry-run 测试",
                },
                "startsAt": datetime.now(timezone.utc).isoformat(),
                "endsAt": "0001-01-01T00:00:00Z",
                "generatorURL": "http://prometheus.example.local/graph?g0.expr=net_internet_e2e_dryrun",
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
        "groupKey": f"net-internet-e2e:{case['source_file']}:{alertname}",
    }


class TestV711NetInternetEndToEndDryrun(unittest.TestCase):
    def test_alertmanager_payload_to_playbook_and_skill_for_each_net_internet_alert(self):
        summary = []

        for case in NET_INTERNET_E2E_CASES:
            with self.subTest(source_file=case["source_file"], alertname=case["alertname"]):
                payload = build_payload(case)
                events = normalize_alertmanager(payload)
                self.assertEqual(len(events), 1)

                event = events[0]
                self.assertEqual(event.get("source"), "alertmanager")
                self.assertEqual(event.get("status"), "firing")
                self.assertEqual(event.get("vendor"), "cisco")
                self.assertEqual(event.get("alarm_type"), case["alertname"])

                event["platform"] = "iosxe"
                event["interface"] = case["interface"]
                event["object_name"] = case["interface"]

                classification = classify_event(event)
                self.assertIsInstance(classification, dict)

                playbook = find_best_playbook(event, classification)
                self.assertIsNotNone(playbook)
                self.assertEqual(playbook.get("playbook_id"), case["expected_playbook_id"])

                candidates = build_execution_candidates_from_playbook(playbook, event)
                self.assertTrue(candidates)
                self.assertTrue(all(x.get("readonly") for x in candidates))

                commands = [x.get("command", "") for x in candidates]
                commands_joined = " ".join(commands).lower()
                self.assertIn(case["command_hint"].lower(), commands_joined)

                skill_ctx = build_runtime_context_for_family(
                    case["expected_family"],
                    base_dir="/opt/netaiops-webhook",
                    levels=["metadata", "instructions", "commands", "evidence", "schema"],
                )
                self.assertTrue(skill_ctx.get("matched"))
                self.assertEqual(skill_ctx.get("family"), case["expected_family"])
                self.assertIn("commands", skill_ctx)
                self.assertIn("evidence", skill_ctx)
                self.assertIn("schema", skill_ctx)

                summary.append(
                    {
                        "source_file": case["source_file"],
                        "alertname": case["alertname"],
                        "family": case["expected_family"],
                        "playbook_id": playbook.get("playbook_id"),
                        "command_count": len(commands),
                        "first_command": commands[0] if commands else "",
                        "skill_matched": bool(skill_ctx.get("matched")),
                    }
                )

        print()
        print("===== NET_INTERNET_E2E_DRYRUN_SUMMARY =====")
        print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    unittest.main()
