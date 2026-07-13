import json
import unittest
from datetime import datetime, timezone

from netaiops.normalizers import normalize_alertmanager
from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


VENDOR_CASES = [
    {
        "vendor": "cisco",
        "platform": "nxos",
        "job": "SW-CISCO-NXOS-CORE",
        "device_ip": "10.255.255.20",
        "interface": "Ethernet1/1",
        "playbook_prefix": "cisco",
        "device_status_hint": "show version",
        "ping_hint": "show version",
        "duplex_hint": "show interface ethernet1/1",
        "packet_hint": "counters errors",
        "util_hint": "show interfaces ethernet1/1",
    },
    {
        "vendor": "f5",
        "platform": "tmos",
        "job": "LTM-F5",
        "device_ip": "10.255.255.10",
        "interface": "1.1",
        "playbook_prefix": "f5",
        "device_status_hint": "tmsh show sys version",
        "ping_hint": "tmsh show sys version",
        "duplex_hint": "tmsh show net interface",
        "packet_hint": "tmsh show net interface",
        "util_hint": "tmsh show net interface",
    },
    {
        "vendor": "fortigate",
        "platform": "fortios",
        "job": "FW-FORTIGATE-400",
        "device_ip": "10.255.255.30",
        "interface": "port1",
        "playbook_prefix": "fortigate",
        "device_status_hint": "get system status",
        "ping_hint": "get system status",
        "duplex_hint": "get system interface physical",
        "packet_hint": "get system interface physical",
        "util_hint": "get system interface physical",
    },
    {
        "vendor": "h3c",
        "platform": "h3c",
        "job": "SW-H3C-CORE",
        "device_ip": "10.255.255.40",
        "interface": "Ten-GigabitEthernet1/0/1",
        "playbook_prefix": "h3c",
        "device_status_hint": "display version",
        "ping_hint": "display version",
        "duplex_hint": "display interface",
        "packet_hint": "display interface",
        "util_hint": "display interface",
    },
]


ALERT_CASES = [
    {
        "alertname": "up",
        "family": "device_reachability_down",
        "playbook_suffix": "device_reachability_down",
        "hint_key": "device_status_hint",
    },
    {
        "alertname": "Ping",
        "family": "device_ping_abnormal",
        "playbook_suffix": "device_ping_abnormal",
        "hint_key": "ping_hint",
    },
    {
        "alertname": "双工模式",
        "family": "interface_duplex_mismatch",
        "playbook_suffix": "interface_duplex_mismatch",
        "hint_key": "duplex_hint",
    },
    {
        "alertname": "丢包率-入向",
        "family": "interface_packet_loss_or_discards_high",
        "playbook_suffix": "interface_packet_loss_or_discards_high",
        "hint_key": "packet_hint",
    },
    {
        "alertname": "丢包率-出向",
        "family": "interface_packet_loss_or_discards_high",
        "playbook_suffix": "interface_packet_loss_or_discards_high",
        "hint_key": "packet_hint",
    },
    {
        "alertname": "错包率-入向",
        "family": "interface_packet_loss_or_discards_high",
        "playbook_suffix": "interface_packet_loss_or_discards_high",
        "hint_key": "packet_hint",
    },
    {
        "alertname": "错包率-出向",
        "family": "interface_packet_loss_or_discards_high",
        "playbook_suffix": "interface_packet_loss_or_discards_high",
        "hint_key": "packet_hint",
    },
    {
        "alertname": "5m错包数-入向",
        "family": "interface_packet_loss_or_discards_high",
        "playbook_suffix": "interface_packet_loss_or_discards_high",
        "hint_key": "packet_hint",
    },
    {
        "alertname": "5m错包数-出向",
        "family": "interface_packet_loss_or_discards_high",
        "playbook_suffix": "interface_packet_loss_or_discards_high",
        "hint_key": "packet_hint",
    },
    {
        "alertname": "利用率-入向",
        "family": "interface_or_link_utilization_high",
        "playbook_suffix": "interface_or_link_utilization_high",
        "hint_key": "util_hint",
    },
    {
        "alertname": "利用率-出向",
        "family": "interface_or_link_utilization_high",
        "playbook_suffix": "interface_or_link_utilization_high",
        "hint_key": "util_hint",
    },
]


def build_payload(alertname, vendor_case):
    labels = {
        "alertname": alertname,
        "severity": "critical",
        "vendor": vendor_case["vendor"],
        "job": vendor_case["job"],
        "instance": vendor_case["device_ip"],
        "ip": vendor_case["device_ip"],
        "interface": vendor_case["interface"],
        "ifName": vendor_case["interface"],
    }

    return {
        "receiver": "netaiops-net-global-e2e-dryrun",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": labels,
                "annotations": {
                    "summary": alertname,
                    "description": f"{alertname} {vendor_case['interface']} net-global 端到端 dry-run 测试",
                },
                "startsAt": datetime.now(timezone.utc).isoformat(),
                "endsAt": "0001-01-01T00:00:00Z",
                "generatorURL": "http://prometheus.example.local/graph?g0.expr=net_global_e2e_dryrun",
            }
        ],
        "commonLabels": {
            "alertname": alertname,
            "severity": "critical",
            "vendor": vendor_case["vendor"],
        },
        "commonAnnotations": {
            "summary": alertname,
        },
        "externalURL": "http://alertmanager.example.local",
        "version": "4",
        "groupKey": f"net-global-e2e:{vendor_case['vendor']}:{alertname}",
    }


class TestV711NetGlobalEndToEndDryrun(unittest.TestCase):
    def test_alertmanager_payload_to_playbook_and_skill_for_each_net_global_alert(self):
        summary = []

        for vendor_case in VENDOR_CASES:
            for alert_case in ALERT_CASES:
                with self.subTest(vendor=vendor_case["vendor"], alertname=alert_case["alertname"]):
                    payload = build_payload(alert_case["alertname"], vendor_case)
                    events = normalize_alertmanager(payload)
                    self.assertEqual(len(events), 1)

                    event = events[0]
                    self.assertEqual(event.get("source"), "alertmanager")
                    self.assertEqual(event.get("status"), "firing")
                    self.assertEqual(event.get("vendor"), vendor_case["vendor"])
                    self.assertEqual(event.get("alarm_type"), alert_case["alertname"])

                    classification = classify_event(event)
                    self.assertIsInstance(classification, dict)

                    playbook = find_best_playbook(event, classification)
                    self.assertIsNotNone(playbook)

                    expected_playbook_id = f"{vendor_case['playbook_prefix']}_{alert_case['playbook_suffix']}"
                    self.assertEqual(playbook.get("playbook_id"), expected_playbook_id)

                    candidates = build_execution_candidates_from_playbook(playbook, event)
                    self.assertTrue(candidates)
                    self.assertTrue(all(x.get("readonly") for x in candidates))

                    commands = [x.get("command", "") for x in candidates]
                    commands_joined = " ".join(commands).lower()
                    self.assertIn(vendor_case[alert_case["hint_key"]].lower(), commands_joined)

                    skill_ctx = build_runtime_context_for_family(
                        alert_case["family"],
                        base_dir="/opt/netaiops-webhook",
                        levels=["metadata", "instructions", "commands", "evidence", "schema"],
                    )
                    self.assertTrue(skill_ctx.get("matched"))
                    self.assertIn("commands", skill_ctx)
                    self.assertIn("evidence", skill_ctx)
                    self.assertIn("schema", skill_ctx)

                    summary.append(
                        {
                            "vendor": vendor_case["vendor"],
                            "alertname": alert_case["alertname"],
                            "family": alert_case["family"],
                            "playbook_id": playbook.get("playbook_id"),
                            "command_count": len(commands),
                            "first_command": commands[0] if commands else "",
                            "skill_matched": bool(skill_ctx.get("matched")),
                        }
                    )

        print()
        print("===== NET_GLOBAL_E2E_DRYRUN_SUMMARY =====")
        print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    unittest.main()
