import json
import unittest
from datetime import datetime, timezone

from netaiops.normalizers import normalize_alertmanager
from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


def build_payload(alertname, labels=None, annotations=None):
    labels = labels or {}
    annotations = annotations or {}

    base_labels = {
        "alertname": alertname,
        "severity": "critical",
        "vendor": "cisco",
        "job": labels.get("job", "SW-CISCO-E2E-DRYRUN"),
        "instance": labels.get("instance", "test-cisco.example.local"),
        "ip": labels.get("ip", "10.255.255.20"),
    }
    base_labels.update(labels)

    base_annotations = {
        "summary": alertname,
        "description": annotations.get("description", f"{alertname} 端到端 dry-run 测试"),
    }
    base_annotations.update(annotations)

    return {
        "receiver": "netaiops-cisco-e2e-dryrun",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": base_labels,
                "annotations": base_annotations,
                "startsAt": datetime.now(timezone.utc).isoformat(),
                "endsAt": "0001-01-01T00:00:00Z",
                "generatorURL": "http://prometheus.example.local/graph?g0.expr=cisco_e2e_dryrun",
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
        "groupKey": f"cisco-e2e:{alertname}",
    }


CISCO_E2E_CASES = [
    {
        "alertname": "全局CPU利用率",
        "expected_playbook_id": "cisco_device_cpu_high",
        "expected_family": "device_cpu_high",
        "command_hint": "show processes cpu",
        "labels": {"job": "SW-CISCO-NXOS-CORE"},
    },
    {
        "alertname": "全局内存利用率",
        "expected_playbook_id": "cisco_device_memory_high",
        "expected_family": "device_memory_high",
        "command_hint": "show processes memory",
        "labels": {"job": "SW-CISCO-NXOS-CORE"},
    },
    {
        "alertname": "磁盘利用率",
        "expected_playbook_id": "cisco_device_disk_high",
        "expected_family": "device_disk_high",
        "command_hint": "show file systems",
        "labels": {"job": "SW-CISCO-NXOS-CORE", "ciscoFlashDeviceName": "bootflash:"},
    },
    {
        "alertname": "电源状态",
        "expected_playbook_id": "cisco_hardware_component_fault",
        "expected_family": "hardware_power_abnormal",
        "command_hint": "show environment power",
        "labels": {"job": "SW-CISCO-NXOS-CORE"},
    },
    {
        "alertname": "风扇状态",
        "expected_playbook_id": "cisco_hardware_component_fault",
        "expected_family": "hardware_fan_abnormal",
        "command_hint": "show environment fan",
        "labels": {"job": "SW-CISCO-NXOS-CORE"},
    },
    {
        "alertname": "非路由器温度",
        "expected_playbook_id": "cisco_temperature_high",
        "expected_family": "hardware_temperature_high",
        "command_hint": "show environment temperature",
        "labels": {"job": "SW-CISCO-NXOS-CORE", "entPhysicalName": "Temp Sensor 1"},
    },
    {
        "alertname": "路由器温度",
        "expected_playbook_id": "cisco_temperature_high",
        "expected_family": "hardware_temperature_high",
        "command_hint": "show environment temperature",
        "labels": {"job": "SW-CISCO-RT", "entPhysicalName": "Temp Sensor 1"},
    },
    {
        "alertname": "NXOS光功率",
        "expected_playbook_id": "cisco_optical_power_abnormal",
        "expected_family": "optical_power_abnormal",
        "command_hint": "transceiver",
        "labels": {"job": "SW-CISCO-NXOS-CORE", "interface": "Ethernet1/10", "ifName": "Ethernet1/10"},
    },
    {
        "alertname": "Catalyst光功率",
        "expected_playbook_id": "cisco_optical_power_abnormal",
        "expected_family": "optical_power_abnormal",
        "command_hint": "transceiver",
        "labels": {"job": "SW-CISCO-CATALYST", "interface": "TenGigabitEthernet1/0/1", "ifName": "TenGigabitEthernet1/0/1"},
    },
    {
        "alertname": "非ACI端口",
        "expected_playbook_id": "cisco_interface_down_or_oper_status",
        "expected_family": "interface_down_or_oper_status",
        "command_hint": "show interface ethernet1/1",
        "labels": {"job": "SW-CISCO-NXOS-CORE", "interface": "Ethernet1/1", "ifName": "Ethernet1/1"},
    },
    {
        "alertname": "Leaf-Spine互联端口",
        "expected_playbook_id": "cisco_interface_down_or_oper_status",
        "expected_family": "interface_down_or_oper_status",
        "command_hint": "show interface ethernet1/53",
        "labels": {"job": "SW-CISCO-ACI-SL", "interface": "Ethernet1/53", "ifName": "Ethernet1/53"},
    },
    {
        "alertname": "BorderLeaf端口",
        "expected_playbook_id": "cisco_interface_down_or_oper_status",
        "expected_family": "interface_down_or_oper_status",
        "command_hint": "show interface ethernet1/35",
        "labels": {"job": "SW-CISCO-ACI-BL", "interface": "Ethernet1/35", "ifName": "Ethernet1/35"},
    },
    {
        "alertname": "Spine端口",
        "expected_playbook_id": "cisco_interface_down_or_oper_status",
        "expected_family": "interface_down_or_oper_status",
        "command_hint": "show interface ethernet1/1",
        "labels": {"job": "SW-CISCO-ACI-SPINE", "interface": "Ethernet1/1", "ifName": "Ethernet1/1"},
    },
    {
        "alertname": "BGP邻居状态",
        "expected_playbook_id": "cisco_bgp_neighbor_down",
        "expected_family": "routing_neighbor_down",
        "command_hint": "show bgp",
        "labels": {"job": "SW-CISCO-NXOS-DCI-BN", "bgpPeerRemoteAddr": "192.0.2.1"},
    },
    {
        "alertname": "OSPF邻居状态",
        "expected_playbook_id": "cisco_ospf_neighbor_down",
        "expected_family": "routing_neighbor_down",
        "command_hint": "show ip ospf",
        "labels": {"job": "SW-CISCO-NXOS-DCI-CORE", "ospfNbrIpAddr": "192.0.2.2"},
    },
    {
        "alertname": "BFD邻居状态",
        "expected_playbook_id": "cisco_bfd_neighbor_down",
        "expected_family": "routing_neighbor_down",
        "command_hint": "show bfd",
        "labels": {"job": "SW-CISCO-NXOS-DCI-CORE", "ciscoBfdSessAddr": "192.0.2.3"},
    },
]


class TestV711CiscoEndToEndDryrun(unittest.TestCase):
    def test_alertmanager_payload_to_playbook_and_skill_for_each_cisco_alert(self):
        summary = []

        for case in CISCO_E2E_CASES:
            with self.subTest(alertname=case["alertname"]):
                payload = build_payload(
                    case["alertname"],
                    labels=case.get("labels"),
                    annotations=case.get("annotations"),
                )

                events = normalize_alertmanager(payload)
                self.assertEqual(len(events), 1)

                event = events[0]
                self.assertEqual(event.get("source"), "alertmanager")
                self.assertEqual(event.get("status"), "firing")
                self.assertEqual(event.get("vendor"), "cisco")
                self.assertEqual(event.get("alarm_type"), case["alertname"])

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
                        "alertname": case["alertname"],
                        "family": case["expected_family"],
                        "playbook_id": playbook.get("playbook_id"),
                        "command_count": len(commands),
                        "first_command": commands[0] if commands else "",
                        "skill_matched": bool(skill_ctx.get("matched")),
                    }
                )

        print()
        print("===== CISCO_E2E_DRYRUN_SUMMARY =====")
        print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    unittest.main()
