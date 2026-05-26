#!/usr/bin/env python3
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netaiops.normalizers import normalize_alertmanager
from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


CASES = [
    ("全局CPU利用率", "cisco_device_cpu_high", "device_cpu_high", "show processes cpu", {"job": "SW-CISCO-NXOS-CORE"}),
    ("全局内存利用率", "cisco_device_memory_high", "device_memory_high", "show processes memory", {"job": "SW-CISCO-NXOS-CORE"}),
    ("磁盘利用率", "cisco_device_disk_high", "device_disk_high", "show file systems", {"job": "SW-CISCO-NXOS-CORE", "ciscoFlashDeviceName": "bootflash:"}),
    ("电源状态", "cisco_hardware_component_fault", "hardware_power_abnormal", "show environment power", {"job": "SW-CISCO-NXOS-CORE"}),
    ("风扇状态", "cisco_hardware_component_fault", "hardware_fan_abnormal", "show environment fan", {"job": "SW-CISCO-NXOS-CORE"}),
    ("非路由器温度", "cisco_temperature_high", "hardware_temperature_high", "show environment temperature", {"job": "SW-CISCO-NXOS-CORE", "entPhysicalName": "Temp Sensor 1"}),
    ("路由器温度", "cisco_temperature_high", "hardware_temperature_high", "show environment temperature", {"job": "SW-CISCO-RT", "entPhysicalName": "Temp Sensor 1"}),
    ("NXOS光功率", "cisco_optical_power_abnormal", "optical_power_abnormal", "transceiver", {"job": "SW-CISCO-NXOS-CORE", "interface": "Ethernet1/10", "ifName": "Ethernet1/10"}),
    ("Catalyst光功率", "cisco_optical_power_abnormal", "optical_power_abnormal", "transceiver", {"job": "SW-CISCO-CATALYST", "interface": "TenGigabitEthernet1/0/1", "ifName": "TenGigabitEthernet1/0/1"}),
    ("非ACI端口", "cisco_interface_down_or_oper_status", "interface_down_or_oper_status", "show interface ethernet1/1", {"job": "SW-CISCO-NXOS-CORE", "interface": "Ethernet1/1", "ifName": "Ethernet1/1"}),
    ("Leaf-Spine互联端口", "cisco_interface_down_or_oper_status", "interface_down_or_oper_status", "show interface ethernet1/53", {"job": "SW-CISCO-ACI-SL", "interface": "Ethernet1/53", "ifName": "Ethernet1/53"}),
    ("BorderLeaf端口", "cisco_interface_down_or_oper_status", "interface_down_or_oper_status", "show interface ethernet1/35", {"job": "SW-CISCO-ACI-BL", "interface": "Ethernet1/35", "ifName": "Ethernet1/35"}),
    ("Spine端口", "cisco_interface_down_or_oper_status", "interface_down_or_oper_status", "show interface ethernet1/1", {"job": "SW-CISCO-ACI-SPINE", "interface": "Ethernet1/1", "ifName": "Ethernet1/1"}),
    ("BGP邻居状态", "cisco_bgp_neighbor_down", "routing_neighbor_down", "show bgp", {"job": "SW-CISCO-NXOS-DCI-BN", "bgpPeerRemoteAddr": "192.0.2.1"}),
    ("OSPF邻居状态", "cisco_ospf_neighbor_down", "routing_neighbor_down", "show ip ospf", {"job": "SW-CISCO-NXOS-DCI-CORE", "ospfNbrIpAddr": "192.0.2.2"}),
    ("BFD邻居状态", "cisco_bfd_neighbor_down", "routing_neighbor_down", "show bfd", {"job": "SW-CISCO-NXOS-DCI-CORE", "ciscoBfdSessAddr": "192.0.2.3"}),
]


def build_payload(alertname, labels):
    labels = dict(labels or {})
    base_labels = {
        "alertname": alertname,
        "severity": "critical",
        "vendor": "cisco",
        "job": labels.get("job", "SW-CISCO-E2E-DRYRUN"),
        "instance": "test-cisco.example.local",
        "ip": "10.255.255.20",
    }
    base_labels.update(labels)

    return {
        "receiver": "netaiops-cisco-e2e-dryrun",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": base_labels,
                "annotations": {
                    "summary": alertname,
                    "description": f"{alertname} 端到端 dry-run 测试",
                },
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


def main() -> int:
    results = []
    failed = []

    for alertname, expected_playbook_id, expected_family, command_hint, labels in CASES:
        payload = build_payload(alertname, labels)
        events = normalize_alertmanager(payload)
        event = events[0] if events else {}

        classification = classify_event(event)
        playbook = find_best_playbook(event, classification)
        candidates = build_execution_candidates_from_playbook(playbook, event) if playbook else []
        commands = [x.get("command", "") for x in candidates]
        commands_joined = " ".join(commands).lower()

        skill_ctx = build_runtime_context_for_family(
            expected_family,
            base_dir="/opt/netaiops-webhook",
            levels=["metadata", "instructions", "commands", "evidence", "schema"],
        )

        ok = True
        reasons = []

        if event.get("alarm_type") != alertname:
            ok = False
            reasons.append("normalize_alertmanager alarm_type mismatch")

        if not playbook:
            ok = False
            reasons.append("playbook not matched")
        elif playbook.get("playbook_id") != expected_playbook_id:
            ok = False
            reasons.append(f"playbook mismatch: {playbook.get('playbook_id')} != {expected_playbook_id}")

        if not candidates:
            ok = False
            reasons.append("no execution candidates")

        if candidates and not all(x.get("readonly") for x in candidates):
            ok = False
            reasons.append("non-readonly command exists")

        if command_hint.lower() not in commands_joined:
            ok = False
            reasons.append(f"command hint not found: {command_hint}")

        if not skill_ctx.get("matched"):
            ok = False
            reasons.append("skill not matched")

        result = {
            "alertname": alertname,
            "expected_family": expected_family,
            "playbook_id": playbook.get("playbook_id") if playbook else None,
            "command_count": len(commands),
            "first_command": commands[0] if commands else "",
            "skill_matched": bool(skill_ctx.get("matched")),
            "ok": ok,
            "reasons": reasons,
        }
        results.append(result)

        if not ok:
            failed.append(result)

    print(json.dumps(
        {
            "status": "pass" if not failed else "failed",
            "case_count": len(results),
            "failed_count": len(failed),
            "results": results,
        },
        ensure_ascii=False,
        indent=2,
    ))

    return 0 if not failed else 2


if __name__ == "__main__":
    raise SystemExit(main())
