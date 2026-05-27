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
    ("net-internet.yml", "SH8-GDS利用率-入向", "Te1/0/1", "10.192.251.95", "cisco_interface_or_link_utilization_high", "interface_or_link_utilization_high", "show interface"),
    ("net-internet.yml", "SH8-GDS利用率-出向", "Te1/0/1", "10.192.251.95", "cisco_interface_or_link_utilization_high", "interface_or_link_utilization_high", "show interface"),
    ("net-internet.yml", "SH8-CTC利用率-入向", "Te1/0/2", "10.192.251.95", "cisco_interface_or_link_utilization_high", "interface_or_link_utilization_high", "show interface"),
    ("net-internet.yml", "SH8-CTC利用率-出向", "Te1/0/2", "10.192.251.95", "cisco_interface_or_link_utilization_high", "interface_or_link_utilization_high", "show interface"),
    ("net-internet.yml", "SH16-GDS利用率-入向", "Te1/0/1", "10.187.251.95", "cisco_interface_or_link_utilization_high", "interface_or_link_utilization_high", "show interface"),
    ("net-internet.yml", "SH16-GDS利用率-出向", "Te1/0/1", "10.187.251.95", "cisco_interface_or_link_utilization_high", "interface_or_link_utilization_high", "show interface"),
    ("net-internet.yml", "SH16-CTC利用率-入向", "Te1/0/2", "10.187.251.95", "cisco_interface_or_link_utilization_high", "interface_or_link_utilization_high", "show interface"),
    ("net-internet.yml", "SH16-CTC利用率-出向", "Te1/0/2", "10.187.251.95", "cisco_interface_or_link_utilization_high", "interface_or_link_utilization_high", "show interface"),
    ("net-internet.yml", "互联网线路延迟", "Te1/0/1", "10.192.251.95", "cisco_internet_line_latency_high", "internet_line_latency_high", "show ip sla statistics"),
    ("net-internet.yml", "互联网边界交换机-互联网线路端口down", "Te1/0/1", "10.192.251.95", "cisco_interface_down_or_oper_status", "interface_down_or_oper_status", "show interface"),
    ("net-internet.yml", "互联网线路流量突增", "Te1/0/1", "10.192.251.95", "cisco_interface_traffic_anomaly", "interface_traffic_anomaly", "show interface"),
    ("net-internet.yml", "互联网线路流量突降", "Te1/0/1", "10.192.251.95", "cisco_interface_traffic_anomaly", "interface_traffic_anomaly", "show interface"),
    ("net-internet-wg88.yml", "WG88互联网线路_电信利用率-入向", "Te1/0/1", "10.189.250.8", "cisco_interface_or_link_utilization_high", "interface_or_link_utilization_high", "show interface"),
    ("net-internet-wg88.yml", "WG88互联网线路_电信_100M_利用率-出向", "Te1/0/1", "10.189.250.8", "cisco_interface_or_link_utilization_high", "interface_or_link_utilization_high", "show interface"),
    ("net-internet-wg88.yml", "WG88互联网线路_电信BGP_200M_利用率-入向", "Te1/0/2", "10.189.250.8", "cisco_interface_or_link_utilization_high", "interface_or_link_utilization_high", "show interface"),
    ("net-internet-wg88.yml", "WG88互联网线路_电信BGP_200M_利用率-出向", "Te1/0/2", "10.189.250.8", "cisco_interface_or_link_utilization_high", "interface_or_link_utilization_high", "show interface"),
]


def build_payload(source_file, alertname, interface, device_ip):
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
                    "description": f"{alertname} {interface} {source_file} 端到端 dry-run 测试",
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
        "groupKey": f"net-internet-e2e:{source_file}:{alertname}",
    }


def main() -> int:
    results = []
    failed = []

    for source_file, alertname, interface, device_ip, expected_playbook_id, expected_family, command_hint in CASES:
        payload = build_payload(source_file, alertname, interface, device_ip)
        events = normalize_alertmanager(payload)
        event = events[0] if events else {}

        event["platform"] = "iosxe"
        event["interface"] = interface
        event["object_name"] = interface

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
            "source_file": source_file,
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
