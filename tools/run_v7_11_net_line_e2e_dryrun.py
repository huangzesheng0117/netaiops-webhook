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
    ("DCI专线利用率-入向", "Ethernet1/1", ["cisco_interface_or_link_utilization_high"], ["interface_or_link_utilization_high"], "show interface"),
    ("DCI专线利用率-出向", "Ethernet1/1", ["cisco_interface_or_link_utilization_high"], ["interface_or_link_utilization_high"], "show interface"),
    ("DCI专线延迟", "Ethernet1/1", ["cisco_internet_line_latency_high"], ["internet_line_latency_high"], "show ip sla statistics"),
    ("DCI线路流量突增", "Ethernet1/1", ["cisco_interface_traffic_anomaly"], ["interface_traffic_anomaly"], "show interface"),
    ("DCI线路流量突降", "Ethernet1/1", ["cisco_interface_traffic_anomaly", "cisco_interface_or_link_traffic_drop"], ["interface_traffic_anomaly", "interface_or_link_traffic_drop", "interface_or_link_traffic_anomaly"], "show interface"),
]


def build_payload(alertname, interface):
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


def main() -> int:
    results = []
    failed = []

    for alertname, interface, expected_playbook_ids, expected_families, command_hint in CASES:
        payload = build_payload(alertname, interface)
        events = normalize_alertmanager(payload)
        event = events[0] if events else {}

        event["vendor"] = "cisco"
        event["platform"] = "nxos"
        event["interface"] = interface
        event["object_name"] = interface

        classification = classify_event(event)
        playbook = find_best_playbook(event, classification)
        candidates = build_execution_candidates_from_playbook(playbook, event) if playbook else []
        commands = [x.get("command", "") for x in candidates]
        commands_joined = " ".join(commands).lower()

        matched_family, skill_ctx = load_any_skill(expected_families)

        ok = True
        reasons = []

        if event.get("alarm_type") != alertname:
            ok = False
            reasons.append("normalize_alertmanager alarm_type mismatch")

        if not playbook:
            ok = False
            reasons.append("playbook not matched")
        elif playbook.get("playbook_id") not in expected_playbook_ids:
            ok = False
            reasons.append(f"playbook mismatch: {playbook.get('playbook_id')} not in {expected_playbook_ids}")

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
            reasons.append(f"skill not matched: {expected_families}")

        result = {
            "alertname": alertname,
            "matched_family": matched_family,
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
