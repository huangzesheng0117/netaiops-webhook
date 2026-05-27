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


VENDOR_CASES = [
    ("cisco", "nxos", "SW-CISCO-NXOS-CORE", "10.255.255.20", "Ethernet1/1", "cisco", "show version", "show version", "show interface ethernet1/1", "counters errors", "show interface ethernet1/1"),
    ("f5", "tmos", "LTM-F5", "10.255.255.10", "1.1", "f5", "tmsh show sys version", "tmsh show sys version", "tmsh show net interface", "tmsh show net interface", "tmsh show net interface"),
    ("fortigate", "fortios", "FW-FORTIGATE-400", "10.255.255.30", "port1", "fortigate", "get system status", "get system status", "get system interface physical", "get system interface physical", "get system interface physical"),
    ("h3c", "h3c", "SW-H3C-CORE", "10.255.255.40", "Ten-GigabitEthernet1/0/1", "h3c", "display version", "display version", "display interface", "display interface", "display interface"),
]

ALERT_CASES = [
    ("up", "device_reachability_down", "device_reachability_down", 6),
    ("Ping", "device_ping_abnormal", "device_ping_abnormal", 7),
    ("双工模式", "interface_duplex_mismatch", "interface_duplex_mismatch", 8),
    ("丢包率-入向", "interface_packet_loss_or_discards_high", "interface_packet_loss_or_discards_high", 9),
    ("丢包率-出向", "interface_packet_loss_or_discards_high", "interface_packet_loss_or_discards_high", 9),
    ("错包率-入向", "interface_packet_loss_or_discards_high", "interface_packet_loss_or_discards_high", 9),
    ("错包率-出向", "interface_packet_loss_or_discards_high", "interface_packet_loss_or_discards_high", 9),
    ("5m错包数-入向", "interface_packet_loss_or_discards_high", "interface_packet_loss_or_discards_high", 9),
    ("5m错包数-出向", "interface_packet_loss_or_discards_high", "interface_packet_loss_or_discards_high", 9),
    ("利用率-入向", "interface_or_link_utilization_high", "interface_or_link_utilization_high", 10),
    ("利用率-出向", "interface_or_link_utilization_high", "interface_or_link_utilization_high", 10),
]


def build_payload(alertname, vendor, job, device_ip, interface):
    labels = {
        "alertname": alertname,
        "severity": "critical",
        "vendor": vendor,
        "job": job,
        "instance": device_ip,
        "ip": device_ip,
        "interface": interface,
        "ifName": interface,
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
                    "description": f"{alertname} {interface} net-global 端到端 dry-run 测试",
                },
                "startsAt": datetime.now(timezone.utc).isoformat(),
                "endsAt": "0001-01-01T00:00:00Z",
                "generatorURL": "http://prometheus.example.local/graph?g0.expr=net_global_e2e_dryrun",
            }
        ],
        "commonLabels": {
            "alertname": alertname,
            "severity": "critical",
            "vendor": vendor,
        },
        "commonAnnotations": {
            "summary": alertname,
        },
        "externalURL": "http://alertmanager.example.local",
        "version": "4",
        "groupKey": f"net-global-e2e:{vendor}:{alertname}",
    }


def main() -> int:
    results = []
    failed = []

    for vendor, platform, job, device_ip, interface, playbook_prefix, device_status_hint, ping_hint, duplex_hint, packet_hint, util_hint in VENDOR_CASES:
        hints = {
            6: device_status_hint,
            7: ping_hint,
            8: duplex_hint,
            9: packet_hint,
            10: util_hint,
        }

        for alertname, family, suffix, hint_key in ALERT_CASES:
            payload = build_payload(alertname, vendor, job, device_ip, interface)
            events = normalize_alertmanager(payload)
            event = events[0] if events else {}

            event["platform"] = platform
            event["interface"] = interface
            event["object_name"] = interface

            classification = classify_event(event)
            playbook = find_best_playbook(event, classification)
            candidates = build_execution_candidates_from_playbook(playbook, event) if playbook else []
            commands = [x.get("command", "") for x in candidates]
            commands_joined = " ".join(commands).lower()

            expected_playbook_id = f"{playbook_prefix}_{suffix}"
            command_hint = hints[hint_key]

            skill_ctx = build_runtime_context_for_family(
                family,
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
                "vendor": vendor,
                "alertname": alertname,
                "expected_family": family,
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
