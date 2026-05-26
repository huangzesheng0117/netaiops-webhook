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
    ("主备状态变化", "f5_ha_status_change", "f5_ha_status_change", "tmsh show sys failover", {"job": "LTM-F5"}),
    ("全局CPU利用率", "f5_cpu_high", "f5_cpu_high", "tmsh show sys cpu", {"job": "LTM-F5"}),
    ("全局内存利用率", "f5_memory_high", "f5_memory_high", "tmsh show sys memory", {"job": "LTM-F5"}),
    ("磁盘利用率", "f5_disk_high", "f5_disk_high", "tmsh show sys disk", {"job": "LTM-F5"}),
    ("机框风扇状态", "f5_hardware_component_abnormal", "f5_hardware_component_abnormal", "tmsh show sys hardware", {"job": "LTM-F5"}),
    ("CPU温度", "f5_temperature_high", "f5_temperature_high", "tmsh show sys hardware", {"job": "LTM-F5"}),
    ("活动连接数", "f5_connection_capacity_high", "f5_connection_capacity_high", "tmsh show sys performance connections", {"job": "LTM-F5"}),
    ("新建HTTP请求数", "f5_http_request_rate_high", "f5_http_request_rate_high", "tmsh show ltm virtual", {"job": "LTM-F5"}),
    ("新建连接数(SSL)", "f5_ssl_connection_rate_high", "f5_ssl_connection_rate_high", "tmsh show ltm virtual", {"job": "LTM-F5"}),
    ("吞吐量-入向", "f5_throughput_high", "f5_throughput_high", "tmsh show sys performance throughput", {"job": "LTM-F5"}),
    ("收光功率", "f5_optical_power_abnormal", "f5_optical_power_abnormal", "tmsh show net interface", {"job": "LTM-F5", "name": "1.1", "sysSwitchDdmStatName": "1.1"}),
    ("f5端口状态", "f5_interface_status_abnormal", "f5_interface_status_abnormal", "tmsh show net interface", {"job": "LTM-F5", "name": "1.1", "ifName": "1.1"}),
    ("DNS请求率", "f5_dns_request_rate_high", "f5_dns_request_rate_high", "tmsh show gtm wideip", {"job": "DNS-F5"}),
    ("DNS解析率", "f5_dns_resolution_quality_low", "f5_dns_resolution_quality_low", "tmsh show gtm wideip", {"job": "DNS-F5"}),
    ("F5活跃连接数突增", "f5_connection_anomaly", "f5_connection_anomaly", "tmsh show sys performance connections", {"job": "LTM-F5"}),
    ("DNS每秒请求率突增", "f5_dns_rate_anomaly", "f5_dns_rate_anomaly", "tmsh show gtm wideip", {"job": "DNS-F5"}),
]


def build_payload(alertname, labels):
    labels = dict(labels or {})
    base_labels = {
        "alertname": alertname,
        "severity": "critical",
        "vendor": "f5",
        "job": labels.get("job", "F5-E2E-DRYRUN"),
        "instance": "test-f5.example.local",
        "ip": "10.255.255.10",
    }
    base_labels.update(labels)

    return {
        "receiver": "netaiops-e2e-dryrun",
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
                "generatorURL": "http://prometheus.example.local/graph?g0.expr=e2e_dryrun",
            }
        ],
        "commonLabels": {
            "alertname": alertname,
            "severity": "critical",
            "vendor": "f5",
        },
        "commonAnnotations": {
            "summary": alertname,
        },
        "externalURL": "http://alertmanager.example.local",
        "version": "4",
        "groupKey": f"e2e:{alertname}",
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
