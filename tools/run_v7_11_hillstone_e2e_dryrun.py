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
    ("主备状态变化", "hillstone_ha_status_change", "hillstone_ha_status_change", "show ha cluster"),
    ("CPU利用率", "hillstone_cpu_high", "hillstone_cpu_high", "show system resource"),
    ("内存利用率", "hillstone_memory_high", "hillstone_memory_high", "show system resource"),
    ("活动连接数", "hillstone_connection_capacity_high", "hillstone_connection_capacity_high", "show session generic"),
    ("新建连接数(TCP)", "hillstone_connection_capacity_high", "hillstone_connection_capacity_high", "show session generic"),
]


def build_payload(alertname):
    labels = {
        "alertname": alertname,
        "severity": "critical",
        "vendor": "hillstone",
        "job": "FW-HILLSTONE-V8-INT",
        "instance": "test-hillstone.example.local",
        "ip": "10.255.255.50",
    }

    return {
        "receiver": "netaiops-hillstone-e2e-dryrun",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": labels,
                "annotations": {
                    "summary": alertname,
                    "description": f"{alertname} net-hillstone 端到端 dry-run 测试",
                },
                "startsAt": datetime.now(timezone.utc).isoformat(),
                "endsAt": "0001-01-01T00:00:00Z",
                "generatorURL": "http://prometheus.example.local/graph?g0.expr=hillstone_e2e_dryrun",
            }
        ],
        "commonLabels": {
            "alertname": alertname,
            "severity": "critical",
            "vendor": "hillstone",
        },
        "commonAnnotations": {
            "summary": alertname,
        },
        "externalURL": "http://alertmanager.example.local",
        "version": "4",
        "groupKey": f"hillstone-e2e:{alertname}",
    }


def main() -> int:
    results = []
    failed = []

    for alertname, expected_playbook_id, expected_family, command_hint in CASES:
        payload = build_payload(alertname)
        events = normalize_alertmanager(payload)
        event = events[0] if events else {}
        event["platform"] = "stoneos"

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
