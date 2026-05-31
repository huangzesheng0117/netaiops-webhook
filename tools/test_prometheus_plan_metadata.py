#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试 v8 Prometheus plan metadata hook。

只做本地 fake plan 测试，不生成真实告警 plan，不触发 Prometheus 查询。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netaiops.prometheus_plan_hooks import apply_prometheus_evidence_metadata_to_plan


TARGET_PLAYBOOKS = [
    "playbooks/cisco_interface_or_link_traffic_drop.yaml",
    "playbooks/cisco_interface_traffic_anomaly.yaml",
    "playbooks/cisco_interface_or_link_utilization_high.yaml",
    "playbooks/cisco_interface_packet_loss_or_discards_high.yaml",
]


def load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def build_fake_plan(playbook_path: str, with_interface: bool = True) -> dict:
    pb = load_yaml(ROOT / playbook_path)

    target_scope = {
        "vendor": "cisco",
        "platform": "nxos",
        "hostname": "DEMO-SW01",
        "device_ip": "10.1.1.1",
        "alarm_type": pb.get("name") or pb.get("playbook_id") or Path(playbook_path).stem,
    }

    if with_interface:
        target_scope.update({
            "interface": "Ethernet1/1",
            "if_name": "Ethernet1/1",
            "ifName": "Ethernet1/1",
            "object_name": "Ethernet1/1",
        })

    return {
        "request_id": "demo",
        "plan_id": "demo-plan",
        "target_scope": target_scope,
        "playbook": {
            "matched": True,
            "playbook_id": pb.get("playbook_id") or pb.get("name") or Path(playbook_path).stem,
            "playbook_file": playbook_path,
            "mode": "legacy_playbook",
        },
        "playbook_runtime": pb,
        "execution_source": "playbook",
    }


def main() -> int:
    print("========== Fake plan with interface ==========")
    for path in TARGET_PLAYBOOKS:
        print(f"\n--- {path} ---")
        if not (ROOT / path).exists():
            print("[MISSING]")
            continue

        plan = build_fake_plan(path, with_interface=True)
        patched = apply_prometheus_evidence_metadata_to_plan(plan)
        meta = patched.get("prometheus_evidence_first") or {}

        print("enabled =", meta.get("enabled"))
        print("status =", meta.get("status"))
        print("profile =", meta.get("evidence_profile"))
        print("query_names =", meta.get("query_names"))
        print("missing_required_labels =", meta.get("missing_required_labels"))
        print("runtime_stage =", meta.get("runtime_stage"))

    print("\n========== Fake plan without interface，用于验证缺失标签识别 ==========")
    plan = build_fake_plan("playbooks/cisco_interface_or_link_utilization_high.yaml", with_interface=False)
    patched = apply_prometheus_evidence_metadata_to_plan(plan)
    meta = patched.get("prometheus_evidence_first") or {}
    print(json.dumps({
        "enabled": meta.get("enabled"),
        "status": meta.get("status"),
        "profile": meta.get("evidence_profile"),
        "missing_required_labels": meta.get("missing_required_labels"),
        "target_context": meta.get("target_context"),
    }, ensure_ascii=False, indent=2))

    ok_count = 0
    for path in TARGET_PLAYBOOKS:
        if not (ROOT / path).exists():
            continue
        plan = build_fake_plan(path, with_interface=True)
        patched = apply_prometheus_evidence_metadata_to_plan(plan)
        meta = patched.get("prometheus_evidence_first") or {}
        if meta.get("enabled") is True and meta.get("status") == "metadata_ready":
            ok_count += 1

    print("\nmetadata_ready_count =", ok_count)

    if ok_count >= 4:
        print("[OK] Prometheus plan metadata hook POC 成功。")
        return 0

    print("[WARN] 存在 playbook 未达到 metadata_ready。")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
