#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import sys
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from netaiops.family_registry import classify_family
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.interface_utilization_notification_formatter import rewrite_interface_utilization_notification_text


def base_event():
    return {
        "vendor": "cisco",
        "platform": "iosxe",
        "alertname": "WG88互联网线路_电信_100M_利用率-出向",
        "alarm_type": "WG88互联网线路_电信_100M_利用率-出向",
        "device_ip": "10.189.250.8",
        "hostname": "WG404-H0304-C95-INT-ACC",
        "summary": "WG88互联网线路_电信_100M_利用率超过80%-出向",
        "labels": {
            "vendor": "cisco",
            "platform": "iosxe",
            "device_ip": "10.189.250.8",
            "hostname": "WG404-H0304-C95-INT-ACC",
            "alertname": "WG88互联网线路_电信_100M_利用率-出向"
        },
        "annotations": {
            "summary": "WG88互联网线路_电信_100M_利用率超过80%-出向",
            "description": "WG88互联网线路_电信_100M_利用率超过80%-出向"
        },
    }


def check_yaml_json():
    files = [
        "playbooks/cisco_interface_utilization_high.yaml",
        "playbooks/interface_or_link_utilization_high.yaml",
        "skills/interface_utilization_high/commands.yaml",
        "skills/interface_utilization_high/evidence_rules.yaml",
        "skills/interface_utilization_high/output_schema.json",
        "config/prometheus_metrics.yaml",
    ]
    for f in files:
        p = Path(f)
        if p.suffix == ".json":
            json.loads(p.read_text(encoding="utf-8"))
        else:
            yaml.safe_load(p.read_text(encoding="utf-8"))
    print("[OK] YAML/JSON syntax")


def check_family_and_commands():
    ev = base_event()
    fam = classify_family(ev)
    print("family=", fam)
    assert fam.get("family") == "interface_or_link_utilization_high"
    ts = fam.get("target_scope") or {}
    assert ts.get("interface_regex") == "Te1/0/1|Te2/0/1", ts
    assert str(ts.get("capacity_bps")) == "100000000", ts
    assert ts.get("direction") == "out", ts
    assert ts.get("interfaces") == ["Te1/0/1", "Te2/0/1"], ts

    pb = find_best_playbook(ev, fam)
    assert pb and pb.get("playbook_id") in ("cisco_interface_utilization_high", "interface_or_link_utilization_high", "cisco_interface_or_link_utilization_high"), pb
    print("playbook=", pb.get("playbook_id"))
    pef = pb.get("prometheus_evidence_first") or {}
    assert int((pb.get("execution") or {}).get("max_commands") or 0) == 30, pb
    assert pef.get("evidence_profile") == "interface_utilization_high", pef
    assert "out_util_percent" in (pef.get("query_names") or []), pef
    assert "in_util_percent" in (pef.get("query_names") or []), pef
    assert "show port-channel summary" not in "\n".join((pb.get("execution") or {}).get("commands") or []), pb

    candidates = build_execution_candidates_from_playbook(pb, ev)
    commands = [x.get("command") for x in candidates]
    print("command_count=", len(commands))
    for idx, cmd in enumerate(commands, 1):
        print(f"{idx:02d}. {cmd}")

    assert len(commands) <= 30
    assert all("{interface" not in c and "{{" not in c for c in commands)
    assert any("show interfaces Te1/0/1" == c for c in commands)
    assert any("show interfaces Te2/0/1" == c for c in commands)
    assert any("show logging | include Te1/0/1|Te2/0/1" in c for c in commands)
    assert any("show policy-map interface Te1/0/1" == c for c in commands)
    assert any("show policy-map interface Te2/0/1" == c for c in commands)
    print("[OK] family/playbook/commands")


def check_prometheus_profile():
    data = yaml.safe_load(Path("config/prometheus_metrics.yaml").read_text(encoding="utf-8")) or {}
    profile = ((data.get("profiles") or {}).get("interface_utilization_high") or {})
    queries = profile.get("queries") or {}
    for name in ["in_bps", "out_bps", "in_util_percent", "out_util_percent", "if_oper_status", "in_errors_delta", "out_discards_delta"]:
        assert name in queries, name
        assert queries[name].get("promql_candidates"), name

    out_util = "\n".join(queries["out_util_percent"]["promql_candidates"])
    assert "interface_regex" in out_util
    assert "capacity_bps" in out_util
    print("[OK] prometheus profile")


def check_formatter():
    payload = {
        "request_id": "unit_test_req_util",
        "target_scope": {
            "family": "interface_or_link_utilization_high",
            "hostname": "WG404-H0304-C95-INT-ACC",
            "device_ip": "10.189.250.8",
            "interfaces": ["Te1/0/1", "Te2/0/1"],
            "interface": "Te1/0/1|Te2/0/1",
            "interface_regex": "Te1/0/1|Te2/0/1",
            "direction": "out",
            "capacity_bps": "100000000",
            "link_name": "WG88互联网线路_电信_100M",
            "aggregate_circuit": True,
        },
        "command_results": [
            {"command": "show clock", "dispatch_status": "completed", "output": "ok"},
            {"command": "show interfaces Te1/0/1", "dispatch_status": "completed", "output": "ok"},
            {"command": "show interfaces Te2/0/1", "dispatch_status": "completed", "output": "ok"},
            {"command": "show policy-map interface Te1/0/1", "dispatch_status": "completed", "output": "no policy"},
        ],
        "notify_view": {
            "prometheus_evidence_text": (
                "Prometheus窗口证据：\n"
                "- 状态：成功 7 项，失败/无数据 0 项\n"
                "- out_bps:\n"
                "查询窗口：过去15分钟，step=60s，对比偏移=5分钟；\n"
                "当前值：86.00 Mbps；对比值：70.00 Mbps；变化量：16.00 Mbps；变化比例：22.86%\n"
                "- out_util_percent:\n"
                "当前值：86.00%；对比值：70.00%；窗口最大值：91.00%；窗口平均值：82.00%\n"
            )
        },
    }
    original = (
        "NetAIOps分析结果-20260615-1452\n"
        "设备：WG404-H0304-C95-INT-ACC（10.189.250.8）\n\n"
        "告警内容：\nWG88互联网线路_电信_100M_利用率-出向  WG88互联网线路_电信_100M_利用率超过80%-出向\n\n"
        "分析过程：\n旧文本"
    )
    out = rewrite_interface_utilization_notification_text(original, payload=payload)

    checks = {
        "not_spike_drop": "流量突增" not in out and "流量突降" not in out,
        "aggregate_visible": "Te1/0/1 + Te2/0/1" in out,
        "capacity_visible": "100M" in out,
        "direction_out": "告警方向为出向" in out,
        "commands_visible": "show interfaces Te1/0/1" in out and "show interfaces Te2/0/1" in out,
        "prom_visible": "out_util_percent" in out and "当前值：86.00%" in out,
        "no_prom_failure_wrong": "存在失败或无数据项" not in out,
        "has_all_sections": all(x in out for x in [
            "1. 根据告警内容初步判断",
            "2. 告警含义分析",
            "3. 命令执行概况",
            "4. 命令分析",
            "5. Prometheus窗口证据",
            "6. 综合执行结果判断",
            "建议",
        ]),
    }

    for k, v in checks.items():
        print(f"{k}={v}")
    assert all(checks.values()), out
    print("[OK] formatter")


if __name__ == "__main__":
    check_yaml_json()
    check_family_and_commands()
    check_prometheus_profile()
    check_formatter()
    print("[OK] v9 Cisco interface utilization high validation passed")
