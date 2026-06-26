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
from netaiops.family_evidence import build_family_evidence_summary
from netaiops.cisco_hardware_notification_formatter import rewrite_cisco_hardware_notification_text


def check_yaml_json():
    targets = [
        Path("playbooks/cisco_hardware_component_fault.yaml"),
        Path("skills/cisco_hardware_component_fault/commands.yaml"),
        Path("skills/cisco_hardware_component_fault/evidence_rules.yaml"),
        Path("skills/cisco_hardware_component_fault/output_schema.json"),
        Path("config/prometheus_metrics.yaml"),
    ]

    for p in targets:
        if p.suffix == ".json":
            json.loads(p.read_text(encoding="utf-8"))
        else:
            yaml.safe_load(p.read_text(encoding="utf-8"))

    print("[OK] YAML/JSON syntax")


def check_playbook():
    event = {
        "vendor": "cisco",
        "platform": "nxos",
        "alarm_type": "硬件部件故障",
        "alertname": "Cisco Hardware Component Fault",
        "device_ip": "10.187.251.101",
        "hostname": "SH16-G03-DCI-BN-SW01",
        "summary": "Cisco Hardware Component Fault fan power temperature module hardware fault simulation",
        "labels": {
            "vendor": "cisco",
            "platform": "nxos",
            "device_ip": "10.187.251.101",
            "hostname": "SH16-G03-DCI-BN-SW01",
            "alertname": "Cisco Hardware Component Fault",
        },
        "annotations": {
            "summary": "硬件部件故障，包含风扇/电源/温度/模块状态验证"
        },
    }

    family = classify_family(event)
    print("[OK] family=", family.get("family"), "source=", family.get("match_source"))

    pb = find_best_playbook(event, family)
    assert pb and pb.get("playbook_id") == "cisco_hardware_component_fault", pb
    print("[OK] matched_playbook=", pb.get("playbook_id"))

    candidates = build_execution_candidates_from_playbook(pb, event)
    assert len(candidates) == 14, len(candidates)
    blocked = [x["command"] for x in candidates if not x.get("readonly")]
    assert not blocked, blocked
    print("[OK] command_count=14 readonly_all=True")

    prom = pb.get("prometheus_evidence_first") or {}
    assert prom.get("enabled") is True
    assert prom.get("evidence_profile") == "cisco_hardware_health"
    assert prom.get("query_names") == ["device_up", "temperature_celsius", "fan_state", "power_state"]
    print("[OK] prometheus metadata ready")


def check_prometheus_profile():
    data = yaml.safe_load(Path("config/prometheus_metrics.yaml").read_text(encoding="utf-8")) or {}
    profile = ((data.get("profiles") or {}).get("cisco_hardware_health") or {})
    queries = profile.get("queries") or {}
    for name in ["device_up", "temperature_celsius", "fan_state", "power_state"]:
        assert name in queries, name
        assert queries[name].get("promql_candidates"), name
    print("[OK] prometheus profile cisco_hardware_health")


def check_evidence_summary():
    execution_data = {
        "family_result": {"family": "chassis_slot_or_module_abnormal"},
        "classification": {},
        "playbook": {"playbook_id": "cisco_hardware_component_fault"},
        "command_results": [
            {
                "command": "show environment power",
                "dispatch_status": "completed",
                "output": "Power supply 1 OK\nPower supply 2 failed",
                "judge": {"final_status": "completed", "hard_error": False},
            },
            {
                "command": "show environment temperature",
                "dispatch_status": "completed",
                "output": "Temperature Sensor 1 35 C Normal",
                "judge": {"final_status": "completed", "hard_error": False},
            },
        ],
    }
    summary = build_family_evidence_summary(execution_data)
    assert summary.get("has_facts") is True
    assert summary.get("notify_lines"), summary
    print("[OK] family evidence summary")


def check_formatter():
    sample = """设备：SH16-G03-DCI-BN-SW01（10.187.251.101）

告警内容：
Cisco Hardware Component Fault [全链路仿真-v9-Cisco-Hardware] 硬件部件故障，风扇/电源/温度检查

分析过程：
1. 根据告警内容初步判断：Cisco 设备 SH16-G03-DCI-BN-SW01 出现硬件部件故障。
2. 已完成MCP只读取证：共执行 14 条只读命令，成功 13 条，具体内容为：show clock；show version；show environment；show environment fan；show environment fan detail；show environment power；show environment power detail；show environment temperature；show module；show inventory；show system resources；show logging last 500 | include ENV|ENVMON|THERMAL；show system cores。失败 1 条，具体内容为：show diagnostic result module all。部分完成 0 条，具体内容为：无。
3. 取证事实：硬件/环境类取证：已执行 14 条只读命令。
4. 综合执行结果判断：硬件/环境类只读取证完成；建议结合异常关键字、Prometheus窗口指标和现场/厂商硬件状态继续确认。

Prometheus窗口证据：
- 状态：成功 2 项，失败/无数据 2 项
- device_up:
查询窗口：过去15分钟，step=60s，对比偏移=5分钟；
当前值：1.00 state；对比值：1.00 state；变化量：0.00 state；变化比例：0.00%；趋势判断：基本持平

建议：
1. 重点核查风扇模块状态、转速、是否缺失或故障；如持续异常，建议联系现场或厂商处理。
2. 优先核对 capability 与平台命令映射是否正确，并确认当前设备平台类型识别是否准确。
"""
    out = rewrite_cisco_hardware_notification_text(sample)

    checks = {
        "has_meaning": "2. 告警含义分析：" in out,
        "has_command_overview": "3. 命令执行概况：" in out,
        "one_command_per_line": "具体如下：\nshow clock\nshow version\nshow environment" in out,
        "has_command_analysis": "4. 命令分析：" in out,
        "has_prometheus": "5. Prometheus窗口证据：" in out,
        "has_overall": "6. 综合执行结果判断：" in out,
        "removed_old_fact": "3. 取证事实：" not in out,
        "removed_internal_rec": "capability" not in out.lower(),
    }

    for k, v in checks.items():
        print(f"{k}={v}")

    assert all(checks.values()), out
    print("[OK] hardware notification formatter")


if __name__ == "__main__":
    check_yaml_json()
    check_playbook()
    check_prometheus_profile()
    check_evidence_summary()
    check_formatter()
    print("[OK] v9 Cisco hardware component fault offline validation passed")
