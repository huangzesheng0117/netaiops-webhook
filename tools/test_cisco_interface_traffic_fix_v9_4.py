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
from netaiops.interface_traffic_notification_formatter import rewrite_interface_traffic_notification_text
from netaiops.cli_result_status_normalizer import normalize_command_results


def event(alertname="骨干网流量突增"):
    return {
        "vendor": "cisco",
        "platform": "nxos",
        "alarm_type": alertname,
        "alertname": alertname,
        "device_ip": "10.187.251.101",
        "hostname": "SH16-G03-DCI-BN-SW01",
        "interface": "Ethernet1/33",
        "ifName": "Ethernet1/33",
        "object_name": "Ethernet1/33",
        "direction": "inbound",
        "traffic_change_type": "spike" if "突增" in alertname else "drop",
        "labels": {
            "vendor": "cisco",
            "platform": "nxos",
            "device_ip": "10.187.251.101",
            "hostname": "SH16-G03-DCI-BN-SW01",
            "alertname": alertname,
            "interface": "Ethernet1/33",
            "ifName": "Ethernet1/33",
            "object_name": "Ethernet1/33",
            "direction": "inbound",
        },
        "annotations": {
            "summary": f"{alertname} Ethernet1/33 入向流量异常"
        },
    }


def check_yaml():
    files = [
        "playbooks/cisco_interface_traffic_anomaly.yaml",
        "playbooks/cisco_interface_or_link_traffic_drop.yaml",
        "playbooks/interface_traffic_anomaly.yaml",
        "skills/interface_traffic_anomaly/commands.yaml",
    ]
    for f in files:
        yaml.safe_load(Path(f).read_text(encoding="utf-8"))
    print("[OK] yaml syntax")


def check_playbook_render():
    for alertname in ["骨干网流量突增", "骨干网流量突降", "互联网流量突增", "互联网流量突降"]:
        ev = event(alertname)
        fam = classify_family(ev)
        pb = find_best_playbook(ev, fam)
        assert pb, alertname
        candidates = build_execution_candidates_from_playbook(pb, ev)
        commands = [x.get("command") for x in candidates]

        assert len(commands) <= 14, commands
        assert all("{ interface }" not in c for c in commands), commands
        assert all("{{ interface }}" not in c for c in commands), commands
        assert all("show vpc brief" not in c for c in commands), commands
        assert any("Ethernet1/33" in c for c in commands), commands
        assert any(c == "show lacp neighbor" for c in commands), commands

        print("[OK]", alertname, "playbook=", pb.get("playbook_id"), "commands=", len(commands))
        for i, c in enumerate(commands, 1):
            print(f"  {i:02d}. {c}")


def check_normalizer():
    data = [
        {
            "order": 1,
            "command": "show interface Ethernet1/33",
            "dispatch_status": "completed",
            "output": "Ethernet1/33 is up",
            "error": "",
            "judge": {"hard_error": False},
        },
        {
            "order": 2,
            "command": "show interface { interface }",
            "dispatch_status": "completed",
            "output": "Invalid interface format at '^' marker.",
            "error": "",
            "judge": {"hard_error": False},
        },
    ]
    out = normalize_command_results(data)
    assert out[0]["dispatch_status"] == "completed"
    assert out[1]["dispatch_status"] == "failed"
    assert out[1]["judge"]["hard_error"] is True
    print("[OK] cli hard error normalizer")


def check_formatter():
    payload = {
        "request_id": "unit_test_req",
        "target": {"family": "interface_traffic_anomaly", "playbook_id": "cisco_interface_traffic_anomaly"},
        "target_scope": {
            "hostname": "SH16-G03-DCI-BN-SW01",
            "device_ip": "10.187.251.101",
            "interface": "Ethernet1/33",
            "direction": "inbound",
            "traffic_change_type": "spike",
        },
        "command_results": [
            {"command": "show clock", "dispatch_status": "completed", "output": "ok"},
            {"command": "show interface Ethernet1/33", "dispatch_status": "completed", "output": "Ethernet1/33 is up"},
            {"command": "show lacp neighbor", "dispatch_status": "completed", "output": "neighbor ok"},
            {"command": "show vlan brief", "dispatch_status": "failed", "output": "% Invalid command", "error": ""},
        ],
        "notify_view": {
            "device": "SH16-G03-DCI-BN-SW01（10.187.251.101）",
            "alarm_content": "骨干网流量突增 Ethernet1/33 入向",
            "prometheus_evidence_text": (
                "Prometheus窗口证据：\n"
                "- 状态：成功 5 项，失败/无数据 0 项\n"
                "- in_bps:\n"
                "查询窗口：过去15分钟，step=60s，对比偏移=5分钟；\n"
                "当前值：1.85 Gbps；对比值：1.18 Gbps；变化量：669.46 Mbps；变化比例：56.51%\n"
            ),
        },
    }

    original = (
        "设备：SH16-G03-DCI-BN-SW01（10.187.251.101）\n\n"
        "告警内容：\n骨干网流量突增 Ethernet1/33 入向\n\n"
        "分析过程：\n"
        "3. 命令执行概况：本次共执行 14 条只读命令，成功 12 条，具体如下：\n无\n"
        "5. Prometheus窗口证据：\n- 状态：未展示\n- 原因：本次通知未携带 Prometheus runtime sidecar 摘要，硬件历史趋势判断存在边界。\n"
        "\n建议：\n1. 优先核对 capability 与平台命令映射。"
    )

    out = rewrite_interface_traffic_notification_text(original, payload=payload)

    checks = {
        "has_command_show_clock": "show clock" in out,
        "has_command_interface": "show interface Ethernet1/33" in out,
        "failed_count_correct": "失败 1 条" in out,
        "failed_command_visible": "show vlan brief" in out,
        "prometheus_visible": "当前值：1.85 Gbps" in out and "对比值：1.18 Gbps" in out,
        "no_unshown": "未展示" not in out,
        "no_hardware_cross_text": "硬件历史趋势" not in out and "模块/板卡/主控" not in out,
        "no_internal_capability": "capability" not in out.lower(),
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
    print("[OK] formatter structured rebuild")


if __name__ == "__main__":
    check_yaml()
    check_playbook_render()
    check_normalizer()
    check_formatter()
    print("[OK] v9.4 Cisco interface traffic fix validation passed")
