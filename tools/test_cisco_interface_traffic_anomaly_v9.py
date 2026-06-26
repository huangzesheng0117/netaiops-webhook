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


def check_yaml_json():
    targets = [
        Path("playbooks/cisco_interface_traffic_anomaly.yaml"),
        Path("playbooks/cisco_interface_or_link_traffic_drop.yaml"),
        Path("playbooks/interface_traffic_anomaly.yaml"),
        Path("skills/interface_traffic_anomaly/commands.yaml"),
        Path("skills/interface_traffic_anomaly/evidence_rules.yaml"),
        Path("skills/interface_traffic_anomaly/output_schema.json"),
        Path("config/prometheus_metrics.yaml"),
    ]

    for p in targets:
        if p.suffix == ".json":
            json.loads(p.read_text(encoding="utf-8"))
        else:
            yaml.safe_load(p.read_text(encoding="utf-8"))

    print("[OK] YAML/JSON syntax")


def check_playbook(alertname, expected_playbook_ids):
    event = {
        "vendor": "cisco",
        "platform": "nxos",
        "alarm_type": alertname,
        "alertname": alertname,
        "device_ip": "10.187.251.101",
        "hostname": "SH16-G03-DCI-BN-SW01",
        "interface": "Ethernet1/33",
        "ifName": "Ethernet1/33",
        "object_name": "Ethernet1/33",
        "direction": "in",
        "summary": alertname + " Ethernet1/33 入向流量异常",
        "labels": {
            "vendor": "cisco",
            "platform": "nxos",
            "device_ip": "10.187.251.101",
            "hostname": "SH16-G03-DCI-BN-SW01",
            "alertname": alertname,
            "interface": "Ethernet1/33",
            "ifName": "Ethernet1/33",
            "direction": "in",
        },
        "annotations": {
            "summary": alertname + " Ethernet1/33 入向流量异常"
        },
    }

    family = classify_family(event)
    print("[OK] family for", alertname, "=", family.get("family"), "source=", family.get("match_source"))

    pb = find_best_playbook(event, family)
    assert pb and pb.get("playbook_id") in expected_playbook_ids, pb
    print("[OK] matched_playbook=", pb.get("playbook_id"))

    candidates = build_execution_candidates_from_playbook(pb, event)
    assert len(candidates) <= 14, len(candidates)
    bad = [x.get("command") for x in candidates if not x.get("readonly", True)]
    assert not bad, bad
    print("[OK] command_count=", len(candidates), "readonly_all=True")

    commands_text = "\n".join(str(x.get("command")) for x in candidates)
    assert "show clock" in commands_text
    assert "show interface status" in commands_text or "show interfaces status" in commands_text
    assert "show policy-map interface" in commands_text
    print("[OK] command content sanity")


def check_prometheus_profile():
    data = yaml.safe_load(Path("config/prometheus_metrics.yaml").read_text(encoding="utf-8")) or {}
    profile = ((data.get("profiles") or {}).get("interface_traffic_anomaly") or {})
    queries = profile.get("queries") or {}
    for name in ["in_bps", "out_bps", "if_oper_status", "in_errors_delta", "out_discards_delta"]:
        assert name in queries, name
        assert queries[name].get("promql_candidates"), name
    print("[OK] prometheus profile interface_traffic_anomaly")


def check_formatter():
    sample = """NetAIOps分析结果-20260612-1430
设备：SH16-G03-DCI-BN-SW01（10.187.251.101）

告警内容：
骨干网流量突降 [全链路仿真-v9-Cisco-Traffic-Drop] Ethernet1/33 入向流量突降

分析过程：
1. 根据告警内容初步判断：Cisco 设备 Ethernet1/33 入向流量突降。
2. 已完成MCP只读取证：共执行 14 条只读命令，成功 13 条，具体内容为：show clock；show interface status；show interface Ethernet1/33；show running-config interface Ethernet1/33；show logging last 500 | include Ethernet1/33|ETHPORT|IF_DOWN|IF_UP；show interface counters errors；show interface Ethernet1/33 counters；show policy-map interface Ethernet1/33；show interface Ethernet1/33 transceiver details；show port-channel summary；show vpc brief；show interface trunk；show spanning-tree interface Ethernet1/33 detail。失败 1 条，具体内容为：show vlan brief。部分完成 0 条，具体内容为：无。
3. 取证事实：接口状态：Ethernet1/33 oper=up admin=up。
4. 综合执行结果判断：接口流量类只读取证完成。

Prometheus窗口证据：
- in_bps:
查询窗口：过去15分钟，step=60s，对比偏移=5分钟；
当前值：1000000.00 bps；对比值：9000000.00 bps；变化量：-8000000.00 bps；变化比例：-88.89%；窗口最大值：9000000.00 bps；窗口最小值：1000000.00 bps；窗口平均值：3000000.00 bps；趋势判断：明显下降
- out_bps:
查询窗口：过去15分钟，step=60s，对比偏移=5分钟；
当前值：2000000.00 bps；对比值：2100000.00 bps；变化量：-100000.00 bps；变化比例：-4.76%；趋势判断：基本持平

建议：
1. 优先核对 capability 与平台命令映射是否正确，并确认当前设备平台类型识别是否准确。
"""

    out = rewrite_interface_traffic_notification_text(sample)

    checks = {
        "has_meaning": "2. 告警含义分析：" in out,
        "has_command_overview": "3. 命令执行概况：" in out,
        "one_command_per_line": "具体如下：\nshow clock\nshow interface status\nshow interface Ethernet1/33" in out,
        "has_command_analysis": "4. 命令分析：" in out,
        "has_prometheus": "5. Prometheus窗口证据：" in out,
        "has_overall": "6. 综合执行结果判断：" in out,
        "removed_old_fact": "3. 取证事实：" not in out,
        "removed_internal_rec": "capability" not in out.lower(),
    }

    for k, v in checks.items():
        print(f"{k}={v}")

    assert all(checks.values()), out
    print("[OK] interface traffic notification formatter")


if __name__ == "__main__":
    check_yaml_json()
    check_playbook("骨干网流量突增", {"cisco_interface_traffic_anomaly", "interface_traffic_anomaly"})
    check_playbook("骨干网流量突降", {"cisco_interface_or_link_traffic_drop", "cisco_interface_traffic_anomaly", "interface_traffic_anomaly"})
    check_playbook("互联网流量突增", {"cisco_interface_traffic_anomaly", "interface_traffic_anomaly"})
    check_playbook("互联网流量突降", {"cisco_interface_or_link_traffic_drop", "cisco_interface_traffic_anomaly", "interface_traffic_anomaly"})
    check_playbook("接口/链路流量突降", {"cisco_interface_or_link_traffic_drop", "cisco_interface_traffic_anomaly", "interface_traffic_anomaly"})
    check_playbook("接口/链路流量突增/突降", {"cisco_interface_traffic_anomaly", "interface_traffic_anomaly"})
    check_prometheus_profile()
    check_formatter()
    print("[OK] v9 Cisco interface traffic anomaly offline validation passed")
