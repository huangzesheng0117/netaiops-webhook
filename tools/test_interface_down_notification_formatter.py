#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from netaiops.interface_down_notification_formatter import rewrite_interface_down_notification_text


sample = """NetAIOps分析结果-20260610-1737
设备：SH16-G03-DCI-BN-SW01（10.187.251.101）

告警内容：
Cisco Interface Down [全链路仿真-v9-Cisco-Interface-Down] SH16-G03-DCI-BN-SW01 Ethernet1/33 接口状态异常/Down

分析过程：
1. 根据告警内容初步判断：Cisco NX-OS 设备 SH16-G03-DCI-BN-SW01 的 Ethernet1/33 接口状态变为 Down。
2. 已完成MCP只读取证：共执行 14 条只读命令，成功 13 条，具体内容为：show clock；show interface status；show interface Ethernet1/33；show running-config interface Ethernet1/33；show interface status err-disabled；show logging last 500 | include Ethernet1/33|ETHPORT|IF_DOWN|IF_UP|ERR|ERRDISABLE|UDLD|STP|SPANTREE|SFP|XCVR|TRANSCEIVER|LACP|VPC；show interface counters errors；show interface Ethernet1/33 transceiver details；show vlan brief；show interface trunk；show spanning-tree interface Ethernet1/33 detail；show port-channel summary；show module。失败 1 条，具体内容为：show vpc brief。部分完成 0 条，具体内容为：无。
3. 取证事实：接口状态：Ethernet1/33 oper=up admin=up
4. 综合执行结果判断：接口 状态类只读取证完成；接口状态 oper=未知 / admin=未知。建议结合接口状态、聚合关系、对端端口和日志时间线判断是否存在链路抖动、模块异常或链路切换。

Prometheus窗口证据：
- 状态：成功 3 项，失败/无数据 1 项
- oper_status:
查询窗口：过去15分钟，step=60s，对比偏移=5分钟；
当前值：1.00 status；对比值：1.00 status；变化量：0.00 status；变化比例：0.00%；窗口最大值：1.00 status；窗口最小值：1.00 status；窗口平均值：1.00 status；趋势判断：基本持平

建议：
1. 核查接口当前 oper/admin 状态是否与告警状态一致。
2. 结合接口日志时间线确认是否存在链路 up/down、flap、模块异常或对端切换。
3. 优先核对 capability 与平台命令映射是否正确，并确认当前设备平台类型识别是否准确。
"""

out = rewrite_interface_down_notification_text(sample)

checks = {
    "has_alarm_meaning": "2. 告警含义分析：" in out,
    "has_command_overview": "3. 命令执行概况：" in out,
    "commands_one_per_line": "具体如下：\nshow clock\nshow interface status\nshow interface Ethernet1/33" in out,
    "has_command_analysis": "4. 命令分析：" in out,
    "has_numbered_prometheus": "5. Prometheus窗口证据：" in out,
    "has_overall": "6. 综合执行结果判断：" in out,
    "removed_old_fact": "3. 取证事实：" not in out,
    "removed_internal_recommendation": "capability" not in out.lower(),
}

for k, v in checks.items():
    print(f"{k}={v}")

if not all(checks.values()):
    print("\n===== rewritten text =====")
    print(out)
    raise SystemExit(1)

print("\n[OK] interface down notification formatter test passed")
print("\n===== preview =====")
print(out)
