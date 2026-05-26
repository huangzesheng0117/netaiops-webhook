---
name: fortigate_connection_capacity_high
version: v6.3.0
family: fortigate_connection_capacity_high
description: FortiGate active and new TCP connection high analysis skill.
risk_level: readonly
stage: v6.3
---

# fortigate_connection_capacity_high

## Scope

This Skill is generated from FortiGate Prometheus rule semantics.

Covered alert names:

- 活动连接数
- 新建连接数(TCP)

## Investigation goal

Confirm whether FortiGate active sessions or new TCP connection rate are still high, and determine whether this is global capacity pressure, business traffic surge, abnormal traffic, short-lived spike, or HA/failover related.

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute config, edit, set, unset, delete, reboot, shutdown, factoryreset, kill, or debug-enable operations.

## Evidence expectation

The final review should clearly show:

- 当前活动连接数或新建连接数
- 设备名称和设备 IP
- 会话统计和系统性能状态
- 是否仍处于高位
- 是否可能为业务突增、异常流量或短时峰值
- 是否伴随 CPU / 内存 / HA 异常
- 建议下一步动作
