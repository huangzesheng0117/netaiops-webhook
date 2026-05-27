---
name: hillstone_connection_capacity_high
version: v6.3.0
family: hillstone_connection_capacity_high
description: Hillstone StoneOS active and new TCP connection high analysis skill.
risk_level: readonly
stage: v6.3
---

# hillstone_connection_capacity_high

## Scope

This Skill is generated from Hillstone / StoneOS Prometheus rule semantics.

Covered alert names:

- 活动连接数
- 新建连接数(TCP)
- 山石防火墙活动连接数
- 山石防火墙新建连接数(TCP)
- Hillstone活动连接数
- Hillstone新建连接数(TCP)

## Investigation goal

Confirm whether Hillstone active sessions or new TCP connection rate are still high, correlate current session summary, system resource state, resource history and HA state, and determine whether the event is sustained capacity pressure, business traffic surge, abnormal traffic, failover-related or transient.

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute configure, set, no, delete, clear, reboot, debug or other state-changing operations.

## Evidence expectation

The final review should clearly show:

- 当前活动连接数或新建连接数
- 当前 session 概览
- 当前 CPU / 内存资源状态
- Prometheus 窗口趋势
- 是否伴随 HA 状态变化
- 是否仍处于连接数高位
- 是否可能为业务突增、异常流量或短时峰值
- 建议下一步动作
