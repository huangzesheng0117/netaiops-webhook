---
name: hillstone_memory_high
version: v6.3.0
family: hillstone_memory_high
description: Hillstone StoneOS memory utilization high analysis skill.
risk_level: readonly
stage: v6.3
---

# hillstone_memory_high

## Scope

This Skill is generated from Hillstone / StoneOS Prometheus rule semantics.

Covered alert names:

- 内存利用率
- 山石防火墙内存利用率
- Hillstone内存利用率

## Investigation goal

Confirm whether Hillstone memory utilization is still high, correlate resource state, session pressure and HA state, and determine whether the event is persistent, transient, capacity-related or traffic-driven.

## Runtime boundary

Only readonly tools are allowed.

## Evidence expectation

The final review should clearly show:

- 当前内存利用率
- Prometheus 窗口趋势
- 当前系统资源状态
- 当前 session 压力
- 是否伴随 HA 状态变化
- 是否仍处于高内存
- 建议下一步动作
