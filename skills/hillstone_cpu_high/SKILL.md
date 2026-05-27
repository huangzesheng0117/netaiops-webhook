---
name: hillstone_cpu_high
version: v6.3.0
family: hillstone_cpu_high
description: Hillstone StoneOS CPU utilization high analysis skill.
risk_level: readonly
stage: v6.3
---

# hillstone_cpu_high

## Scope

This Skill is generated from Hillstone / StoneOS Prometheus rule semantics.

Covered alert names:

- CPU利用率
- 山石防火墙CPU利用率
- Hillstone CPU利用率

## Investigation goal

Confirm whether Hillstone CPU utilization is still high, correlate resource status, session pressure and HA state, and determine whether the event is persistent, transient, business-traffic-driven or potentially abnormal.

## Runtime boundary

Only readonly tools are allowed.

## Evidence expectation

The final review should clearly show:

- 当前 CPU 利用率
- Prometheus 窗口趋势
- 当前系统资源状态
- 当前 session 压力
- 是否伴随 HA 状态变化
- 是否仍处于高 CPU
- 建议下一步动作
