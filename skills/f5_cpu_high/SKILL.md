---
name: f5_cpu_high
version: v6.3.0
family: f5_cpu_high
description: F5 global, data-plane and control-plane CPU high analysis skill.
risk_level: readonly
stage: v6.3
---

# f5_cpu_high

## Scope

This Skill is generated from F5 Prometheus rule semantics.

Covered alert names:

- 全局CPU利用率
- 数据平面CPU利用率
- 控制平面CPU利用率

## Investigation goal

确认 F5 CPU 高是否仍在持续，并区分 host/control-plane 与 TMM/data-plane 压力。

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute modify, create, delete, save, load, reboot, restart, reset, bash or run util operations.

## Evidence expectation

The final review should clearly show:

- CPU 类型
- 当前 CPU
- 是否 TMM/data-plane 压力
- 是否 control-plane 压力
- 是否持续高位
