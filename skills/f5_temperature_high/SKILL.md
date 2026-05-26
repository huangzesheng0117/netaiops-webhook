---
name: f5_temperature_high
version: v6.3.0
family: f5_temperature_high
description: F5 CPU, chassis and blade temperature high analysis skill.
risk_level: readonly
stage: v6.3
---

# f5_temperature_high

## Scope

This Skill is generated from F5 Prometheus rule semantics.

Covered alert names:

- CPU温度
- 机框温度
- 机框板卡温度

## Investigation goal

确认 F5 温度是否仍超过阈值，并关联风扇、机框、板卡和机房环境。

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute modify, create, delete, save, load, reboot, restart, reset, bash or run util operations.

## Evidence expectation

The final review should clearly show:

- 温度传感器
- 当前温度
- 阈值
- 风扇状态
- 是否仍高温
- 是否存在硬件风险
