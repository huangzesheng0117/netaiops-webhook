---
name: f5_hardware_component_abnormal
version: v6.3.0
family: f5_hardware_component_abnormal
description: F5 chassis fan, power supply and blade status abnormal analysis skill.
risk_level: readonly
stage: v6.3
---

# f5_hardware_component_abnormal

## Scope

This Skill is generated from F5 Prometheus rule semantics.

Covered alert names:

- 机框风扇状态
- 机框电源状态
- 机框板卡状态

## Investigation goal

确认 F5 机框风扇、电源或板卡是否异常，并评估冗余和硬件风险。

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute modify, create, delete, save, load, reboot, restart, reset, bash or run util operations.

## Evidence expectation

The final review should clearly show:

- 异常部件类型
- 异常部件名称
- 当前状态
- 冗余是否下降
- 是否需要现场/厂商处理
