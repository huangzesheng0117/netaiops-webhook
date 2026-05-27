---
name: hillstone_ha_status_change
version: v6.3.0
family: hillstone_ha_status_change
description: Hillstone StoneOS HA active-standby status change analysis skill.
risk_level: readonly
stage: v6.3
---

# hillstone_ha_status_change

## Scope

This Skill is generated from Hillstone / StoneOS Prometheus rule semantics.

Covered alert names:

- 主备状态变化
- 山石防火墙主备状态变化
- Hillstone主备状态变化
- Hillstone HA状态变化

## Investigation goal

Confirm whether the Hillstone HA role changed, identify current master/backup state, HA group state, HA link state, HA traffic state and whether the event may affect business traffic.

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute configure, set, no, delete, clear, reboot, debug or other state-changing operations.

## Evidence expectation

The final review should clearly show:

- 当前主备角色
- HA cluster / group 状态
- HA link 状态
- HA traffic 状态
- SCM / module 主备状态
- 是否发生切换
- 是否需要检查对端、心跳链路或业务影响
