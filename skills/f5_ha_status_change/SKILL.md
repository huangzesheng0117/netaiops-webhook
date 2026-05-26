---
name: f5_ha_status_change
version: v6.3.0
family: f5_ha_status_change
description: F5 HA failover or active-standby status change analysis skill.
risk_level: readonly
stage: v6.3
---

# f5_ha_status_change

## Scope

This Skill is generated from F5 Prometheus rule semantics.

Covered alert names:

- 主备状态变化
- F5主备状态变化
- F5 HA状态变化

## Investigation goal

确认 F5 是否发生主备切换、当前 active/standby 角色、traffic-group 归属、同步状态以及是否存在 HA 风险。

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute modify, create, delete, save, load, reboot, restart, reset, bash or run util operations.

## Evidence expectation

The final review should clearly show:

- 当前主备角色
- 同步状态
- traffic-group 状态
- 是否发生切换
- 是否需要检查对端或业务影响
