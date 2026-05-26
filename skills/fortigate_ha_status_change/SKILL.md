---
name: fortigate_ha_status_change
version: v6.3.0
family: fortigate_ha_status_change
description: FortiGate HA role or active-standby state change analysis skill.
risk_level: readonly
stage: v6.3
---

# fortigate_ha_status_change

## Scope

This Skill is generated from FortiGate Prometheus rule semantics.

Covered alert names:

- 主备状态切换

## Investigation goal

确认 FortiGate 是否发生主备角色切换、当前主备角色、HA 健康状态、集群成员状态以及切换后是否存在业务风险。

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute config, edit, set, unset, delete, reboot, shutdown, factoryreset, kill, or debug-enable operations.

## Evidence expectation

The final review should clearly show:

- 当前主备角色
- HA 健康状态
- 集群成员状态
- 是否发生切换
- 是否需要检查对端和业务影响
