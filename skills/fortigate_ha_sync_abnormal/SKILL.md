---
name: fortigate_ha_sync_abnormal
version: v6.3.0
family: fortigate_ha_sync_abnormal
description: FortiGate HA configuration sync abnormal analysis skill.
risk_level: readonly
stage: v6.3
---

# fortigate_ha_sync_abnormal

## Scope

This Skill is generated from FortiGate Prometheus rule semantics.

Covered alert names:

- 同步状态

## Investigation goal

确认 FortiGate HA 配置同步是否异常、哪些成员 out-of-sync，以及是否存在配置完整性风险。

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute config, edit, set, unset, delete, reboot, shutdown, factoryreset, kill, or debug-enable operations.

## Evidence expectation

The final review should clearly show:

- HA 同步状态
- Configuration Status
- 是否存在 out-of-sync 成员
- checksum 是否一致
- 建议下一步动作
