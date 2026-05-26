---
name: fortigate_memory_high
version: v6.3.0
family: fortigate_memory_high
description: FortiGate memory utilization high analysis skill.
risk_level: readonly
stage: v6.3
---

# fortigate_memory_high

## Scope

This Skill is generated from FortiGate Prometheus rule semantics.

Covered alert names:

- 内存利用率

## Investigation goal

确认 FortiGate 内存是否仍处于高位，并判断是否存在 conserve mode 风险、进程异常占用或短时波动。

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute config, edit, set, unset, delete, reboot, shutdown, factoryreset, kill, or debug-enable operations.

## Evidence expectation

The final review should clearly show:

- 当前内存利用率
- 内存使用/剩余
- 是否存在 conserve mode 风险
- Top 进程
- 建议下一步动作
