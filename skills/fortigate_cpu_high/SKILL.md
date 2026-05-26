---
name: fortigate_cpu_high
version: v6.3.0
family: fortigate_cpu_high
description: FortiGate average CPU or per-core CPU high analysis skill.
risk_level: readonly
stage: v6.3
---

# fortigate_cpu_high

## Scope

This Skill is generated from FortiGate Prometheus rule semantics.

Covered alert names:

- CPU平均利用率
- CPU单核利用率

## Investigation goal

确认 FortiGate CPU 是否仍处于高位，并区分平均 CPU、单核 CPU、进程占用和短时峰值。

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute config, edit, set, unset, delete, reboot, shutdown, factoryreset, kill, or debug-enable operations.

## Evidence expectation

The final review should clearly show:

- CPU 类型
- 当前 CPU 利用率
- Top 进程
- 是否仍高位
- 是否为短时峰值
- 建议下一步动作
