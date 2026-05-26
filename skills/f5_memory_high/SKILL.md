---
name: f5_memory_high
version: v6.3.0
family: f5_memory_high
description: F5 global memory and TMM memory high analysis skill.
risk_level: readonly
stage: v6.3
---

# f5_memory_high

## Scope

This Skill is generated from F5 Prometheus rule semantics.

Covered alert names:

- 全局内存利用率
- TMM内存利用率

## Investigation goal

确认 F5 host memory 或 TMM memory 是否仍高，并判断是否存在容量压力或异常增长。

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute modify, create, delete, save, load, reboot, restart, reset, bash or run util operations.

## Evidence expectation

The final review should clearly show:

- 内存类型
- 当前内存利用率
- TMM 内存
- Host 内存
- 是否持续高位
