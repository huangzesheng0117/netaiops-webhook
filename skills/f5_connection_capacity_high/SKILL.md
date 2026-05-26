---
name: f5_connection_capacity_high
version: v6.3.0
family: f5_connection_capacity_high
description: F5 active and new TCP connection capacity high analysis skill.
risk_level: readonly
stage: v6.3
---

# f5_connection_capacity_high

## Scope

This Skill is generated from F5 Prometheus rule semantics.

Covered alert names:

- 活动连接数
- 新建连接数(TCP)

## Investigation goal

确认 F5 当前连接数或新建 TCP 连接数是否仍处于高位，并判断是全局容量压力、业务突增、异常流量还是短时峰值。

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute modify, create, delete, save, load, reboot, restart, reset, bash or run util operations.

## Evidence expectation

The final review should clearly show:

- 当前连接数或新建连接数
- Top virtual server / pool
- 是否仍高位
- 是否可能为业务突增或异常流量
- 建议下一步动作
