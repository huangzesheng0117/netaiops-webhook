---
name: f5_throughput_high
version: v6.3.0
family: f5_throughput_high
description: F5 inbound or outbound throughput high analysis skill.
risk_level: readonly
stage: v6.3
---

# f5_throughput_high

## Scope

This Skill is generated from F5 Prometheus rule semantics.

Covered alert names:

- 吞吐量-入向
- 吞吐量-出向

## Investigation goal

确认 F5 入向或出向吞吐量是否仍高，并识别是否集中在特定 virtual server、pool 或物理接口。

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute modify, create, delete, save, load, reboot, restart, reset, bash or run util operations.

## Evidence expectation

The final review should clearly show:

- 吞吐量方向
- 当前吞吐量
- Top interface / virtual server / pool
- 是否仍高位
- 建议下一步动作
