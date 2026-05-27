---
name: interface_duplex_mismatch
version: v6.3.0
family: interface_duplex_mismatch
description: Interface duplex mismatch analysis skill.
risk_level: readonly
stage: v6.3
---

# interface_duplex_mismatch

## Scope

This Skill is generated from net-global Prometheus rule semantics.

Covered alert names:

- 双工模式

## Investigation goal

Confirm whether an interface duplex mismatch is still present, identify interface speed/duplex negotiation state, correlate CRC/input errors and peer-side status, and determine whether it is auto-negotiation, forced speed/duplex mismatch, module/media issue, or stale monitoring data.

## Runtime boundary

Only readonly tools are allowed.

## Evidence expectation

The final review should clearly show:

- 设备名称和设备 IP
- 接口名称
- 当前 speed / duplex
- admin / oper 状态
- CRC / input errors / drops
- 是否仍存在双工不匹配
- 对端或物理层排查建议
