---
name: device_cpu_high
version: v6.3.0
family: device_cpu_high
description: Cisco device CPU high analysis skill.
risk_level: readonly
stage: v6.3
---

# device_cpu_high

## Scope

This Skill is generated from Prometheus rule semantics and is used for Cisco resource or hardware alert analysis.

Covered alert names:

- 全局CPU利用率
- CPU利用率

## Investigation goal

Confirm whether CPU pressure is still active, whether a specific process dominates CPU, and whether the event is sustained or transient.

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute configuration, clearing, reload, delete, copy, commit or debug operations.

## Evidence expectation

The final review should clearly show:

- alert name and rule meaning
- device hostname and device IP
- readonly MCP commands executed
- current device evidence
- Prometheus window state when available
- whether the issue is still active, recovered, transient, or inconclusive
- next recommended action
