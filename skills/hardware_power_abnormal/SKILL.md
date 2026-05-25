---
name: hardware_power_abnormal
version: v6.3.0
family: hardware_power_abnormal
description: Cisco power supply abnormal analysis skill.
risk_level: readonly
stage: v6.3
---

# hardware_power_abnormal

## Scope

This Skill is generated from Prometheus rule semantics and is used for Cisco resource or hardware alert analysis.

Covered alert names:

- 电源状态

## Investigation goal

Confirm whether a power supply is failed, absent, input-lost, or reducing redundancy.

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
