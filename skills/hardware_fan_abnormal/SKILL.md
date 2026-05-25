---
name: hardware_fan_abnormal
version: v6.3.0
family: hardware_fan_abnormal
description: Cisco fan abnormal analysis skill.
risk_level: readonly
stage: v6.3
---

# hardware_fan_abnormal

## Scope

This Skill is generated from Prometheus rule semantics and is used for Cisco resource or hardware alert analysis.

Covered alert names:

- 风扇状态

## Investigation goal

Confirm whether a fan module is failed, absent, speed abnormal, or accompanied by temperature issues.

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
