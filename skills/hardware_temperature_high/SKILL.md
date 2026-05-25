---
name: hardware_temperature_high
version: v6.3.0
family: hardware_temperature_high
description: Cisco device temperature high analysis skill.
risk_level: readonly
stage: v6.3
---

# hardware_temperature_high

## Scope

This Skill is generated from Prometheus rule semantics and is used for Cisco resource or hardware alert analysis.

Covered alert names:

- 非路由器温度
- 路由器温度
- 温度异常

## Investigation goal

Confirm whether temperature is still above threshold and correlate fan, airflow, sensor and environment evidence.

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
