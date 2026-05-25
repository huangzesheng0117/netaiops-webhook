---
name: device_disk_high
version: v6.3.0
family: device_disk_high
description: Cisco disk, flash or bootflash utilization high analysis skill.
risk_level: readonly
stage: v6.3
---

# device_disk_high

## Scope

This Skill is generated from Prometheus rule semantics and is used for Cisco resource or hardware alert analysis.

Covered alert names:

- 磁盘利用率
- Flash利用率
- 存储空间利用率

## Investigation goal

Confirm whether storage utilization is high and whether logs, core files, old images, or filesystem issues are involved.

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
