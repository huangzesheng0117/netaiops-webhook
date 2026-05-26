---
name: f5_interface_status_abnormal
version: v6.3.0
family: f5_interface_status_abnormal
description: F5 interface operational status abnormal analysis skill.
risk_level: readonly
stage: v6.3
---

# f5_interface_status_abnormal

## Scope

This Skill is generated from F5 Prometheus rule semantics.

Covered alert names:

- f5端口状态
- F5端口状态
- F5接口状态
- 端口状态
- 接口状态

## Investigation goal

Confirm whether the F5 interface is still down or abnormal, determine whether it is a physical interface, VLAN, trunk member or management interface, and correlate device evidence with Prometheus ifOperStatus.

## Diagnosis focus

Focus on:

- interface operational status
- physical interface or trunk relation
- VLAN dependency
- management interface exception
- whether the interface is intentionally unused
- whether the status has recovered since alert time

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute modify, create, delete, save, load, reboot, restart, reset, bash or run util operations.

## Evidence expectation

The final review should clearly show:

- alert name and interface class
- device hostname and device IP
- interface name when available
- readonly MCP commands executed
- current interface status
- trunk or VLAN relationship when available
- whether the issue is still active, recovered, transient, or inconclusive
- recommended next action
