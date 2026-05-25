---
name: interface_down_or_oper_status
version: v6.3.0
family: interface_down_or_oper_status
description: Cisco interface operational status analysis skill for physical, uplink, spine, border leaf and ACI-related port status alerts.
risk_level: readonly
stage: v6.3
---

# interface_down_or_oper_status

## Scope

This Skill is generated from Cisco Prometheus rule semantics and is used for interface or port operational status alerts.

Covered alert names:

- 非ACI端口状态
- Leaf-Spine互联端口状态
- BorderLeaf端口状态
- Spine端口状态
- 接口状态异常
- 端口状态异常

## Investigation goal

Confirm whether the interface is still down or abnormal, identify whether the affected port is a physical link or a port-channel member, and correlate device CLI evidence with Prometheus alert windows and recent interface logs.

## Alert class notes

### 非ACI端口状态

Focus on the single interface state, admin/oper status, link flap history, optical transceiver state and physical counters.

### Leaf-Spine互联端口状态

Focus on fabric-facing link impact, both ends of the uplink, transceiver evidence, and whether multiple fabric links are affected.

### BorderLeaf端口状态

Focus on border connectivity risk, external L3Out or upstream dependency, port-channel relation and recent link state changes.

### Spine端口状态

Focus on fabric core link impact, whether the port belongs to a fabric bundle, and whether multiple down events exist in the same window.

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute configuration, clearing, reload, delete, copy, commit or debug operations.

## Evidence expectation

The final review should clearly show:

- alert name and interface class
- device hostname and device IP
- interface name
- admin status and operational status
- port-channel or member relation when available
- transceiver or physical layer evidence when available
- input/output errors and drops when available
- recent link up/down or flap logs
- Prometheus window state when available
- whether the issue is still active, recovered, transient, or inconclusive
- next recommended action
