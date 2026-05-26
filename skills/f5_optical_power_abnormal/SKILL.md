---
name: f5_optical_power_abnormal
version: v6.3.0
family: f5_optical_power_abnormal
description: F5 optical receive and transmit power abnormal analysis skill.
risk_level: readonly
stage: v6.3
---

# f5_optical_power_abnormal

## Scope

This Skill is generated from F5 Prometheus rule semantics.

Covered alert names:

- 收光功率
- 发光功率
- F5收光功率
- F5发光功率
- F5光功率异常

## Investigation goal

Confirm whether the F5 interface optical receive or transmit power is abnormal, identify the affected interface or optical module when available, and correlate device evidence with Prometheus DDM metrics.

## Diagnosis focus

### Receive optical power abnormal

Focus on:

- remote transmitter
- fiber attenuation
- ODF and jumper quality
- local receiver side
- connector contamination
- whether the abnormality is still visible in the Prometheus window

### Transmit optical power abnormal

Focus on:

- local transceiver transmitter side
- local interface hardware state
- remote receiver evidence
- transceiver or module status
- whether replacement or onsite check is required

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute modify, create, delete, save, load, reboot, restart, reset, bash or run util operations.

## Evidence expectation

The final review should clearly show:

- alert name and optical direction
- device hostname and device IP
- interface or DDM sensor name when available
- readonly MCP commands executed
- current optical evidence from device or Prometheus
- whether the issue is receive-power or transmit-power related
- whether the issue is still active, recovered, transient, or inconclusive
- recommended next action
