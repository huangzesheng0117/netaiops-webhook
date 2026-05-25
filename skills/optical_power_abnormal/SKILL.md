---
name: optical_power_abnormal
version: v6.3.0
family: optical_power_abnormal
description: Cisco optical power abnormal analysis skill for NX-OS and Catalyst transceiver Rx/Tx power alerts.
risk_level: readonly
stage: v6.3
---

# optical_power_abnormal

## Scope

This Skill is generated from Cisco Prometheus rule semantics and is used for optical module power alerts.

Covered alert names:

- NXOS光功率
- Catalyst光功率
- 光功率异常
- 光模块光功率异常

## Investigation goal

Confirm whether the optical module is present, whether Tx Power or Rx Power is abnormal, and whether the issue points to local transmitter, local receiver, remote transmitter, fiber path, ODF, jumper, or optical attenuation.

## Diagnosis focus

### Rx Power low

Focus on:

- remote Tx Power
- remote interface and remote transceiver
- fiber attenuation
- ODF and jumper quality
- connector contamination
- local receiver side

### Tx Power low

Focus on:

- local transceiver transmitter side
- local port health
- transceiver temperature and bias current
- remote Rx Power
- whether replacing local SFP or jumper is required

### Rx Power high or Tx Power high

Focus on:

- short fiber distance
- excessive remote transmit power
- whether optical attenuator is required
- receiver overload risk

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute configuration, clearing, reload, delete, copy, commit or debug operations.

## Evidence expectation

The final review should clearly show:

- alert name
- device hostname and device IP
- interface name
- transceiver present state
- module type and product ID when available
- Tx Power current value and thresholds
- Rx Power current value and thresholds
- Tx/Rx status: normal, low_warning, low_alarm, high_warning, high_alarm
- readonly MCP commands executed
- whether the issue is still active, recovered, transient, or inconclusive
- next recommended action
