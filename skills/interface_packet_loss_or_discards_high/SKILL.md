---
name: interface_packet_loss_or_discards_high
version: v6.3.0
family: interface_packet_loss_or_discards_high
description: Cisco interface packet error, CRC, FCS, input error and discard analysis skill with delta recheck support.
risk_level: readonly
stage: v6.3
---

# interface_packet_loss_or_discards_high

## Scope

This Skill is generated from Cisco Prometheus rule semantics and is used for interface packet error or discard alerts.

Covered alert names:

- 5m错包数-入向
- 5m错包数-出向
- 端口CRC错包
- 接口错包
- 端口错包
- 接口错误包
- 接口丢包
- 端口丢包

## Investigation goal

Confirm whether interface error or discard counters are still increasing, determine whether the issue is physical-layer, queue/congestion, port-channel member related, peer-side related, or historical counter accumulation.

## Diagnosis focus

### CRC / FCS / input errors

Focus on:

- physical link quality
- optical module and fiber path
- remote port health
- ODF and jumper quality
- whether errors are still increasing

### Output drops / discards

Focus on:

- congestion
- microburst
- queue drops
- bandwidth utilization
- traffic pattern in Prometheus window

### Port-channel interface

Focus on:

- member interface state
- whether only one member is increasing errors
- LACP state
- peer port-channel state

### Delta recheck

This project has v7.9 interface error delta recheck. If a delta result exists, the final review should explain whether counters are still increasing, not increasing, or unknown.

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute configuration, clearing, reload, delete, copy, commit or debug operations.

## Evidence expectation

The final review should clearly show:

- alert name and direction
- device hostname and device IP
- interface name
- current input errors, CRC/FCS, output errors and drops
- whether the interface belongs to a port-channel
- transceiver or physical evidence when available
- v7.9 delta recheck status and counter delta when available
- whether the issue is still active, historical, transient, or inconclusive
- next recommended action
