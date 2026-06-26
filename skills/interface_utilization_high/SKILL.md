---
name: interface_utilization_high
version: v9.5.0-cisco-interface-utilization-high
family: interface_or_link_utilization_high
description: Cisco interface/link utilization high analysis skill with single-interface and multi-interface aggregate circuit support.
risk_level: readonly
stage: v9
---

# interface_utilization_high

## Scope

This Skill covers Cisco interface/link utilization high alerts, including:

- 接口利用率高
- 链路利用率高
- 接口/链路利用率超过阈值
- 运营商线路利用率超过阈值
- 逻辑链路由多个物理接口聚合计算的利用率告警

## Important aggregate rule

Some alerts are not about a single physical interface.

For example:

- `WG88互联网线路_电信_100M_利用率超过80%-出向`
- Device: `WG404-H0304-C95-INT-ACC`
- Device IP: `10.189.250.8`
- Interfaces: `Te1/0/1` and `Te2/0/1`
- Capacity: `100M`
- Direction: outbound

For this case, the utilization is calculated by:

```text
sum(out_bps of Te1/0/1 and Te2/0/1) / 100000000 * 100
```

Do not judge by only one interface.

Both CLI evidence and Prometheus evidence must use all member interfaces.

## Investigation goal

Do not conclude solely from a utilization curve above 80%.

First confirm:

1. Whether utilization is real.
2. Whether it is sustained or only a short spike.
3. Whether the direction is inbound or outbound.
4. Whether the interface object is a physical port, Port-channel, logical circuit, SVI or multiple member interfaces.
5. Whether high utilization is accompanied by errors, drops, QoS drops, link flap, LACP/STP/VLAN changes or physical layer problems.
6. Whether monitoring and CLI agree.

## Prometheus evidence requirements

Prometheus evidence is mandatory when available.

For single interface:

- Query the interface's in_bps and out_bps.
- Query in_util_percent and out_util_percent if capacity is known or can be inferred.
- Query oper status, input errors and output discards.

For multi-interface aggregate circuit:

- Query `sum(ifHCInOctets)` and `sum(ifHCOutOctets)` across all member interfaces.
- Compute utilization percent against the alert logical capacity, not necessarily the physical port speed.
- For WG88电信100M, use `Te1/0/1|Te2/0/1` and `capacity_bps=100000000`.

## First wave CLI rules

The first wave is read-only and may run up to 30 commands for this alert family.

For a multi-interface alert, per-interface commands must be expanded for every member interface.

Typical IOS/IOS-XE first wave:

- show clock
- show ip interface brief
- show interfaces status
- show logging | include <INTERFACE_REGEX>|LINEPROTO|LINK|ERR|ERRDISABLE|UDLD|SPANTREE|STP|LACP|PAGP|QOS|POLICE|DROP|TRANSCEIVER|SFP|flap
- show interfaces counters errors
- show etherchannel summary
- show lacp neighbor
- show interfaces trunk
- show vlan brief
- show interfaces <INTERFACE>
- show running-config interface <INTERFACE>
- show interfaces <INTERFACE> counters
- show policy-map interface <INTERFACE>
- show interfaces <INTERFACE> transceiver detail
- show spanning-tree interface <INTERFACE> detail
- show mac address-table interface <INTERFACE>

## Core decision paths

### High utilization but no errors/drops

Prefer normal traffic peak, capacity pressure, path shift or backup/sync traffic.

### High utilization with output drops/discards

Prefer egress congestion, queue drops, QoS drops or policing.

### High utilization with CRC/FCS/input errors

Prefer physical link quality issue.

### High utilization on one Port-channel member

Prefer hash imbalance or member reduction.

### Monitoring high but CLI not high

Prefer monitoring issue:

- SNMP ifIndex changed
- sampling window too short
- Port-channel and member ports counted together
- counter reset
- interface mapping wrong
- wrong logical capacity

## Forbidden actions

Never execute automatically:

- configure terminal / conf t
- shutdown / no shutdown
- clear counters
- debug
- reload
- write memory
- ACL / QoS / SPAN configuration
- interface reset
