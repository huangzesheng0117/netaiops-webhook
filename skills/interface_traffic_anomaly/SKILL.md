---
name: interface_traffic_anomaly
version: v9.3.0-cisco-interface-traffic-anomaly
family: interface_traffic_anomaly
description: Cisco interface/link traffic spike and drop analysis skill for backbone and internet links.
risk_level: readonly
stage: v9
---

# interface_traffic_anomaly

## Scope

This Skill covers Cisco interface or link traffic spike/drop alerts, including:

- 骨干网流量突增
- 骨干网流量突降
- 互联网流量突增
- 互联网流量突降
- 接口/链路流量突降
- 接口/链路流量突增/突降

## Core principle

Do not immediately judge the event as "link abnormal" or "business abnormal".
First confirm whether the traffic change really happened, or whether it is caused by monitoring sampling, SNMP index change, counter clearing, interface flap, Port-channel member change, traffic hash redistribution, duplicate collection of Port-channel/member traffic, QoS drops, VLAN/STP/vPC path change, route/path change, or real business change.

## First judgement questions

1. Is the change inbound or outbound?
2. Is it traffic spike or traffic drop?
3. Is the target a physical port, Port-channel, SVI, sub-interface or Tunnel?
4. Is it only one interface or multiple links along the same service path?
5. Does CLI current rate match Prometheus historical/current rate?

## Prometheus evidence requirements

Prometheus MCP evidence is mandatory when available.

Default profile: `interface_traffic_anomaly`.

Minimum queries:

- in_bps
- out_bps
- if_oper_status
- in_errors_delta
- out_discards_delta

Prometheus evidence should compare current value, previous value, delta, ratio, max, min, average and trend in the lookback window.

## First CLI wave

For NX-OS/Nexus, no more than 14 readonly commands:

- show clock
- show interface status
- show interface <INTERFACE>
- show running-config interface <INTERFACE>
- show logging last 500 | include <INTERFACE>|ETHPORT|IF_DOWN|IF_UP|ERR|ERRDISABLE|UDLD|STP|SPANTREE|SFP|XCVR|TRANSCEIVER|LACP|VPC|QOS|DROP|flap
- show interface counters errors
- show interface <INTERFACE> counters
- show policy-map interface <INTERFACE>
- show interface <INTERFACE> transceiver details
- show port-channel summary
- show vpc brief
- show interface trunk
- show spanning-tree interface <INTERFACE> detail
- show vlan brief

For IOS/IOS-XE, use equivalent `show interfaces` commands.

## Decision paths

- Spike with no errors/drops: prefer real business increase or path shift into the link.
- Spike with output drops: prefer queue congestion, QoS drops or policing.
- Drop with interface flap: prefer physical link instability.
- Drop while interface remains up/up: prefer route/path shift, QoS policing, STP/vPC/Port-channel change or business source stop.
- Only Port-channel member changes: prefer hashing redistribution or member change.
- Broadcast/multicast spike: prefer L2 storm, multicast abnormality, unknown unicast flooding or loop.

## Forbidden actions

Never execute automatically:

- configure terminal / conf t
- shutdown / no shutdown
- clear counters / clear interface
- debug
- reload
- write memory / copy running-config startup-config
- SPAN configuration
- ACL configuration
- QoS policy modification
- interface reset or flap

## Notification format

Final notification must contain:

1. 根据告警内容初步判断
2. 告警含义分析
3. 命令执行概况
4. 命令分析
5. Prometheus窗口证据
6. 综合执行结果判断
7. 建议

Command lists must be one command per line.
