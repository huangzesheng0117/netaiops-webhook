---
name: interface_traffic_anomaly
version: v6.3.0
family: interface_traffic_anomaly
description: Interface or internet line traffic spike/drop analysis skill.
risk_level: readonly
stage: v6.3
---

# interface_traffic_anomaly

## Scope

This Skill is generated from net-internet Prometheus rule semantics.

Covered alert names:

- 互联网线路流量突增
- 互联网线路流量突降
- 互联网链路流量突增
- 互联网链路流量突降

## Investigation goal

Confirm whether interface traffic spike or drop is still visible, compare current traffic with previous baseline, correlate interface rate, errors, port-channel state and logs, and determine whether the change is business traffic surge/drop, line/provider issue, failover, monitoring artifact, or transient.

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute configuration, clear, reload, debug-enable, shutdown, save, write, copy or destructive operations.

## Evidence expectation

The final review should clearly show:

- 线路名称
- 突增或突降方向
- 当前流量和历史基线
- 设备名称和设备 IP
- 关联接口
- 接口当前速率、带宽、错误计数
- 是否伴随 link flap / 聚合成员变化
- 是否仍处于异常变化状态
- 建议下一步动作

<!-- V7_12_PROMETHEUS_FIRST_TRAFFIC_ANOMALY BEGIN -->
## v7.12 Prometheus-first traffic anomaly rule

For internet/DCI line traffic spike or drop alerts, do not start from device CLI.

Required workflow:

1. Query Prometheus first for the affected interface and direction.
2. Fetch each point in the recent time window, normally 5 to 15 minutes around the alert.
3. Compare current traffic with the previous baseline.
4. Confirm whether the spike/drop really exists.
5. Only after Prometheus confirms the trend, collect device-side evidence:
   - interface current rate
   - interface bandwidth or operational speed
   - errors/discards
   - port-channel state
   - link flap or traffic-related logs

The final review must explicitly include:

- current traffic series
- previous baseline
- spike/drop direction
- whether Prometheus confirms the anomaly
- whether device-side evidence supports a link, port-channel, provider, failover or traffic-source issue
<!-- V7_12_PROMETHEUS_FIRST_TRAFFIC_ANOMALY END -->
