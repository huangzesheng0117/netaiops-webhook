---
name: f5_connection_anomaly
version: v6.3.0
family: f5_connection_anomaly
description: F5 active or new connection spike/drop analysis skill.
risk_level: readonly
stage: v6.3
---

# f5_connection_anomaly

## Scope

This Skill is generated from F5 Prometheus rule semantics.

Covered alert names:

- F5活跃连接数突增
- F5活跃连接数突降
- F5新建连接数突增
- F5新建连接数突降

## Investigation goal

Confirm whether active connections or new connections changed sharply, identify whether the change is service-driven, abnormal traffic, failover-related, or transient, and correlate with virtual server, pool, throughput and Prometheus offset comparison.

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute modify, create, delete, save, load, reboot, restart, reset, bash or run util operations.

## Evidence expectation

The final review should clearly show:

- anomaly direction: spike or drop
- metric type: active connections or new connections
- current value and previous value when available
- device hostname and device IP
- Top virtual server / pool when available
- whether the change is still visible in the current window
- recommended next action
