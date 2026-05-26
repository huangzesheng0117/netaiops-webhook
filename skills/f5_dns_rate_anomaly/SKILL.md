---
name: f5_dns_rate_anomaly
version: v6.3.0
family: f5_dns_rate_anomaly
description: F5 DNS request or response rate spike/drop analysis skill.
risk_level: readonly
stage: v6.3
---

# f5_dns_rate_anomaly

## Scope

This Skill is generated from F5 DNS Prometheus rule semantics.

Covered alert names:

- DNS每秒请求率突增
- DNS每秒请求率突降
- DNS每秒响应率突增
- DNS每秒响应率突降

## Investigation goal

Confirm whether DNS request or response rate changed sharply, identify whether the anomaly is still active, and correlate the change with Wide IP, pool, server and listener evidence.

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute modify, create, delete, save, load, reboot, restart, reset, bash or run util operations.

## Evidence expectation

The final review should clearly show:

- anomaly direction: spike or drop
- DNS metric type: request rate or response/resolution rate
- current value and previous value when available
- device hostname and device IP
- Wide IP / pool / listener evidence when available
- whether the change is still active, recovered, transient, or inconclusive
- recommended next action
