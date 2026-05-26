---
name: f5_dns_request_rate_high
version: v6.3.0
family: f5_dns_request_rate_high
description: F5 DNS request rate high analysis skill.
risk_level: readonly
stage: v6.3
---

# f5_dns_request_rate_high

## Scope

This Skill is generated from F5 DNS Prometheus rule semantics.

Covered alert names:

- DNS请求率
- F5-DNS请求率
- DNS每秒请求率高

## Investigation goal

Confirm whether DNS request rate is still high, identify whether the load is concentrated on specific Wide IP, pool, DNS listener, site, or datacenter, and determine whether it is a business surge, abnormal request burst, or transient spike.

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute modify, create, delete, save, load, reboot, restart, reset, bash or run util operations.

## Evidence expectation

The final review should clearly show:

- DNS request rate and alert threshold
- device hostname and device IP
- DNS role or job name
- Wide IP / pool / server / listener evidence when available
- Prometheus window state
- whether the request rate is still high, recovered, transient, or inconclusive
- recommended next action
