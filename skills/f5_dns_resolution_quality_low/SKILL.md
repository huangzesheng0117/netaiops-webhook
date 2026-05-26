---
name: f5_dns_resolution_quality_low
version: v6.3.0
family: f5_dns_resolution_quality_low
description: F5 DNS resolution quality or preferred-resolution ratio low analysis skill.
risk_level: readonly
stage: v6.3
---

# f5_dns_resolution_quality_low

## Scope

This Skill is generated from F5 DNS Prometheus rule semantics.

Covered alert names:

- DNS解析率
- DNS优选解析率
- F5-DNS解析率
- F5-DNS优选解析率

## Investigation goal

Confirm whether DNS resolution ratio or preferred-resolution ratio is still low, and correlate Wide IP, pool, server, datacenter and listener state to identify whether the issue is DNS service quality, pool/server availability, or GTM topology/preference related.

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute modify, create, delete, save, load, reboot, restart, reset, bash or run util operations.

## Evidence expectation

The final review should clearly show:

- DNS resolution ratio or preferred-resolution ratio
- device hostname and device IP
- affected DNS job or site
- Wide IP / pool / server / datacenter state
- whether the issue is service quality or preferred site selection related
- Prometheus window state
- recommended next action
