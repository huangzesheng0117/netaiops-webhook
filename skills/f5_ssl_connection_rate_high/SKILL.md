---
name: f5_ssl_connection_rate_high
version: v6.3.0
family: f5_ssl_connection_rate_high
description: F5 SSL new connection rate high analysis skill.
risk_level: readonly
stage: v6.3
---

# f5_ssl_connection_rate_high

## Scope

This Skill is generated from F5 Prometheus rule semantics.

Covered alert names:

- 新建连接数(SSL)
- SSL新建连接数

## Investigation goal

确认 F5 SSL 新建连接数是否仍高，并关联 SSL profile、virtual server、CPU/TMM 压力和业务访问突增。

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute modify, create, delete, save, load, reboot, restart, reset, bash or run util operations.

## Evidence expectation

The final review should clearly show:

- SSL 新建连接数
- Top virtual server
- Client SSL profile
- 是否伴随 CPU/TMM 压力
- 建议下一步动作
