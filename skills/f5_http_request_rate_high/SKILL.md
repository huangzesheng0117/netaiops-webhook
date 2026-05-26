---
name: f5_http_request_rate_high
version: v6.3.0
family: f5_http_request_rate_high
description: F5 HTTP request rate high analysis skill.
risk_level: readonly
stage: v6.3
---

# f5_http_request_rate_high

## Scope

This Skill is generated from F5 Prometheus rule semantics.

Covered alert names:

- 新建HTTP请求数
- HTTP请求数

## Investigation goal

确认 F5 HTTP 请求速率是否仍高，并识别是否由特定 virtual server、HTTP profile 或业务访问突增引起。

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute modify, create, delete, save, load, reboot, restart, reset, bash or run util operations.

## Evidence expectation

The final review should clearly show:

- HTTP 请求速率
- Top virtual server
- 吞吐量和连接数
- 是否仍高位
- 建议下一步动作
