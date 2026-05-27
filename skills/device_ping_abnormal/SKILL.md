---
name: device_ping_abnormal
version: v6.3.0
family: device_ping_abnormal
description: Device Ping reachability or latency abnormal analysis skill.
risk_level: readonly
stage: v6.3
---

# device_ping_abnormal

## Scope

This Skill is generated from net-global Prometheus rule semantics.

Covered alert names:

- Ping

## Investigation goal

Confirm whether Ping packet loss or latency abnormality is still active, distinguish device management-plane reachability from exporter or ICMP path issue, and correlate with current device status, interface status and Prometheus window evidence.

## Runtime boundary

Only readonly tools are allowed.

## Evidence expectation

The final review should clearly show:

- 目标设备和 IP
- Ping 丢包、时延或 Prometheus 窗口状态
- MCP 是否能连接
- 设备当前基础状态
- 是否仍处于 Ping 异常、已恢复、短时抖动或证据不足
- 建议下一步动作
