---
name: internet_line_latency_high
version: v6.3.0
family: internet_line_latency_high
description: Internet line latency abnormal analysis skill for Cisco internet edge links.
risk_level: readonly
stage: v6.3
---

# internet_line_latency_high

## Scope

This Skill is generated from net-internet Prometheus rule semantics.

Covered alert names:

- 互联网线路延迟
- 互联网线路时延
- 互联网链路延迟
- 互联网链路时延

## Investigation goal

Confirm whether internet line latency is still abnormal, correlate IP SLA / Prometheus latency window, interface health, error counters, link state and recent logs, and determine whether the issue is sustained latency, transient spike, line-side issue, peer/provider issue, or monitoring-only anomaly.

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute configuration, clear, reload, debug-enable, shutdown, save, write, copy or destructive operations.

## Evidence expectation

The final review should clearly show:

- 告警线路名称
- 设备名称和设备 IP
- 关联接口
- 当前延迟或 IP SLA 状态
- Prometheus 窗口趋势
- 接口当前状态、速率、错误计数
- 是否伴随 link flap / timeout / SLA 异常日志
- 是否仍处于延迟异常、已恢复、短时抖动或证据不足
- 建议下一步动作
