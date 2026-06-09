---
name: device_cpu_utilization_high
version: v8.3.0-cisco-cpu-prometheus
family: device_cpu_utilization_high
description: Cisco device CPU high utilization analysis skill with Prometheus historical CPU evidence and readonly CLI evidence.
risk_level: readonly
stage: v8
---

# device_cpu_utilization_high

## Scope

This Skill handles Cisco device CPU high utilization alerts.

Supported platforms:

- Cisco NX-OS
- Cisco IOS-XE
- Cisco IOS

## Investigation strategy

CPU high utilization analysis must combine:

1. Prometheus historical CPU window.
2. Device current CPU and CPU history.
3. Process CPU ranking.
4. Logs around the alert time.
5. Memory and system resource pressure.
6. Control-plane / CoPP / punt indicators.
7. SNMP and management session indicators.
8. Routing protocol and L2 control-plane indicators.
9. Interface error summary when needed for CPU-trigger correlation.

## Prometheus-first policy

When available, Prometheus CPU history is used before CLI judgement.

Default window:

- lookback: 30 minutes
- step: 60 seconds
- compare offset: 5 minutes

Prometheus should determine whether CPU is:

- instant spike
- periodic spike
- sustained high
- recovered
- unavailable / no data

Prometheus failure must not block CLI evidence.

## Command boundary

Only readonly commands are allowed.

Forbidden operations:

- configure terminal
- shutdown / no shutdown
- clear
- reload
- copy / delete / erase
- debug

## DingTalk notification format

Use the confirmed standard format:

1. 根据告警内容初步判断
2. 告警含义分析
3. 命令执行概况
4. 命令分析
5. 综合执行结果判断
6. 建议

Do not expose internal orchestration wording such as 第一批、第二批、第一波、第二波.

Command analysis should not explain every command one by one.
It should aggregate Prometheus and CLI evidence into operational judgement.

## CPU judgement rules

- Prometheus sustained high + CLI high: high confidence sustained CPU issue.
- Prometheus spike + CLI normal: likely transient or recovered.
- CPU high with one dominant process: process-driven CPU issue.
- CPU high with interrupt/punt/CoPP indicators: control-plane packet pressure.
- CPU high with SNMP or many management sessions: management-plane pressure.
- CPU high with routing neighbor flaps: routing protocol churn.
- CPU high with STP/vPC/LACP/ETHPORT logs: L2/interface event pressure.
- CPU high without obvious trigger: platform process, version defect or resource leak remains possible.
