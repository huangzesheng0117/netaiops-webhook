---
name: fortigate_connection_anomaly
version: v6.3.0
family: fortigate_connection_anomaly
description: FortiGate active or new connection spike/drop analysis skill.
risk_level: readonly
stage: v6.3
---

# fortigate_connection_anomaly

## Scope

This Skill is generated from FortiGate Prometheus rule semantics.

Covered alert names:

- 活动连接数突增
- 活动连接数突降
- 新建连接数突增
- 新建连接数突降

## Investigation goal

Confirm whether FortiGate active sessions or new connection rate changed sharply, compare current value with previous window, and determine whether the anomaly is business traffic change, abnormal traffic, failover, upstream/downstream interruption, or transient.

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute config, edit, set, unset, delete, reboot, shutdown, factoryreset, kill, or debug-enable operations.

## Evidence expectation

The final review should clearly show:

- 突增或突降方向
- 指标类型：活动连接数或新建连接数
- 当前值和上一窗口值
- 设备名称和设备 IP
- 当前会话统计
- 是否仍处于异常变化状态
- 是否可能与业务流量、攻击流量、HA 切换或链路中断有关
- 建议下一步动作
