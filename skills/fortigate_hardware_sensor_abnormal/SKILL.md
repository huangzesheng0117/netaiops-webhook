---
name: fortigate_hardware_sensor_abnormal
version: v6.3.0
family: fortigate_hardware_sensor_abnormal
description: FortiGate hardware sensor abnormal analysis skill.
risk_level: readonly
stage: v6.3
---

# fortigate_hardware_sensor_abnormal

## Scope

This Skill is generated from FortiGate Prometheus rule semantics.

Covered alert names:

- 硬件传感器状态

## Investigation goal

确认 FortiGate 硬件传感器是否异常，并结合型号、硬件状态、资源状态评估是否存在电源、风扇、温度、板卡或 ASIC 风险。

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute config, edit, set, unset, delete, reboot, shutdown, factoryreset, kill, or debug-enable operations.

## Evidence expectation

The final review should clearly show:

- 异常传感器
- 设备型号
- 当前硬件状态
- 是否存在温度/电源/风扇风险
- 建议下一步动作
