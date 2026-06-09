---
name: device_memory_utilization_high
version: v8.4.0-cisco-memory-prometheus
family: device_memory_utilization_high
description: Cisco device memory utilization high analysis skill with Prometheus history and readonly CLI evidence.
risk_level: readonly
stage: v8
---

# device_memory_utilization_high

## Scope

This Skill handles Cisco device memory high utilization alerts.

Supported platforms:

- Cisco NX-OS
- Cisco IOS-XE
- Cisco IOS

## Investigation strategy

Memory high analysis must not rely on one percentage only.

The first-stage investigation distinguishes:

1. Monitoring false positive or cache-related high used memory.
2. Real low available/free memory.
3. Process-level memory pressure.
4. Sustained growth / suspected leak.
5. Route / ARP / MAC table scale growth.
6. Low-memory fault symptoms such as MALLOCFAIL, OOM, core, crash or restart.
7. HA / standby / stack member inconsistency.

## First-stage command policy

The first-stage commands are generic and do not assume BGP is enabled.

BGP, OSPF, ISIS, EVPN, vPC, LACP or feature-specific commands are only added in a later targeted stage if first-stage evidence points to those areas.

## NX-OS caution

NX-OS memory high must distinguish used memory from available and cache.

High used memory alone is not enough to conclude a fault. Linux page cache can make used memory look high while available memory remains healthy.

## IOS-XE caution

IOS-XE needs both IOS process view and platform/Linux process view.

Important evidence includes:

- show processes memory sorted
- show processes memory platform sorted
- show processes memory platform accounting
- show memory statistics history table
- show memory failures alloc

## DingTalk notification format

Use the confirmed standard format:

1. 根据告警内容初步判断
2. 告警含义分析
3. 命令执行概况
4. 命令分析
5. 综合执行结果判断
6. 建议

Do not expose internal orchestration wording such as 第一批、第二批、第一波、第二波.

Command analysis should aggregate evidence instead of explaining commands one by one.

## Safety boundary

The default playbook is readonly only.

Forbidden actions:

- configure
- clear
- reload
- debug
- delete
- copy
- write memory
- process restart
