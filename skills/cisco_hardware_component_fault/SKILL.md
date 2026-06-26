---
name: cisco_hardware_component_fault
version: v9.2.0-cisco-hardware-component-fault
family: cisco_hardware_component_fault
description: Cisco hardware component fault analysis skill covering fan, power, temperature, module, supervisor, stack, PoE and FEX symptoms.
risk_level: readonly
stage: v9
---

# cisco_hardware_component_fault

## Scope

This Skill is used for Cisco hardware component fault alerts, including:

- Fan fault / fan absent / fan speed abnormal
- Power supply failed / PSU input lost / capacity insufficient / redundancy lost
- Temperature warning / major / critical
- Module or linecard failed / offline / powered-dn
- Supervisor or redundancy abnormal
- Stack member hardware state abnormal
- PoE power denied / power budget insufficient
- FEX hardware abnormal
- Sensor warning / critical / fault

## Investigation goal

The goal is to determine:

1. Whether the hardware alarm is currently still active.
2. Which component or external factor is more likely involved.
3. Whether redundancy has been lost.
4. Whether the fault has affected service, modules, interfaces or control plane.
5. Whether the next action should be observation, redundancy restoration, site work, TAC/RMA or urgent escalation.

## Core principles

Do not jump directly to hardware replacement.

The analysis must first split the alarm into a concrete class:

| Alarm class | Key judgement |
| --- | --- |
| Fan fault | Is a single fan failed or the whole fan tray failed? Is temperature rising? |
| Power fault | Is PSU failed, absent, input lost or capacity insufficient? Is power redundancy lost? |
| Temperature alarm | Is it minor warning, major, critical or shutdown-level? Are fans normal? |
| Module fault | Is the module offline, powered-dn, ha-standby, failed or just standby? |
| Supervisor fault | Is standby supervisor ready? Is SSO healthy? |
| PoE fault | Is it power budget issue or endpoint/PD issue? |
| FEX fault | Are FEX fan/power/temp/uplink states abnormal? |
| Sensor fault | Is it a real environment issue or sensor-only anomaly? |

## Impact judgement

Hardware faults must be judged by impact:

- Is only one redundant component degraded?
- Is redundancy already lost?
- Is the device single-power or dual-power?
- Are multiple fans abnormal?
- Is temperature still increasing?
- Is a module offline and are interfaces affected?
- Is standby supervisor unhealthy?
- Are multiple devices reporting temperature or power alarms at the same time?

If several devices report power or temperature alarms at the same time, prefer checking site-level power, PDU, UPS, air conditioner, cabinet airflow and room temperature before replacing a single device part.

## Prometheus evidence requirements

The platform should query Prometheus MCP before or together with CLI evidence.

Expected historical evidence:

- device up status history
- temperature value or state history when available
- fan state history when available
- power supply state history when available

Prometheus evidence is auxiliary. Missing Prometheus metric data must not block CLI evidence. If Prometheus has no data, the notification must explicitly say that historical metric evidence is unavailable or incomplete.

## CLI evidence requirements

The first automated CLI wave must be readonly and no more than 15 commands.

For NX-OS/Nexus, the default command list is:

- show clock
- show version
- show environment
- show environment fan
- show environment fan detail
- show environment power
- show environment power detail
- show environment temperature
- show module
- show inventory
- show system resources
- show logging last 500 | include ENV|ENVMON|THERMAL|TEMP|TEMPERATURE|FAN|POWER|PS|PSU|FRU|OIR|MODULE|PLATFORM|SUP|SUPERVISOR|SENSOR|VOLT|XBAR|FABRIC|FEX|POE|ILPOWER
- show system cores
- show diagnostic result module all

## Forbidden actions

The skill must never automatically execute:

- configure terminal / conf t
- shutdown / no shutdown
- reload / redundancy force-switchover
- clear / delete / erase / format
- copy running-config startup-config / write memory
- diagnostic start / disruptive test
- power enable/disable
- module reload / power-cycle
- any physical replacement instruction as an automated action

## Notification requirements

The final message must use the standard v8/v9 format:

1. 根据告警内容初步判断
2. 告警含义分析
3. 命令执行概况
4. 命令分析
5. Prometheus窗口证据
6. 综合执行结果判断

Command lists must be one command per line.
