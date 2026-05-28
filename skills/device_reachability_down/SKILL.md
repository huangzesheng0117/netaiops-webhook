---
name: device_reachability_down
version: v6.3.0
family: device_reachability_down
description: Device reachability down analysis skill for Prometheus up alert.
risk_level: readonly
stage: v6.3
---

# device_reachability_down

## Scope

This Skill is generated from net-global Prometheus rule semantics.

Covered alert names:

- up

## Investigation goal

Confirm whether the device exporter or network device is currently unreachable, distinguish exporter scrape failure from actual device down, and correlate with recent device status, HA status, interface/link events and Prometheus scrape window.

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute configuration, clearing, reboot, delete, save, commit, debug-enable or destructive operations.

## Evidence expectation

The final review should clearly show:

- 告警对象和设备 IP
- up 当前值和 Prometheus 窗口状态
- 是否是 exporter / SNMP / ICMP / 设备管理面不可达
- 如果 MCP 仍可连接，展示设备当前状态和基础只读取证
- 如果 MCP 无法连接，明确说明无法登录取证
- 是否仍处于不可达、已恢复、短时抖动或证据不足
- 建议下一步动作

<!-- V7_12_VENDOR_SPLIT_REACHABILITY BEGIN -->
## v7.12 vendor split reachability rule

For Prometheus `up` alerts, do not treat the alert as a generic HA or cluster event by default.

The analysis must first branch by vendor and follow the corresponding vendor-specific Skill:

- Cisco: `cisco_device_reachability_down`
- FortiGate: `fortigate_device_reachability_down`
- F5: `f5_device_reachability_down`
- Hillstone: `hillstone_device_reachability_down`

Mandatory diagnosis order:

1. ping management IP from the NetAIOps execution side
2. if ping fails, stop SSH/CLI analysis and report device/power/management-path/monitoring-path issue
3. if ping succeeds, check SSH login
4. if SSH fails, stop deeper CLI analysis and report management-plane/AAA/SSH/high-resource suspicion
5. only if SSH succeeds, run vendor-specific lightweight health inspection
<!-- V7_12_VENDOR_SPLIT_REACHABILITY END -->
