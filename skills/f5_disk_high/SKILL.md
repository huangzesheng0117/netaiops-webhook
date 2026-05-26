---
name: f5_disk_high
version: v6.3.0
family: f5_disk_high
description: F5 disk utilization high analysis skill.
risk_level: readonly
stage: v6.3
---

# f5_disk_high

## Scope

This Skill is generated from F5 Prometheus rule semantics.

Covered alert names:

- 磁盘利用率
- F5磁盘利用率

## Investigation goal

确认 F5 分区或磁盘空间是否不足，并评估是否影响日志、core、软件卷或升级空间。

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute modify, create, delete, save, load, reboot, restart, reset, bash or run util operations.

## Evidence expectation

The final review should clearly show:

- 高利用率分区
- 当前磁盘利用率
- 剩余空间
- 是否影响日志/core/软件卷
- 是否需要人工清理
