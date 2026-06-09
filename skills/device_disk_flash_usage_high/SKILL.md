---
name: device_disk_flash_usage_high
version: v8.4.0-cisco-disk-flash-prometheus
family: device_disk_flash_usage_high
description: Cisco device disk / Flash usage high analysis skill with Prometheus filesystem history and readonly CLI evidence.
risk_level: readonly
stage: v8
---

# device_disk_flash_usage_high

## Scope

This Skill handles Cisco device disk / Flash / bootflash / crashinfo / log filesystem high utilization alerts.

Supported platforms:

- Cisco NX-OS
- Cisco IOS-XE
- Cisco IOS

## Investigation strategy

Disk / Flash high utilization analysis must combine:

1. Prometheus filesystem usage history when available.
2. Current device filesystem and directory evidence.
3. Current version and boot variable.
4. Image / package dependency analysis.
5. Large file type classification.
6. Core / crash / show-tech / pcap / log / backup file detection.
7. Standby / stack member storage consistency.
8. Filesystem error and no-space log correlation.

## Safety boundary

The default playbook is readonly only.

The following operations are forbidden in auto execution:

- delete
- erase
- install remove inactive
- request platform software package clean
- request platform software package clean switch all
- copy
- format
- squeeze

Do not delete files just because they are large.

Protect these files unless manually confirmed safe:

- packages.conf
- current boot variable referenced .bin
- current install mode .pkg
- startup-config
- private-config
- vlan.dat
- license files
- trustpoint / crypto / pki files
- current SMU / patch files
- recent TAC core / show-tech files

## Prometheus-first policy

When available, Prometheus filesystem history is used to determine:

- sustained high usage
- still growing usage
- periodic growth
- recovered after cleanup
- unavailable/no-data

Prometheus failure must not block CLI evidence.

## DingTalk notification format

Use the confirmed standard format:

1. 根据告警内容初步判断
2. 告警含义分析
3. 命令执行概况
4. 命令分析
5. 综合执行结果判断
6. 建议

Do not expose internal orchestration wording such as 第一批、第二批、第一波、第二波.

Command analysis should aggregate Prometheus and CLI evidence instead of explaining commands one by one.

## Judgement rules

- Multiple old images: check boot variable and current running image before suggesting cleanup.
- install mode package files: check packages.conf and show install summary; do not manually delete current packages.
- show-tech / tech-support archives: usually cleanup candidates after confirmation and archival.
- core / crashinfo files: preserve first and check process or system abnormality.
- pcap / cap files: confirm capture is stopped before cleanup.
- log files growing: find the log source; do not only delete files.
- standby / stack filesystem high: cleanup must consider each member/supervisor.
- filesystem readonly or I/O error: do not treat it as simple cleanup; investigate filesystem/hardware status.
