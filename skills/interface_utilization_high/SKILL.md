---
name: interface_utilization_high
version: v6.3.0
family: interface_or_link_utilization_high
description: Interface utilization high investigation skill for NetAIOps webhook.
risk_level: readonly
stage: v6.3
---

# interface_utilization_high

## 1. 适用范围

本 Skill 适用于接口或链路利用率过高类告警。

对应 family：

- interface_or_link_utilization_high

典型告警包括：

- SH8-GDS利用率-出向
- SH8-CTC利用率-出向
- SH16-GDS利用率-入向
- SH16-CTC利用率-入向
- 互联网线路利用率超过阈值
- 专线或链路带宽利用率超过阈值

## 2. 调查目标

本 Skill 的目标是判断接口利用率告警属于以下哪类情况：

- 持续高利用率
- 瞬时峰值
- 取证时已恢复
- 告警口径带宽与物理带宽不一致
- 接口存在错误包、CRC、丢弃等质量问题
- 聚合链路或双接口场景下只看单口导致结论不完整

## 3. 必要输入字段

至少需要以下字段：

- request_id
- hostname
- device_ip
- alarm_type
- alarm_text
- direction
- interface 或 interfaces
- platform
- family

可选字段：

- threshold_percent
- logical_bandwidth_bps
- physical_bandwidth_bps
- prometheus_rule
- alert_start_time
- alert_end_time

## 4. 允许调用的 Tool

只允许调用 readonly Tool：

- mcp_netmiko_run_show
- prometheus_range_query
- parser_parse_cli_output

当前保留但默认不启用：

- elastic_log_window_query
- cmdb_device_lookup

## 5. 允许执行的 capability

- show_interface_detail
- show_interface_error_counters
- show_interface_aggregation
- prometheus_interface_window
- parse_cli_output

## 6. 禁止动作

禁止任何配置变更动作。

禁止执行以下类型命令：

- configure terminal
- interface <name>
- shutdown
- no shutdown
- clear counters
- reload
- write memory
- copy running-config startup-config
- delete
- erase
- request platform
- debug

## 7. 关键证据字段

接口详情证据：

- interface
- admin_status
- oper_status
- bandwidth_bps
- input_rate_bps
- output_rate_bps
- input_utilization_percent_estimated
- output_utilization_percent_estimated
- description

错误计数证据：

- crc
- fcs_err
- input_errors
- rcv_err
- xmit_err
- out_discards
- output_discards
- output_errors
- output_drops
- runts

聚合证据：

- port_channel_count
- etherchannel_member_count
- etherchannel_bundled_member_count
- etherchannel_down_member_count
- etherchannel_members
- etherchannel_port_channels

Prometheus 窗口证据：

- alert_window_max_percent
- alert_window_avg_percent
- alert_window_last_percent
- sustained_high
- recovered_at_evidence_time

## 8. 判断逻辑

优先判断顺序：

1. 先确认接口状态是否 up/up。
2. 再确认设备侧实时速率是否仍超过阈值。
3. 再按告警口径带宽计算利用率。
4. 再结合 Prometheus 告警窗口判断是否为持续高利用率。
5. 再检查 CRC、FCS、input errors、output drops 等质量指标。
6. 如果涉及双接口或聚合口，必须合并两个接口和聚合关系后判断。
7. 如果设备侧实时数据低于阈值，但 Prometheus 窗口曾经超过阈值，优先判断为瞬时峰值或已恢复。
8. 如果物理带宽是 10G，但告警口径是 300M，应同时展示物理口径和告警口径。

## 9. 通知展示要求

通知里至少展示：

- 接口状态
- 告警方向
- 物理带宽
- 告警口径带宽
- 设备侧实时速率
- 设备侧估算利用率
- 告警口径估算利用率
- 错误包 / CRC / 丢弃情况
- 聚合口成员状态
- Prometheus 窗口判断
- 综合结论

## 10. 人工复核条件

出现以下情况时建议人工复核：

- 接口状态非 up/up
- CRC 或 FCS 持续增长
- output drops 明显增长
- Prometheus 和设备侧数据明显不一致
- 告警口径带宽无法识别
- 多接口或聚合关系无法完整解析
- MCP 取证命令存在 hard_error
- parser status 为 error 或关键命令 no_parser_matched

## 11. 当前边界

当前 Skill 第一版主要覆盖 Cisco IOS / IOS-XE 接口利用率类告警。

NX-OS、ACI、H3C、Huawei、F5 等平台后续继续扩展独立 Skill 或扩展 commands.yaml。
