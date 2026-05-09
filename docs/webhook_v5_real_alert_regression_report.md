# webhook_v5 真实告警回归报告

- generated_at: 2026-05-09T07:38:13.679298+00:00
- total_checked: 5
- passed: 5
- failed: 0
- skipped_no_execution_family_count: 2
- missing_sample_family_count: 14

## family 总数

| family | total_count | execution_count |
|---|---:|---:|
| interface_status_or_flap | 1589 | 668 |
| interface_or_link_utilization_high | 1006 | 259 |
| interface_packet_loss_or_discards_high | 344 | 226 |
| generic_network_readonly | 322 | 0 |
| connection_or_session_anomaly | 236 | 0 |
| dns_quality_or_traffic_anomaly | 53 | 0 |
|  | 27 | 1 |
| hardware_component_abnormal | 22 | 0 |
| interface_or_link_traffic_drop | 11 | 5 |
| bgp_neighbor_down | 10 | 9 |
| cisco_nxos_basic_readonly | 3 | 3 |
| optical_power_abnormal | 2 | 0 |
| manual_real_mcp_test | 1 | 1 |

## 缺少真实样本的 family

- chassis_slot_or_module_abnormal
- cimc_hardware_abnormal
- device_cpu_high
- device_disk_high
- device_memory_high
- dns_request_rate_anomaly
- dns_response_rate_anomaly
- f5_connection_rate_anomaly
- f5_pool_member_down
- ha_or_cluster_state_abnormal
- hardware_fan_abnormal
- hardware_power_abnormal
- hardware_temperature_high
- ospf_neighbor_down

## 有样本但暂无 execution 的 family

- generic_network_readonly
- optical_power_abnormal

## 回归样本结果

| priority | family | request_id | device | commands | ok | errors |
|---|---|---|---|---:|---|---|
| P0 | interface_or_link_utilization_high | 20260509_121856_464702_0753f1e0 | 10.189.250.50 | 3 | True |  |
| P0 | interface_or_link_traffic_drop | 20260424_233124_296218_9915133e | 10.192.251.102 | 4 | True |  |
| P0 | interface_packet_loss_or_discards_high | 20260508_170059_069466_3144d3c3 | 10.187.250.95 | 3 | True |  |
| P0 | interface_status_or_flap | 20260509_152542_719620_de540f58 | 10.187.250.212 | 3 | True |  |
| P0 | bgp_neighbor_down | summarytest01 |  | 0 | True |  |
