# family_registry 说明

## 1. 作用

family_registry 是 webhook_v5 的告警家族收口层。

它负责把 normalized / enriched event 转换成稳定的 family_result，供后续 capability、plan、policy、review、notification 消费。

## 2. 输出结构

典型结构：

{
  "family": "interface_or_link_utilization_high",
  "family_confidence": "high",
  "match_source": "event_field",
  "match_reason": "catalog rule or heuristic reason",
  "catalog_rule_id": "",
  "legacy_playbook_type": "interface_or_link_utilization_high",
  "target_kind": "interface",
  "auto_execute_allowed": true,
  "default_capabilities": [],
  "target_scope": {}
}

## 3. 第一批告警家族

当前支持：

- interface_or_link_utilization_high
- interface_or_link_traffic_drop
- interface_packet_loss_or_discards_high
- interface_status_or_flap
- bgp_neighbor_down
- ospf_neighbor_down
- routing_neighbor_down
- device_cpu_high
- device_memory_high
- f5_pool_member_down
- generic_network_readonly

## 4. 接口利用率高默认能力

interface_or_link_utilization_high 当前默认能力：

- show_interface_detail
- show_interface_error_counters
- show_portchannel_summary

## 5. 路由邻居类默认能力

bgp_neighbor_down 当前默认能力：

- show_bgp_peer_detail
- show_route_to_peer
- ping_peer
- show_interface_brief
- show_bgp_config_snippet

ospf_neighbor_down 当前默认能力：

- show_ospf_peer_detail
- show_interface_brief
- show_recent_logs

## 6. F5 pool member down 默认能力

f5_pool_member_down 当前默认能力：

- show_f5_pool_list
- show_f5_pool_members
- show_f5_pool_config
- show_f5_connections
- show_f5_performance

## 7. 自动执行原则

- firing 告警可按策略自动执行只读取证。
- resolved 告警默认不自动执行。
- generic_network_readonly 默认保守处理。
- 所有自动执行必须通过 readonly guard。
