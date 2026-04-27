# NetAIOps Webhook 当前状态

## 当前版本

5.0.0-v5-batch1

## 当前阶段

webhook_v5 第一批闭环已完成。

当前系统已经从 v4 的 playbook / 字符串命令编排，升级为以“告警家族 -> 能力选择 -> 平台命令矩阵 -> MCP只读取证 -> 输出判错 -> 事实提炼 -> 复核结论 -> 咚咚通知”为主线的能力级只读取证闭环。

## 已完成能力

### 1. 告警接入

- 支持 Alertmanager Webhook。
- 支持 Elastic Webhook。
- 支持 raw payload 落盘。
- 支持 normalized event 落盘。

### 2. 三层上下文增强

当前继续沿用已有 three-layer 增强产物：

- layer1_alert_families.enhanced.yaml
- layer2_classifier_mapping.enhanced.yaml
- layer3_context_enrichment.enhanced.yaml
- device_inventory.normalized.yaml
- target_lookup.yaml
- config_interface_index.json

### 3. 告警家族识别

新增模块：

- netaiops/family_registry.py

当前第一批支持：

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

### 4. 能力注册表

新增模块：

- netaiops/capability_registry.py

作用：

- 将告警家族转换为可执行的只读能力。
- 每个能力声明所需参数、是否只读、判错规则类型。
- 后续不再依赖模型直接自由生成命令。

### 5. 平台命令矩阵

新增模块：

- netaiops/platform_command_matrix.py

当前支持的平台键：

- cisco_nxos
- cisco_iosxe
- huawei_vrp
- h3c_comware
- f5_tmsh
- generic_network

已验证 Cisco ACI / NX-OS 设备不会再误走 IOS-XE 命令。

### 6. 输出判错

新增模块：

- netaiops/output_judger.py

可以识别：

- invalid command
- incorrect command
- ambiguous command
- incomplete command
- unknown command
- syntax error
- shell command not found
- no device named
- authentication failed
- permission denied
- timeout
- traceback
- validation error

同时避免把正常接口计数里的 CRC / input error / output error 误判为命令执行失败。

### 7. 设备名解析

新增模块：

- netaiops/target_resolver.py

作用：

- 将 exporter endpoint 展示名转换为真实设备名。
- 例如将 10.191.96.43:9116 展示为 SH8-K10-ACI-1107（10.192.250.107）。

### 8. 取证事实提炼

新增模块：

- netaiops/evidence_facts.py

当前已支持接口类告警事实提炼：

- 接口 oper/admin 状态
- 接口描述/对端信息
- 实时 input/output rate
- port-channel 归属关系
- 聚合口状态
- 成员口状态
- CRC / input error / output error
- output discard / output drops
- 最近链路抖动时间

### 9. MCP只读取证闭环

已接通链路：

- plan_builder
- agent_client
- agent_runner
- execution_callback
- review_builder
- request_summary
- notification_payload

当前系统可以对真实 firing 告警自动执行只读命令，并基于返回结果生成复核结论。

## 已验证真实告警

request_id：

20260419_011059_145604_a7900a1a

验证结果：

- 设备：SH8-K10-ACI-1107（10.192.250.107）
- 告警家族：interface_or_link_utilization_high
- 执行来源：capability_registry
- 执行模式：mcp
- 执行命令数：3
- 执行状态：completed
- 复核状态：completed
- 已提取事实：接口状态、实时速率、聚合关系、output drops 等。

## 当前安全边界

- 只允许只读命令。
- 不执行配置修改。
- 不执行自动恢复。
- 不执行 shutdown / no shutdown。
- 不执行 clear / reset / reload。
- resolved 告警默认不自动执行。
- 所有自动执行都必须通过 readonly guard 和 auto-confirm policy。

## 当前咚咚通知格式

当前通知正文只保留：

- 设备
- 告警内容
- MCP只读取证统计
- 取证事实
- 综合判断
- 建议

已删除：

- 分析上下文
- 详情链接
- 每条命令的大段原始输出

## 后续方向

1. 补充 Prometheus 指标窗口证据。
2. 补充 Elastic 日志窗口证据。
3. 扩展更多告警家族的 evidence_facts。
4. 增加平台命令矩阵回归测试。
5. 增加 output_judger 回归测试。
6. 引入 capability-level LLM planner。
7. 增加告警去重、节流、冷却时间。
8. 后续考虑将运行元数据迁移到 SQLite 或 PostgreSQL。
