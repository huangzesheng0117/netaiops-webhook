# webhook_v5 第一批闭环收口说明

## 目标

本批次完成 webhook_v5 第一阶段能力级只读取证闭环改造，将原本偏字符串 playbook 的执行方式，升级为：

- family_registry：告警家族识别与默认能力集合
- capability_registry：能力模板定义
- platform_command_matrix：不同平台的能力到命令映射
- output_judger：设备输出硬错误判定
- target_resolver：设备真实名称解析
- evidence_facts：设备返回结果事实提炼
- review / summary / notification：结构化结论与咚咚通知

## 已完成能力

1. 支持真实 Alertmanager 告警进入 v5 capability_registry 路径。
2. 支持 firing 告警自动只读取证。
3. 支持 NX-OS / ACI 平台识别，避免误走 IOS-XE 命令。
4. 支持通过 MCP 对真实设备执行只读命令。
5. 支持命令输出硬错误识别。
6. 支持从设备输出中提取接口状态、实时速率、聚合关系、错误/丢弃计数。
7. 支持在咚咚通知中展示精简后的取证事实、判断结论和建议。
8. 支持将 exporter endpoint 展示名替换为真实设备名。

## 已验证真实告警

request_id：

- 20260419_011059_145604_a7900a1a

验证结果：

- family：interface_or_link_utilization_high
- execution_source：capability_registry
- execution_mode：mcp
- command_count：3
- execution_status：completed
- review_status：completed
- device display：SH8-K10-ACI-1107（10.192.250.107）
- evidence_summary：已提取接口状态、速率、聚合关系、output drops 等事实

## 当前边界

1. 只允许只读命令。
2. 不执行配置变更、自动恢复、接口 shutdown/no shutdown 等写操作。
3. resolved 告警默认不自动执行。
4. 当前第一批重点覆盖接口类告警，其他家族后续继续扩展。
5. 当前 evidence facts 以设备 CLI 输出为主，Prometheus / Elastic 辅助证据后续补充。

## 后续方向

1. 扩展更多告警家族。
2. 补充 Prometheus 指标窗口证据。
3. 补充 Elastic 日志窗口证据。
4. 引入 capability-level LLM planner。
5. 增加回归测试集。
6. 做版本号、README、config.example.yaml 收口。
