# webhook_v5 架构说明

## 1. 目标

webhook_v5 的目标是把系统从“能接警、能分析、能调度”的原型，升级为“面向真实网络运维场景的能力级只读取证平台”。

核心原则：

- 告警分类由 family_registry 统一收口。
- 排障动作先抽象成 capability。
- 不同平台命令由 platform_command_matrix 统一渲染。
- 所有命令必须是只读命令。
- 执行结果必须经过 output_judger 判错。
- review 结论必须尽量基于 evidence facts。
- 咚咚通知面向值班网工，突出可读性和可执行建议。

## 2. 主链路

整体链路：

Alertmanager / Elastic
-> raw payload
-> normalized event
-> context_catalog 三层增强
-> family_registry
-> capability_registry
-> platform_command_matrix
-> plan_builder
-> readonly guard
-> auto-confirm policy
-> agent_client
-> agent_runner
-> MCP readonly execution
-> execution_callback
-> output_judger
-> evidence_facts
-> review_builder
-> request_summary
-> notification_payload
-> notifier

## 3. 主要模块

### family_registry.py

负责：

- 告警家族识别
- legacy playbook_type 兼容
- 默认能力集合选择
- target_kind 定义
- auto_execute_allowed 默认值

### capability_registry.py

负责：

- 能力定义
- 参数要求
- 是否只读
- judge_profile
- family 到 capability 的默认编排

### platform_command_matrix.py

负责：

- 平台识别
- inventory / target_lookup 辅助识别
- capability 到平台命令的渲染
- 生成 execution_candidates

### output_judger.py

负责：

- 识别设备返回中的硬错误
- 修正 completed / failed 状态
- 避免将正常计数输出误判为失败

### target_resolver.py

负责：

- 根据 device_ip 查找真实设备名
- 清理 exporter endpoint 展示问题
- 优化咚咚通知中的设备展示

### evidence_facts.py

负责：

- 从设备命令输出中提取结构化事实
- 为 review 和 notification 提供事实依据

## 4. v4 兼容

v5 第一批仍保留 v4 路由和数据结构兼容：

- /v4/pipeline/run/{request_id}
- /v4/request/{request_id}/summary
- /v4/dispatch/{request_id}

同时继续使用：

- plan JSON
- dispatch JSON
- callback JSON
- execution JSON
- review JSON

这样可以避免一次性推倒重来。

## 5. 当前已验证能力

真实告警：

20260419_011059_145604_a7900a1a

验证内容：

- 真实 Alertmanager firing 告警
- Cisco ACI / NX-OS 平台识别
- 自动只读取证
- MCP 登录真实设备执行只读命令
- 输出判错
- 接口事实提炼
- review 结论生成
- 咚咚通知生成

## 6. 当前边界

- 当前第一批重点覆盖接口类告警。
- 其他告警家族后续继续扩展。
- 当前尚未自动查询 Prometheus 历史窗口。
- 当前尚未自动查询 Elastic 日志窗口。
- 当前不支持自动写操作。
