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

## v6.1 Investigation Session 状态机

当前 v6.1 已完成第一阶段改造：参考 ADAPT 的受控调查状态机思想，为 request_id 建立 Investigation Session。

### 已完成能力

- 新增 netaiops/investigation_state.py
- 新增 netaiops/investigation_policy.py
- 新增 tools/show_investigation_session.py
- 新增 tools/regress_investigation_sessions.py
- 新增 tools/regress_v6_1.sh
- 新增 docs/v6_1_investigation_runbook.md
- 新增 /v6/investigation/{request_id} 查询接口
- 新增 /v6/investigation/{request_id}/build 重建接口
- callback 后可自动生成 investigation session
- 支持 received -> normalized -> analyzed -> planned -> policy_checked -> dispatched -> executed -> judged -> reviewed -> notified 时间线
- v6.1 阶段 adaptive 默认关闭，只做状态记录，不改变现有执行链路

### 当前边界

- v6.1 不启用自适应补充取证
- v6.1 不允许 LLM 自由生成命令
- v6.1 不绕过 safety_policy、platform_command_matrix、output_judger
- 设备侧动作仍坚持只读取证

### v6.1 回归命令

    cd /opt/netaiops-webhook
    source venv/bin/activate
    bash tools/regress_v6_1.sh

### 下一阶段

下一阶段为 v6.2：参考 MCPyATS 建立 Tool Registry 与 Parser Registry，优先解决 CLI 输出结构化问题。

## v6.2 Tool / Parser 体系

当前 v6.2 已完成 Tool Registry 与 Parser Registry 的第一阶段建设，参考 MCPyATS 的 Tool / Parser 设计思路，但不直接引入 MCPyATS 整套框架。

### 已完成能力

- 新增 netaiops/tool_registry.py
- 新增 netaiops/parser_registry.py
- 新增 netaiops/execution_parser_enricher.py
- 新增 netaiops/evidence_parsed_facts.py
- 新增 Cisco show interfaces 解析器
- 新增 Cisco show interfaces counters errors 解析器
- 新增 Cisco etherchannel summary 解析器
- 新增 tools/validate_tool_registry.py
- 新增 tools/validate_parser_registry.py
- 新增 tools/enrich_execution_parsed.py
- 新增 tools/verify_evidence_parsed_facts.py
- 新增 tools/regress_v6_2.sh
- 新增 docs/v6_2_tool_parser_runbook.md

### 当前效果

接口利用率类样例中的 5 条只读命令均可写入 parsed facts：

- show interfaces TenGigabitEthernet1/0/1
- show interfaces TenGigabitEthernet2/0/1
- show interfaces TenGigabitEthernet1/0/1 counters errors
- show interfaces TenGigabitEthernet2/0/1 counters errors
- show etherchannel summary

evidence_facts 已支持 parsed-first：

    parsed_facts_enabled: true
    facts_source_preference: parsed_first_raw_fallback

### 当前边界

- v6.2 不改变现有 MCP 只读取证执行链路
- v6.2 不绕过 safety_policy
- v6.2 不启用自适应取证
- raw output 仍作为 fallback
- 当前 Parser 重点覆盖 Cisco IOS / IOS-XE 接口利用率类命令

### v6.2 回归命令

    cd /opt/netaiops-webhook
    source venv/bin/activate
    bash tools/regress_v6_2.sh

### 下一阶段

下一阶段为 v6.3：参考 claude-network-skills 建设 NetAIOps 网络 Skill 库。

## v6.3 NetAIOps Skill 库

当前 v6.3 已完成第一阶段 Skill 体系建设，参考 claude-network-skills 的网络排障 Skill 思路，但不依赖 Claude，不直接引入外部 Skill Runtime。

### 已完成能力

- 新增 skills/interface_utilization_high/SKILL.md
- 新增 skills/interface_utilization_high/commands.yaml
- 新增 skills/interface_utilization_high/evidence_rules.yaml
- 新增 skills/interface_utilization_high/output_schema.json
- 新增 netaiops/skill_registry.py
- 新增 netaiops/skill_binding_validator.py
- 新增 netaiops/skill_session_context.py
- 新增 netaiops/skill_compliance_validator.py
- 新增 tools/validate_skills.py
- 新增 tools/validate_skill_bindings.py
- 新增 tools/show_investigation_skill_context.py
- 新增 tools/validate_skill_compliance.py
- 新增 tools/regress_v6_3.sh
- 新增 docs/v6_3_skill_runbook.md

### 当前效果

当前已建立第一个 Skill：

    interface_utilization_high

该 Skill 对应：

    interface_or_link_utilization_high

已支持旁路校验：

- Skill Package 完整性
- Skill Binding 完整性
- Investigation Session skill_context
- execution 命令与 parser 合规性
- review facts 与 parsed_fact_sources 合规性
- 通知 required_lines 非严格校验

### 当前边界

- v6.3 不改变现有 MCP 只读取证执行链路
- v6.3 不启用自适应取证
- v6.3 不让 LLM 自由生成命令
- 当前只建设 interface_utilization_high 一个 Skill
- capability 文本扫描存在 warning，不影响当前 pass
- notification required lines 当前为非严格校验

### v6.3 回归命令

    cd /opt/netaiops-webhook
    source venv/bin/activate
    bash tools/regress_v6_3.sh

### 下一阶段

下一阶段为 v6.4：参考 Anthropic Skills 实现 Skill Runtime 与渐进加载机制。

## v6.4 Skill Runtime 渐进加载

当前 v6.4 已完成 Skill Runtime 第一阶段建设，参考 Anthropic Skills 的渐进加载思想。

### 已完成能力

- 新增 netaiops/skill_runtime.py
- 新增 netaiops/skill_runtime_session_context.py
- 新增 netaiops/skill_runtime_api.py
- 新增 tools/show_skill_runtime.py
- 新增 tools/show_investigation_skill_runtime.py
- 新增 tools/validate_skill_runtime_api.py
- 新增 tools/regress_v6_4.sh
- 新增 docs/v6_4_skill_runtime_runbook.md
- 新增 /v6/skills/runtime
- 新增 /v6/skills/runtime/validate
- 新增 /v6/skills/runtime/family/{family}
- 新增 /v6/skills/runtime/skill/{skill_name}

### 当前效果

Skill Runtime 支持以下加载层级：

    metadata
    instructions
    commands
    evidence
    schema

Investigation Session 默认只持久化 metadata：

    loaded_levels: ["metadata"]
    content_embedded: false
    content_policy: metadata_only_in_investigation_session

HTTP API 支持按需加载，例如：

    levels=metadata,commands
    levels=metadata,instructions,commands,evidence,schema

### 当前边界

- v6.4 只提供只读 Runtime 查询能力
- v6.4 不改变现有 MCP 只读取证执行链路
- v6.4 不启用自适应取证
- v6.4 不让 LLM 自由生成命令
- 当前 Runtime 只围绕 interface_utilization_high 一个 Skill

### v6.4 回归命令

    cd /opt/netaiops-webhook
    source venv/bin/activate
    bash tools/regress_v6_4.sh

### 下一阶段

下一阶段为 v6.5：Skill 约束下的自适应取证。

## v6.5 Skill 约束下的自适应取证

当前 v6.5 已完成 Skill 约束下的自适应取证 dry-run 能力。

### 已完成能力

- 新增 netaiops/adaptive_evidence_policy.py
- 新增 netaiops/adaptive_evidence_planner.py
- 新增 netaiops/adaptive_session_context.py
- 新增 netaiops/adaptive_evidence_api.py
- 新增 tools/plan_adaptive_evidence.py
- 新增 tools/show_investigation_adaptive_context.py
- 新增 tools/simulate_adaptive_missing_evidence.py
- 新增 tools/validate_adaptive_evidence_api.py
- 新增 tools/regress_v6_5_adaptive_missing_sample.sh
- 新增 tools/regress_v6_5.sh
- 新增 docs/v6_5_adaptive_evidence_runbook.md
- 新增 tests/fixtures/adaptive_missing_facts/
- 新增 /v6/adaptive/plan/{request_id}
- 新增 /v6/adaptive/simulate/missing-facts

### 当前效果

v6.5 可以根据 review facts 缺失情况，在 Skill 约束下生成补充取证候选命令。

当前模式为 dry-run：

    mode: skill_constrained_dry_run
    dispatch_enabled: false
    dry_run_only: true
    readonly_only: true

模拟缺失 facts 场景下，可生成 3 条候选命令：

    show interfaces TenGigabitEthernet1/0/1
    show interfaces TenGigabitEthernet1/0/1 counters errors
    show etherchannel summary

### 当前边界

- v6.5 不真实执行 adaptive candidates
- v6.5 不改变现有 MCP 主执行链路
- v6.5 不让 LLM 自由生成命令
- v6.5 只允许 Skill 声明范围内的 readonly Tool、capability、command template
- 当前主要围绕 interface_utilization_high Skill

### v6.5 回归命令

    cd /opt/netaiops-webhook
    source venv/bin/activate
    bash tools/regress_v6_5.sh

### 下一阶段

下一阶段为 v6.6：固化回归、发布和维护体系。

## v6.6 发布与维护体系

当前 v6.6 已进入收尾阶段，目标是固化 v6.1 到 v6.5 的全量回归、发布前检查、回滚建议和维护入口。

### 已完成能力

- 新增 tools/regress_v6_all.sh
- 新增 tools/v6_release_precheck.py
- 新增 tests/test_v6_release_precheck.py
- 新增 docs/v6_6_release_and_maintenance_runbook.md
- 新增 docs/v6_6_release_snapshot.json 生成入口

### 当前边界

- v6.6 不改变生产执行链路
- v6.6 不启用 adaptive candidates 真实执行
- v6.6 不让 LLM 自由生成命令
- 当前阶段不自动提交 Git

### v6 全量回归命令

    cd /opt/netaiops-webhook
    source venv/bin/activate
    bash tools/regress_v6_all.sh

### 发布前检查

    python tools/v6_release_precheck.py --rid <request_id>

生成发布快照：

    python tools/v6_release_precheck.py --rid <request_id> --write docs/v6_6_release_snapshot.json

## v6.6 Release Notes 与 Git 审计

v6.6 第二批补充发布说明与 Git 提交前审计能力。

### 新增文件

- docs/v6_release_notes.md
- docs/v6_commit_readiness_checklist.md
- docs/v6_6_git_audit_report.json
- tools/v6_git_audit.py
- tests/test_v6_git_audit.py

### Git 审计命令

    python tools/v6_git_audit.py --write docs/v6_6_git_audit_report.json

### 当前提交策略

当前阶段仍不自动提交 Git。

最终提交前需要确认：

    bash tools/regress_v6_all.sh
    python tools/v6_git_audit.py --write docs/v6_6_git_audit_report.json

均返回 pass。
