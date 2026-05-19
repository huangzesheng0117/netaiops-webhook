# NetAIOps webhook v6 Release Notes

## 1. Release 范围

本次 v6 改造面向 NetAIOps webhook 平台的运维可维护性、结构化取证、Skill 约束和发布回归体系。

v6 改造不改变现有 MCP 主执行链路，不启用真实自适应补充取证，不让 LLM 自由生成命令。

## 2. v6.1 Investigation Session

v6.1 建立受控调查状态机和 Investigation Session。

核心能力：

- 为 request_id 建立调查时间线
- 记录 received、normalized、analyzed、planned、policy_checked、dispatched、executed、judged、reviewed、notified 等阶段
- 新增 /v6/investigation/{request_id}
- 新增 v6.1 回归入口

## 3. v6.2 Tool / Parser 体系

v6.2 参考 MCPyATS 的 Tool / Parser 思路，建立只读 Tool Registry 和 Parser Registry。

核心能力：

- mcp_netmiko_run_show
- prometheus_range_query
- parser_parse_cli_output
- cisco_show_interfaces parser
- cisco_show_interfaces_counters_errors parser
- cisco_etherchannel_summary parser
- execution parsed enrichment
- evidence_facts parsed-first

接口利用率样例中的 5 条命令均可 parsed。

## 4. v6.3 NetAIOps Skill 库

v6.3 参考 claude-network-skills，建立 NetAIOps 自有 Skill 包。

当前 Skill：

- interface_utilization_high

Skill 文件：

- SKILL.md
- commands.yaml
- evidence_rules.yaml
- output_schema.json

核心能力：

- Skill Package 校验
- Skill Binding 校验
- Investigation Session skill_context
- execution/review Skill Compliance 校验

## 5. v6.4 Skill Runtime

v6.4 参考 Anthropic Skills 的渐进加载思想，实现 Skill Runtime。

加载层级：

- metadata
- instructions
- commands
- evidence
- schema

Investigation Session 默认只持久化 metadata，不嵌入完整 Skill 内容。

新增只读 API：

- /v6/skills/runtime
- /v6/skills/runtime/validate
- /v6/skills/runtime/family/{family}
- /v6/skills/runtime/skill/{skill_name}

## 6. v6.5 Skill 约束下的自适应取证 dry-run

v6.5 建立 Skill 约束下的 adaptive evidence dry-run planner。

当前边界：

- dispatch_enabled=false
- adaptive_execution_enabled=false
- dry_run_only=true
- readonly_only=true

模拟缺失 facts 样例可生成 3 条候选命令：

- show interfaces TenGigabitEthernet1/0/1
- show interfaces TenGigabitEthernet1/0/1 counters errors
- show etherchannel summary

候选命令不会被真实执行。

新增只读 API：

- /v6/adaptive/plan/{request_id}
- /v6/adaptive/simulate/missing-facts

## 7. v6.6 发布与维护体系

v6.6 固化全量回归、发布前检查、Git diff 审计和维护文档。

核心入口：

- tools/regress_v6_all.sh
- tools/v6_release_precheck.py
- tools/v6_git_audit.py
- docs/v6_6_release_and_maintenance_runbook.md
- docs/v6_6_release_snapshot.json
- docs/v6_6_git_audit_report.json

## 8. 当前发布边界

当前 v6 发布仍保持以下边界：

- 不启用真实 adaptive candidates 执行
- 不改变 MCP 只读取证边界
- 不绕过 safety_policy
- 不提交 config.yaml、data、logs、backup、venv 等运行时或敏感内容
- Git commit 等最终确认后再执行

## 9. 推荐验收命令

```bash
cd /opt/netaiops-webhook
source venv/bin/activate
bash tools/regress_v6_all.sh
python tools/v6_git_audit.py --write docs/v6_6_git_audit_report.json
```

## 10. 推荐提交说明

建议最终提交信息：

```text
feat: complete NetAIOps webhook v6 investigation, parser, skill and adaptive dry-run framework
```
