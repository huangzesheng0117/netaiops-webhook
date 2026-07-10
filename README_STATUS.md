# NetAIOps Webhook 当前状态

> 更新时间：2026-07-10
> 当前阶段：v11 Learning Loop / Governance 功能建设完成；Release Audit 暂为 WARNING，等待历史回归清理。

## 当前版本

```text
11.0.0-v11-learning-governance
```

## 固定信息

| 项目 | 当前值 |
|---|---|
| 生产目录 | `/opt/netaiops-webhook` |
| MCP Helper | `/opt/netaiops-mcp-helper` |
| systemd 服务 | `netaiops-webhook.service` |
| 端口 | `18080` |
| 分支 | `main` |
| v10 发布 commit | `339e857` |
| 最新维护 commit | `ef1149931419c4d232cad1b2b0fafb2510575b45` |
| 最新维护提交 | `v10: support GLM 5.2 health checks` |
| 生产 LLM | `glm-5.2` |
| AI 通知 | universal card |
| v10 Release Audit | `PASS` |
| v11 Release Audit | `WARNING` |
| 已知历史遗留测试失败 | `28` |
| Batch 11 新增测试失败 | `0` |

## v10 当前能力

```text
Alertmanager
→ Raw / Normalized / request_id
→ GLM 5.2
→ Family / Skill / Playbook
→ Prometheus MCP
→ Netmiko MCP（只读）
→ Execution
→ Review
→ Evidence Hub
→ AI universal card
```

已完成：

- Evidence Hub schema / builder / writer；
- Evidence Hub API / UI；
- Prometheus Evidence；
- 设备命令成功、失败、失败原因和 raw output；
- slim summary / slim text；
- AI universal card；
- firing / resolved 状态；
- 轻量链路与 AI 主链路隔离；
- 轻量 firing 一小时限流；
- resolved 清除 firing 限流；
- GLM 5.2 健康检查兼容；
- Release Audit PASS。

v10 发布验收基线：

```text
定向测试：32 tests OK
综合回归：77 tests OK
最终 request_id：20260703_154613_796157_3750fbea
problems：[]
warnings：[]
Release Audit：PASS
```

## GLM 5.2 发布后维护

原 `qwen3-max` 后端已失效，生产模型已切换为 `glm-5.2`。

标准健康检查：

```text
smoke_max_tokens = max(1200, config.llm.max_tokens)
```

并记录：

```text
chat_smoke_max_tokens
chat_reported_model
chat_finish_reason
```

模型切换已验证 `/models`、chat smoke、真实告警分析、咚咚卡片和 Evidence Hub。生产 `config.yaml` 不提交 Git。

## 当前运行产物

```text
data/raw
data/normalized
data/analysis
data/plans
data/prometheus_evidence
data/execution
data/reviews
data/notifications
data/evidence_hub/requests
data/light_alerts
```

这些都是运行时数据，不提交 Git。

## v11 已冻结范围

v11 建设：

```text
Incident Memory
Learning Signal
Proposal
Offline Replay
Before / After Comparison
Learning Report
Release Audit
Governance API
Governance UI
Backfill / Canary / Regression
```

v11 不建设：

```text
自动修改正式 Skill / Playbook
自动增加或执行设备命令
绕过 Safety Policy
自动执行 Proposal
自动 Git commit / push
默认调用真实 GLM / MCP / 咚咚的 Replay
动态 Evidence Planning
自由多 Agent
真实 ELK Logs Evidence
```

## v11 数据与迁移边界

Governance 运行目录统一为：

```text
data/governance/incident_memory
data/governance/signals
data/governance/proposals
data/governance/replays
data/governance/reports
data/governance/audits
data/governance/backfill
```

当前决定：

- v11 初版不自动删除 Governance 数据；
- API / UI 只读优先；
- 部署在现有内部网络，不新增应用登录系统；
- 设备名称和 IP 可以展示；
- token、secret、完整 raw output 和完整敏感日志不展示；
- reviewer 暂为可选字符串；
- 不迁移旧 v7 `data/memory`、`relation_events` 和旧 `skill_proposals`；
- 旧 v7 代码和数据只作为设计参考。

## Fixture Matrix

v11 使用“真实 request + 合成边界 fixture”，至少覆盖：

```text
v10 Release Audit 基线
GLM 5.2 分析成功但 CLI 失败
Prometheus + Device + Evidence Hub 全成功
模型 JSON 解析失败
429 / 外部模型失败
Safety Policy blocked
Playbook missing / fallback
notification_failed
logs_not_available
```

## 后续路线

已冻结：

```text
v11：Learning Loop / Governance
v12：Controlled Multi-Agent / RCA
     Deterministic Evidence Mode
```

暂定：

```text
v13：Evidence Capability Foundation
v14：ELK Logs Evidence
v15：Policy-Constrained Evidence Planning
```

v13-v15 仍可根据 Elasticsearch 对外查询接口进度调整，不属于最终冻结版本。

## ELK 当前状态

```text
Elasticsearch：8.4.3
采集：Logstash
展示：Kibana
告警：ElastAlert2
告警语义：单条事件、无恢复状态
对外查询接口：建设中
```

在正式查询接口完成前：

```text
source = logs
status = not_available
reason = elasticsearch_query_interface_pending
```

该状态不能解释为查询失败、无异常日志或未发现问题。

## 当前下一步

```text
1. 完成 v11 项目文档和项目指令同步
2. 启动 v11.1 Historical Regression Cleanup
3. 将全仓库历史失败从 28 降至 0
4. 将 v11 Release Audit 从 WARNING 升级为 PASS
```

## v11 Release Acceptance 说明

当前全仓库仍保留 28 个在 Batch 10 修改前已经存在的历史遗留测试失败。Batch 11 不允许新增失败，因此版本一致性修复后，门禁必须满足 `observed_count=28`、`new_failure_count=0`、`exact_match=true`。这些历史问题将在独立维护批次中修复，不归因于 Batch 9、Batch 10 或 Batch 11。
