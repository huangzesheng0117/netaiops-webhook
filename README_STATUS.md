# NetAIOps Webhook 当前状态

> 更新时间：2026-07-13
> 当前阶段：v11.1 Historical Regression Cleanup 已完成；v11 Final Release Audit 已升级为 PASS。

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
| v11 功能收口 commit | `0f60c91da69b732aec23032809715b9d5dfd762c` |
| v11.1 Batch B commit | `9dfe1d76e7091912d1e21daca24a22122af7746b` |
| v11.1 Batch C commit | `16924700d873c01136da9b6e37579f806d0bdd98` |
| v11.1 Batch D commit | `2aa7b77169c0150c2f32bd2652152cd3d756ede0` |
| 生产 LLM | `glm-5.2` |
| AI 通知 | universal card |
| v10 Release Audit | `PASS` |
| v11 Release Audit | `PASS` |
| v11 专项测试 | `269 tests OK` |
| 全仓库测试 | `549 tests OK` |
| 历史遗留测试失败 | `0` |
| 新增测试失败 | `0` |
| 下一主版本 | `v12 Controlled Multi-Agent / RCA` |

## 当前主链路

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
→ Governance Sidecar
```

## 轻量链路

```text
vmalert / Alertmanager
→ 轻量格式化
→ firing / resolved 卡片
→ firing 一小时限流
→ resolved 清除 firing 限流
```

轻量链路不调用 GLM，不调用 MCP，不进入 Evidence Hub 或 Governance。

## v10 已完成

- Evidence Hub schema / builder / writer；
- Evidence Hub API / UI；
- Prometheus Evidence；
- 设备命令结果、失败原因和 raw output；
- slim summary / slim text；
- AI universal card；
- firing / resolved；
- 轻量链路限流；
- GLM 5.2 健康检查兼容；
- Release Audit PASS。

## v11 已完成

```text
Incident Memory
Learning Signal
Draft Proposal
Offline Replay
Before / After Comparison
Learning Report
Release Audit
Governance API
Governance UI
Sidecar Integration
Controlled Backfill
Repository Gate
Release Acceptance
```

v11 Governance Sidecar 是非阻断旁路：

- Proposal 默认 `draft`；
- `auto_apply=false`；
- Replay 默认离线；
- 不自动修改正式 Skill / Playbook；
- 不自动执行新增命令；
- 不自动 Git commit / push；
- 不默认调用真实 GLM、MCP 或咚咚。

## v11.1 Historical Regression Cleanup

### Batch B：Schema 兼容

```text
legacy v6.3 Skill Schema
current v8 / v9 Skill Schema
global / per_interface
{interface} / {interface_each}
legacy facts / JSON Schema properties
```

结果：

```text
28 frozen failures
→ 11 resolved
→ 17 remain
```

### Batch C：当前契约对齐

将旧测试和 fixture 对齐到当前 v9 Skill 权威契约，不降低生产契约，不虚构旧命令。

结果：

```text
17 failures
→ 9 resolved
→ 8 remain
```

### Batch D：流量异常与 DCI Playbook

完成：

```text
DCI线路流量突增
DCI线路流量突降
DCI专线流量突增
DCI专线流量突降
互联网线路流量突降
Prometheus-first traffic anomaly
```

结果：

```text
8 failures
→ 8 resolved
→ 0 remain
```

### Batch E：最终 Release Acceptance

最终门禁：

```text
known_failure_policy = strict-zero-regressions-v2
expected_count = 0
observed_count = 0
new_failure_count = 0
full repository return code = 0
```

最终验收：

```text
v11 专项测试：269 tests OK
全仓库测试：549 tests OK
历史遗留失败：0
新增失败：0
Release Audit：PASS
```

## 最终审计边界

最终确定性门禁不会调用：

```text
真实 GLM
Prometheus MCP
Netmiko MCP
OPS ES API
Elasticsearch MCP Adapter
咚咚通知
生产写操作
```

最终审计要求：

```text
problems = []
warnings = []
external_calls 全部为 false
Git worktree clean
Governance corrupt_total = 0
```

## Governance 运行目录

```text
data/governance/incident_memory
data/governance/signals
data/governance/proposals
data/governance/replays
data/governance/reports
data/governance/audits
data/governance/backfill
```

这些运行时数据不提交 Git。

## ELK 当前状态

```text
Elasticsearch：8.4.3
采集：Logstash
展示：Kibana
告警：ElastAlert2
告警语义：单条事件、无恢复状态
查询边界：OPS ES API
正式 MCP 候选：FastMCP
```

在正式 Logs Evidence 版本批准前：

```text
source = logs
status = not_available
```

该状态不能解释为“未发现日志异常”。

## 当前下一步

```text
1. 提交并推送 v11.1 Batch E
2. 在干净 main 上执行最终 post-commit Release Acceptance
3. 同步 ChatGPT 项目文档和项目指令
4. 进入 v12 Controlled Multi-Agent / RCA
```

## 历史失败说明

已清理的 28 个失败是在 Batch 10 全量测试中发现、并在 Batch 10 修改前已经存在的历史遗留问题。不得表述为“Batch 9 导致的失败”。Batch 9 commit 只是最近对照基线。
