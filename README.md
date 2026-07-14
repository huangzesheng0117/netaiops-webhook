# NetAIOps Webhook

NetAIOps Webhook 是面向网络运维告警场景的 AI 分析与治理平台。平台接收 Alertmanager 等来源的告警，结合确定性分类、Skill / Playbook、Prometheus 指标、Netmiko MCP 设备只读取证、GLM 5.2、Review、Evidence Hub、咚咚通知和 v11 Governance，输出可追溯、可回放、可审计的分析结果。

## 当前生产基线

| 项目 | 当前值 |
|---|---|
| 项目目录 | `/opt/netaiops-webhook` |
| systemd 服务 | `netaiops-webhook.service` |
| 服务端口 | `18080` |
| Git 分支 | `main` |
| v10 发布 commit | `339e857` |
| v11 功能收口 commit | `0f60c91da69b732aec23032809715b9d5dfd762c` |
| v11.1 Schema 兼容 commit | `9dfe1d76e7091912d1e21daca24a22122af7746b` |
| v11.1 测试契约对齐 commit | `16924700d873c01136da9b6e37579f806d0bdd98` |
| v11.1 流量 / DCI 修复 commit | `2aa7b77169c0150c2f32bd2652152cd3d756ede0` |
| 服务版本 | `11.0.0-v11-learning-governance` |
| 生产 LLM | `glm-5.2` |
| Netmiko MCP | 已接入，地址由生产配置管理 |
| Prometheus MCP | 已接入，地址由生产配置管理 |
| AI 通知 | universal card |
| v10 Release Audit | `PASS` |
| v11 Release Audit | `PASS` |
| v11 专项测试 | `269 tests OK` |
| 全仓库测试 | `549 tests OK` |
| 历史遗留失败 | `0` |
| 下一阶段 | `v12 Controlled Multi-Agent / RCA` |

## 当前两条链路

### AI 分析主链路

```text
Alertmanager / 未来 ElastAlert2
→ Webhook
→ Raw / Normalized / request_id
→ GLM 5.2 初步分析
→ Family / Skill / Playbook
→ Prometheus MCP
→ Netmiko MCP（只读）
→ Execution
→ Review
→ Evidence Hub
→ AI universal card
→ Governance Sidecar
```

### 轻量告警链路

```text
vmalert / Alertmanager
→ 轻量格式化
→ firing / resolved 卡片
→ firing 一小时限流
→ resolved 清除 firing 限流
```

轻量链路不调用 GLM，不调用 MCP，不进入 Review，也不创建 AI Evidence Hub 或 Governance request。

## v10 已完成

- Evidence Hub schema、writer、API、UI、回填和回归；
- Prometheus Evidence 展示；
- 设备命令成功、失败、失败原因和 raw output 展示；
- slim summary / slim text；
- AI universal card；
- firing / resolved 状态；
- 轻量链路与 AI 主链路隔离；
- 轻量 firing 一小时限流和 resolved 清限流；
- GLM 5.2 健康检查兼容；
- v10 Release Audit PASS。

## v11 已完成

v11 未重构 v10 告警主链路，而是在现有 request_id、Evidence Hub 和运行产物之上完成旁路治理系统：

```text
Existing Request Artifacts
→ Governance Artifact Reader
→ Incident Memory
→ Learning Signal
→ Draft Proposal
→ Offline Replay / Before-After
→ Learning Report
→ Release Audit
→ Governance API / UI
```

v11 核心交付：

- Incident Memory；
- Learning Signal；
- Draft Proposal；
- Offline Replay 和 Before / After；
- Learning Report；
- Release Audit；
- Governance API；
- Governance UI；
- Sidecar Integration；
- Backfill、Canary 和 Regression；
- Repository Gate；
- Release Acceptance。

v11 长期安全边界：

- Proposal 不自动修改正式 Skill / Playbook；
- 不自动增加或执行设备命令；
- 不绕过 Safety Policy；
- 不自动 Git commit / push；
- Replay 默认不调用真实 GLM、Prometheus MCP、Netmiko MCP 或咚咚；
- 不将 token、secret、完整设备输出或完整敏感日志复制进 Memory。

## v11.1 Historical Regression Cleanup

v11.1 已完成：

```text
Batch B：legacy / current Skill Schema 兼容
Batch C：测试与当前 v9 Skill 契约对齐
Batch D：流量异常、互联网突降和 DCI Playbook 覆盖
Batch E：严格零失败 Release Acceptance 与最终审计
```

历史回归清理结果：

```text
历史遗留失败：28 → 0
v11 专项测试：269 tests OK
全仓库测试：549 tests OK
新增失败：0
Release Audit：PASS
```

28 个失败是在 Batch 10 全量测试中发现、且在 Batch 10 修改前已经存在的历史遗留问题；不归因于 Batch 9、Batch 10 或 Batch 11。

## v11 Final Release Acceptance

最终门禁采用严格零失败策略：

```text
known_failure_policy = strict-zero-regressions-v2
expected_count = 0
observed_count = 0
new_failure_count = 0
full repository return code = 0
Release Audit = PASS
```

最终验收默认不调用真实 GLM、Prometheus MCP、Netmiko MCP、OPS ES API、Elasticsearch MCP Adapter 或咚咚通知。

v11 Governance 入口：

| 入口 | 作用 |
|---|---|
| `GET /governance/health` | Governance API 健康检查 |
| `GET /governance/summary` | Governance 汇总 |
| `GET /governance/memories` | Incident Memory |
| `GET /governance/signals` | Learning Signals |
| `GET /governance/proposals` | Draft Proposals |
| `GET /governance/replays` | Offline Replays |
| `GET /governance/reports` | Learning Reports |
| `GET /governance/audits` | Release Audits |
| `GET /governance-ui` | Governance 只读 UI |

## 版本路线

已冻结：

```text
v11：Learning Loop / Governance
v12：Controlled Multi-Agent / RCA
     Deterministic Evidence Mode
```

暂定，尚未冻结：

```text
v13：Evidence Capability Foundation
v14：ELK Logs Evidence
v15：Policy-Constrained Evidence Planning
```

## 项目结构

```text
.
├── app.py
├── agent_runner/
├── netaiops/
├── playbooks/
├── skills/
├── tools/
├── tests/
├── testdata/
├── docs/
├── config/
├── config.example.yaml
├── requirements.txt
├── VERSION
└── README_STATUS.md
```

以下运行时目录不提交 Git：

```text
data/
logs/
backup/
venv/
config.yaml
config/*.env
```
