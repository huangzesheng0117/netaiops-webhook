# NetAIOps Webhook

NetAIOps Webhook 是面向网络运维告警场景的 AI 分析平台。平台接收 Alertmanager 等来源的告警，结合确定性分类、Skill / Playbook、Prometheus 指标、Netmiko MCP 设备只读取证、本地 LLM、Review、Evidence Hub 和咚咚通知，输出可追溯的告警分析结果。

## 当前生产基线

| 项目 | 当前值 |
|---|---|
| 项目目录 | `/opt/netaiops-webhook` |
| systemd 服务 | `netaiops-webhook.service` |
| 服务端口 | `18080` |
| Git 分支 | `main` |
| v10 发布 commit | `339e857` |
| Batch 10 Integration commit | `302809219e4993fe392d4c5fbb590b1486cf32d2` |
| v11 收口 commit | Batch 11 当前提交 |
| 服务版本 | `11.0.0-v11-learning-governance` |
| 生产 LLM | `glm-5.2` |
| Netmiko MCP | 已接入，地址由生产配置管理 |
| Prometheus MCP | 已接入，地址由生产配置管理 |
| AI 通知 | universal card |
| 下一阶段 | v11 文档同步后进入 `v11.1 Historical Regression Cleanup` |

v10 Release Audit 已通过。原 `qwen3-max` 后端失效后，生产模型已切换为 `glm-5.2`；标准 chat smoke 至少使用 1200 completion tokens，并记录 reported model 和 finish reason。

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
```

### 轻量告警链路

```text
vmalert / Alertmanager
→ 轻量格式化
→ firing / resolved 卡片
→ firing 一小时限流
→ resolved 清除 firing 限流
```

轻量链路不调用 GLM，不调用 MCP，不进入 Review，也不创建 AI Evidence Hub request。

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
→ Proposal
→ Offline Replay / Before-After
→ Learning Report
→ Release Audit
→ Governance API / UI
```

v11 核心交付：

- Incident Memory；
- Learning Signal；
- Proposal；
- Offline Replay 和 Before / After；
- Learning Report；
- Release Audit；
- Governance API；
- Governance UI；
- Backfill、Canary 和 Regression。

v11 明确禁止：

- 自动修改正式 Skill / Playbook；
- 自动增加或执行设备命令；
- 绕过 Safety Policy；
- 自动执行 Proposal；
- 自动 Git commit / push；
- Replay 默认调用真实 GLM、Prometheus MCP、Netmiko MCP 或咚咚；
- 将 token、secret、完整设备输出或完整敏感日志复制进 Memory。

## v11 Release Acceptance 状态

v11 Learning Loop / Governance 功能建设已经完成，当前 Release Acceptance 采用已冻结的历史失败集合门禁：

```text
v11 定向测试：必须全部通过
Batch 10 Integration：必须通过
全仓库测试：必须实际执行
已知历史遗留失败：严格等于 28
Batch 11 新增失败：必须为 0
Release Audit：WARNING
```

这 28 个是 Batch 10 全量测试集中发现、且在 Batch 10 修改前已经存在的历史遗留测试失败；不归因于 Batch 9，也不归因于 Batch 10。它们将在文档同步后的 `v11.1 Historical Regression Cleanup` 中独立修复。修复完成并实现全仓库测试归零后，Release Audit 才升级为 PASS。

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
├── app.py                         # FastAPI 主入口
├── agent_runner/                  # MCP 执行侧桥接
├── netaiops/                      # 核心业务模块
├── playbooks/                     # 确定性告警处理模板
├── skills/                        # 网络取证知识与边界
├── tools/                         # 构建、验证、回归和审计工具
├── tests/                         # 单元测试和回归测试
├── testdata/                      # 测试样例
├── docs/                          # 历史版本文档和运行手册
├── config/                        # 非敏感配置片段；真实 env 不入 Git
├── config.example.yaml            # 无敏感信息的配置示例
├── requirements.txt               # 直接应用依赖版本
├── VERSION                        # 服务版本
└── README_STATUS.md               # 当前状态摘要
```

以下运行时目录不提交 Git：

```text
data/
logs/
backup/
venv/
```

## 配置与启动

生产配置位于：

```text
/opt/netaiops-webhook/config.yaml
```

该文件包含环境相关配置，不提交 Git。仓库中的 `config.example.yaml` 只能作为无敏感信息的结构示例。

生产服务由 systemd 托管：

```bash
cd /opt/netaiops-webhook
source venv/bin/activate
sudo systemctl status netaiops-webhook.service --no-pager
curl -fsS --max-time 5 http://127.0.0.1:18080/health | python -m json.tool
```

`/health` 只证明 Web 服务可用，不单独证明 GLM、MCP 或通知可用。模型验证必须区分 `/models`、chat smoke 和真实告警回归。

## 开发与验证

安装直接应用依赖：

```bash
python -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
```

基础验证：

```bash
python -m compileall -q app.py netaiops agent_runner tools tests
python -m unittest -v   tests.test_notification_summary_builder   tests.test_ai_analysis_card_builder   tests.test_ai_analysis_card_sender   tests.test_notifier_ai_card_mode   tests.test_notifier_slim_mode   tests.test_llm_health_glm_compat
git diff --check
```

服务变更后必须循环等待健康检查，不能只依赖固定 sleep：

```bash
sudo systemctl restart netaiops-webhook.service
for i in $(seq 1 45); do
  if curl -fsS --max-time 5 http://127.0.0.1:18080/health; then
    echo
    echo "[OK] service ready"
    break
  fi
  sleep 2
done
```

## 主要入口

| 入口 | 作用 |
|---|---|
| `GET /health` | Web 服务健康检查 |
| `POST /webhook/alertmanager` | AI 分析主入口 |
| `POST /webhook/elastic` | Elastic 基础入口，正式 Payload 契约待确认 |
| `POST /light-alert/alertmanager` | 轻量告警入口 |
| `GET /evidence` | Evidence Hub 列表 |
| `GET /evidence/<request_id>` | Evidence Hub 详情 API |
| `GET /evidence-ui` | Evidence Hub UI |
| `GET /evidence-ui/<request_id>` | 指定 request 详情页 |

## 安全与 Git 规则

- 设备自动命令只允许只读；
- 禁止配置变更、clear、debug、reload、shutdown / no shutdown；
- LLM 不直接控制设备执行；
- 生产 `config.yaml`、env、token、secret、data、logs、backup、venv 不提交 Git；
- 禁止无边界使用 `git add .` 或 `git add -A`；
- 每个 Batch 完成代码、测试、运行级验证和回归后精确暂存；
- 工作区干净时不创建空提交；
- 提交后回退使用 `git revert`，不改写 `main` 历史。

## 运行证据优先级

```text
最新完整日志、截图和命令输出
→ 生产机完整文件和 request 目录
→ GitHub main
→ 项目 Markdown 文档
→ 历史记忆
```

如果运行时证据与文档冲突，以运行时证据为准，并同步更新文档。
