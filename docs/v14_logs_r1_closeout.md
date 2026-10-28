# v14 Logs Evidence R1 — Release Closeout Evidence

> 2026-10-27；本文件记录截至本次 Release Candidate 的可核验事实。**尚未 Git Closeout**，不得将本文件本身视为 commit/push 完成证明。

## 1. 版本与身份

- repository: `git@github.com:huangzesheng0117/netaiops-webhook.git`；branch: `main`。
- 准备阶段 HEAD/origin/main/live remote main: `5f5b18bb018770b23f51d2504893f4969686d4d6`（真实 commit 后须以 Post-Commit Audit 更新）。
- `VERSION` 仍可能为 `13.0.0-v13-production-ownership`；不能仅凭该常量判断 v14。
- W1/W2 已独立 Closeout，R1-A/B/C 已完成；不得重放 W2 Controller、10002 查询或旧 Canary。
- R1-C 生产配置：store/real_query/analysis/review/rca/card 已开启；以生产配置及最新 Runtime Evidence 为准。

## 2. R1-D 验收证据

- Synthetic Canary ID: `r1-d-synthetic-glm-card-20261022-json02`。
- Execution request ID: `r1-d-synthetic-exec-20261022-json02`。
- 真实 GLM-5.2 attempts = **1**，AI Card attempts = **1**，发送回执 **CONFIRMED**，目标群组 **62800**。
- 卡片标记：`SYNTHETIC TEST / 非真实故障`。合成交换机告警及模拟日志**不是**真实生产告警或真实 ES 正向取证的替代证明。
- successful Canary Result ZIP SHA-256：`011123dc14ae112075b838bb59cc193d068fb0a7b936ab1973410af78c539c0e`。
- GLM 旧失败身份、旧响应、checkpoint/fence 保留，未重放；本次 Release Prepare 不触发 GLM/Card/MCP。

## 3. 正式回归

- 持久化修订范围：`tests/test_v12_placeholder_agents.py` 和 `tests/test_v12_static_planner_agent.py`，仅隔离历史 v12 frozen fixture 的配置；不修改生产 Logs/Planner 逻辑。
- 正常生产源码下的 `unittest` 定向：Placeholder **18/18**、Static Planner **30/30**、R1-A **10/10**。
- 正常全量回归：**1464/1464 PASS**；无失败、错误和跳过。
- 结果文件 SHA-256：`d4fe3171df556747ddd21231366047282d83a0da21dc57a3c7040d0bd74b9bd8`。Private test logs 必须按恢复报告中的 SHA 对应。
- 该回归发生在最终提交之前；Git 提交后的源码/运行审计仍不可省略。

## 4. Health 与已知限制

- Webhook service 已在此前 Release Gate 验证为 active；`/health`、`/evidence-ui`、`/governance-ui` HTTP **200/200/200**。
- Governance UI 本次首字节/总耗时约 **25.634 秒**，属于 **SLOW_WARNING**；HTTP 200 不等于性能正常。仍需单独跟踪性能优化，不得记录成已修复。
- DCI 专线延迟真实告警的日志 selector 存在过度过滤风险：`device_name` 被写成疑似 exporter endpoint、`severity=critical` 与告警标题同时作为过滤；实际 COMPLETE `no_data`。**真实 ES 日志正向命中并进入 RCA 尚未证明**，不得标记为通过。
- `no_data` 不得等同于正常；保留 provisional/complete/partial/failed/not_available 区别。
- RCA 不能自行触发 10002/10004；禁止任意 CLI/PromQL/DSL 或设备写操作。

## 5. Git/生产治理

- 生产 `config/v14_logs_w1.yaml`、Secret、data/、logs/、venv/、历史 State/Fence 与私有响应**永不提交**。
- Git 1.8.3.1 环境不使用 `git -C`；porcelain 两列原样解析，精确路径暂存，不使用 `git add .`、`git add -A`、force push 或 hard reset。
- 本次 Release 文档新建后候选共 **12 路径**（原 11 个 + 本文档）。所有 diff 和 Secret Scan 必须人工最终复核。
- `git commit/push` 需要**单独明确批准**；commit 已成功而 push 失败只能 push-only；push 成功而 post-audit 失败只能 post-audit-only。
- 提交成功后须核对 HEAD=origin/main=live_remote、worktree clean、服务和 Health，并生成独立 Post-Commit Audit。

## 6. 尚未闭合的外部项目文档

`00/02/03/07/08/12/13` 项目活跃母版与 `SOURCE_ARCHIVE` 不全位于此 Git 仓库。需要按其真实原文件同步上述事实，不得编造源中缺失的历史文件，也不得以本文件覆盖旧证据。
