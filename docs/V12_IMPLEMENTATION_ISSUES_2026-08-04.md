# NetAIOps Webhook v12 实施问题账本

> 文档日期：2026-08-04
> 状态：Batch Q V2 发布候选；用于 v12 完结后的项目文档增量更新。

## 1. 目的

本文档保留 v12 Batch A～Q，尤其 Batch O、P、Q 实施期间出现的真实问题、根因、修复方式和长期门禁。它不是替代原实施总纲的摘要，也不删除历史失败分支。

## 2. Batch O

### 2.1 卡片字段顺序假阳性门禁

- 现象：文本扫描将合法字段顺序判为违规。
- 根因：门禁依赖脆弱字符串位置，而非解析后的结构。
- 修复：使用结构化对象和已知假阳性回归用例。
- 长期门禁：Release Gate 不得仅依赖源码字符串顺序。

## 3. Batch P1

### 3.1 datetime 无法 JSON 序列化

- 现象：Canary 结果包含 datetime，写 JSON 时失败，后续文件缺失。
- 根因：运行结构未统一执行 JSON mode 序列化。
- 修复：输出进入持久化前统一标准化。
- 门禁：所有合同均必须稳定 JSON 序列化。

### 3.2 引用不存在的测试模块

- 现象：Runner 调用了仓库中不存在的 test_v12_agent_trace。
- 根因：命令基于预期文件名而非真实仓库检查。
- 修复：执行前检查测试文件存在、真实 import，再调用 discover。

### 3.3 生产 CLI 缺少项目根 PYTHONPATH

- 现象：直接执行 scripts/... 时找不到 netaiops 包。
- 根因：只验证模块 import，没有验证真实 CLI 启动方式。
- 修复：CLI 自带项目根 Bootstrap，调用侧同时设置 PYTHONPATH。
- 门禁：每个生产 CLI 必须从项目根以外目录执行最小调用。

### 3.4 自然告警 Gate 不适配稳定生产

- 现象：生产告警少，completed_count 长期为 0。
- 根因：Gate 把自然告警数量作为唯一进度条件。
- 修复：复用历史 Artifact 建设隔离 Controlled Full-Chain Simulation。
- 门禁：发布验收不能依赖不可控自然事件。

### 3.5 Family 分类层级不一致

- 现象：模拟入口期待旧 Family，最终分层分类器输出新 Family。
- 根因：测试冻结了过时的分类结果。
- 修复：以生产最终分类器为权威并加入回归。

### 3.6 Alertmanager endsAt 哨兵值

- 现象：firing 告警 endsAt=0001-01-01T00:00:00Z 被当成真实结束时间，导致时间范围反转。
- 根因：未识别 Alertmanager 未结束哨兵时间。
- 修复：firing 哨兵 endsAt 视为未设置。

## 4. Batch P2 规划与运行

### 4.1 P2 被错误拆分为 P2-A～P2-E

- 现象：原本一批 P2 被升级成多个正式 Batch。
- 根因：把内部安全阶段误当成版本层级。
- 修复：恢复 P2 单批闭环，一次提交。

### 4.2 旧 Git 不支持 git -C

- 现象：脚本在服务器旧 Git 上失败。
- 修复：统一先 cd 项目目录，不依赖 git -C。

### 4.3 Netmiko Runtime 缺少 MCP_HELPER_CMD

- 现象：真实 Device Collector 无法启动 Helper。
- 根因：测试环境和生产运行环境变量不一致。
- 修复：显式读取既有 Helper 合同并在 Preflight 验证。

### 4.4 target_scope 被 exporter hostname/instance 污染

- 现象：Prometheus 标签被误当设备执行目标。
- 修复：设备目标只接受安全策略批准的私网设备标识和接口字段。

### 4.5 状态目录创建顺序错误

- 现象：在 mkdir 前写入状态文件。
- 修复：所有状态输出先创建 0700 目录，再原子写入。

### 4.6 real_call_count=0 被转换为 -1

- 现象：使用 value or -1，合法零值被覆盖。
- 修复：显式区分 None 和 0。
- 门禁：计数、状态码等零值不得使用 truthy fallback。

### 4.7 Historical Replay 时间语义错误

- 现象：历史 Evidence 用当前时间判断，误判 stale。
- 修复：Replay 显式使用事件参考时间，不用 wall clock。

### 4.8 GLM 30 秒 ReadTimeout

- 现象：V6 在约 30 秒超时。
- 修复方向：记录 request_sent、response_received、latency、error_type。

### 4.9 2400 tokens 被 reasoning 消耗

- 现象：V7 HTTP 200，reasoning_content 很长，content 为空，finish_reason=length。
- 修复：压缩 Prompt，保留足够输出预算，记录 reasoning/content 长度。

### 4.10 V8 120 秒 ReadTimeout

- 现象：Prompt 7657 字符、max_tokens=8192，等待 120 秒仍未收到完整响应。
- 修复：Prompt 压缩至约 2917 字符，read timeout 有界放宽，retry=0。
- 最终结果：GLM 约 23.6 秒返回，HTTP 200，finish_reason=stop。

### 4.11 错误信息不透明

- 现象：主日志只显示 continued GLM RCA failed。
- 修复：持久化 glm_attempt、rca_validation、failure_report，并输出阶段、HTTP、finish_reason、长度和解析状态。

## 5. 状态收敛与源码采集

### 5.1 Secret 扫描 V1 误报

- 现象：变量名包含 password/api_key/secret 即被硬阻断。
- 根因：低精度启发式被错误标记为高置信。

### 5.2 Secret 扫描 V2 未区分测试上下文

- 现象：tests 中故意构造的 credential URL 被当成真实泄密。
- 修复：同时考虑内容格式和文件上下文；测试 Fixture 降为 review；私钥等确定材料仍阻断。

### 5.3 失败前未写 latest 指针

- 现象：采集失败后无法直接定位报告目录。
- 修复：输出目录创建后立即写 latest，失败写 FAILURE.txt。

## 6. Final Continuation 与真实环境闭环

### 6.1 V8 历史证明与 Final Dry-run 文件重名

- 现象：Final 运行合法覆盖同名文件，第二次 prepare 误判被篡改。
- 修复：V8 来源证明改为 v8_source_*；Final 当前结果使用独立名称。

### 6.2 Preflight 非幂等

- 现象：prepare 和 preflight 重复执行失败。
- 修复：连续运行两次 Prepare/Planner/Judge/Preflight，均必须通过。

### 6.3 V7/V8 错误文案不一致

- 现象：实际来源 V8，错误消息写 V7。
- 修复：错误输出必须与真实来源一致。

### 6.4 evaluate_v8_gate 变量遮蔽

- 现象：source 先表示字典，后被 EvidenceSource 枚举覆盖，最终调用 .get 触发 AttributeError。
- 修复：使用 source_checkpoints 和 evidence_source 两个语义变量。
- 门禁：Gate 必须用真实 Pydantic 合同对象执行两次。

### 6.5 大 Stage 局部 Fail-fast

- 现象：Fake 完整链路任一步异常后，后续 Trace/Governance/幂等检查不执行。
- 修复：拆分独立诊断阶段，集中输出 violations。

### 6.6 V3 真实 CLI 再次缺少项目根路径

- 现象：Preflight 全绿，run-real 在 import 阶段失败。
- 根因：问题账本已有同类问题，但交付门禁未执行真实 CLI。
- 修复：Runner Bootstrap + PYTHONPATH 双保险；从 /tmp 清空 PYTHONPATH 执行 status/preflight/gate。

### 6.7 glm_called 字段语义错误

- 现象：导入失败但报告 glm_called=true。
- 修复：拆分 execution_requested、runner_started、import_passed、attempt_file_created、request_sent、response_received。

## 7. Git Closure

### 7.1 旧 Git 不支持 git remote get-url

- 现象：Git Closure Audit 在读取 origin URL 时失败。
- 根因：未落实旧 Git 兼容规则，且 stderr 被抑制。
- 修复：统一使用 git config --get remote.origin.url；保留原始错误上下文。

### 7.2 提交范围

- P2 最终精确提交 14 个文件。
- commit：6a7c5779be83ac6e0276821eb1d7a70c78ded101。
- 提交信息：v12: complete P2 real canary and production RCA。

## 8. 长期实施方法

- 真实环境可作为主要集成和验收环境；连续可用性不是当前约束。
- 允许维护过程中停止服务，但必须精确备份和可恢复。
- 确定性链路在真实外部调用前完整跑通两次。
- 安装、Preflight、真实运行、验证、回退必须分离。
- 普通代码问题尽量集中输出 violations；Secret、基线漂移、并发写入等安全问题立即停止。
- 不能用 bash -n、py_compile、单函数测试代替真实入口和完整状态机测试。
- 所有生产 CLI 必须用实际启动方式执行。
- 旧 Git 兼容必须作为固定门禁。
- 不使用 git add .、git add -A、git reset --hard、git clean -fd。
- 不自动 commit/push。

## 9. Batch Q V1

### 9.1 README 和 README_STATUS 末尾空行

- 现象：`git diff --check` 报告 new blank line at EOF。
- 根因：Section 自带结尾换行，外层拼接逻辑再次增加换行。
- 修复：统一使用 `rstrip() + "\n\n" + section.strip() + "\n"`，并固定检查文件只保留一个结尾换行。

### 9.2 config.example 被错误改为 primary

- 现象：历史安全默认测试要求 `enabled=false`、`mode=shadow`、`rca.enabled=false`，Batch Q V1 却直接把示例配置改为生产启用状态。
- 根因：混淆了安全示例配置和生产运行时配置。
- 修复：`config.example.yaml` 保持安全默认；正式 primary 只写入被 Git 忽略的 `config/v12_primary.yaml`。

### 9.3 Batch O 版本冻结测试未迁移

- 现象：Batch Q 已升级 VERSION，但历史回放测试仍固定要求 v11 版本。
- 根因：Batch O 的阶段性边界没有在 Batch Q 正式发布时增量迁移。
- 修复：测试改为验证 Batch Q 正式目标版本，同时保留历史回放本身不执行写操作的边界。

### 9.4 Master Runner 被整体替换并破坏 Batch A 合同

- 现象：Batch A 冻结安全合同和确认变量清理测试失败。
- 根因：用新模板整体覆盖旧 Master Runner，而不是以旧文件为母版增量扩展。
- 修复：保留原 Batch A Runner 全文，只追加独立 Batch Q dispatch。

### 9.5 Master Runner 被错误归类为新增文件

- 现象：`tools/v12_master_runner.txt` 在基线已跟踪，却被列入 NEW_TRACKED。
- 后果：安装前未备份，自动回退时被直接删除，工作区留下 D 状态。
- 修复：将其纳入 MODIFIED_TRACKED，固定 Git Blob 基线并进入精确备份。

### 9.6 Preflight 失败后自动回退

- 现象：确定性 Preflight 失败后候选现场被自动恢复，且回退自身引入文件删除问题。
- 根因：沿用高可用优先模式，不符合当前“最快收敛、允许停服”的实施目标。
- 修复：V2 在 Preflight、Activate、Verify 失败时保留候选代码和状态目录，不自动回退；仅显式 `CONFIRM_ROLLBACK=YES` 才回退。

### 9.7 全仓库测试执行时机过晚

- 现象：V1 只在激活后的 Release Acceptance 才计划运行全仓库测试。
- 风险：非 v12 测试中的版本或合同冲突会在正式激活后才暴露。
- 修复：V2 将全仓库测试前移到服务停止状态下的确定性 Preflight。

### 9.8 v10 基线卫生测试仍冻结 v11 版本

- 现象：全仓库测试中的 `test_v10_baseline_hygiene` 仍将当前 VERSION 固定为 v11。
- 根因：历史基线卫生测试同时承担“当前版本和当前文档对齐”职责，但 Batch Q V1 未迁移该当前版本常量。
- 修复：保留测试的配置、依赖和 Secret 门禁，只把当前版本与当前主版本断言迁移到 v12。

## 10. Batch Q V2 固定门禁

- `config.example.yaml` 安全默认不变。
- `config/v12_primary.yaml` 才是正式启用配置，权限 0600，不提交 Git。
- Master Runner 以 Batch A 原文件为母版增量追加 Batch Q。
- `tools/v12_master_runner.txt` 必须按 modified tracked 精确备份和恢复。
- README、README_STATUS 和所有提交文本只允许一个结尾换行。
- 定向测试、全部 v12、全仓库测试均在正式激活前执行。
- Preflight 至少包含两轮确定性合同检查。
- Preflight 失败不自动回退，保留候选现场和完整 violations。
- 提供独立 rollback-drill，验证 install→rollback→worktree clean。
- 不自动 commit/push。
