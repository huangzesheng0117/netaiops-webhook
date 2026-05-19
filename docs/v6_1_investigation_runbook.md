# NetAIOps webhook v6.1 Investigation Session 运维手册

## 1. 阶段定位

当前阶段：v6.1。

v6.1 参考 ADAPT 的受控调查状态机思想，为每个 request_id 建立 Investigation Session，记录告警从接入、标准化、分析、计划、安全策略校验、执行、判错、复盘到通知的调查时间线。

v6.1 只做状态记录和审计增强，不启用自适应补充取证，不改变现有 v5 生产执行链路。

## 2. 新增能力

v6.1 新增以下能力：

- netaiops/investigation_state.py
- netaiops/investigation_policy.py
- tools/show_investigation_session.py
- tools/regress_investigation_sessions.py
- tools/regress_v6_1.sh
- tests/test_investigation_state.py
- tests/test_investigation_policy.py
- /v6/investigation/{request_id}
- /v6/investigation/{request_id}/build
- data/investigation/*.investigation.session.json

## 3. Investigation Session 阶段

标准阶段顺序如下：

    received
    normalized
    analyzed
    planned
    policy_checked
    dispatched
    executed
    judged
    reviewed
    notified

## 4. 状态含义

received：告警接入。

normalized：事件标准化。

analyzed：LLM 初步分析。

planned：只读取证计划生成。

policy_checked：安全策略校验。

dispatched：执行请求生成。

executed：MCP / Runner 执行。

judged：执行结果判错。

reviewed：证据复盘生成。

notified：通知发送。

## 5. 安全边界

v6.1 不启用自适应补充取证。

v6.1 不允许 LLM 自由生成设备命令。

v6.1 不绕过 family_registry、capability_registry、platform_command_matrix、safety_policy、output_judger。

设备侧动作仍然坚持只读取证。

v6.1 adaptive 固定为：

    enabled: false
    max_extra_rounds: 0
    max_extra_commands: 0

## 6. 常用运维命令

进入环境：

    cd /opt/netaiops-webhook
    source venv/bin/activate

查看单个 request_id 的 Investigation Session：

    python tools/show_investigation_session.py --rid <request_id> --build

查询 v6.1 API：

    curl -s "http://127.0.0.1:18080/v6/investigation/<request_id>" | python -m json.tool

批量回归最近 10 条 request_id：

    python tools/regress_investigation_sessions.py --limit 10

执行 v6.1 一键回归：

    bash tools/regress_v6_1.sh

服务健康检查：

    curl -s http://127.0.0.1:18080/health | python -m json.tool

## 7. 验收标准

v6.1 收尾验收标准：

- compileall 通过
- output_judger 单元测试通过
- evidence_facts 单元测试通过
- investigation_state 单元测试通过
- investigation_policy 单元测试通过
- regress_investigation_sessions.py 批量回归 FAIL=0
- /health 返回 status=ok
- /v6/investigation/{request_id} 能返回 JSON
- 已完成闭环的 request_id 应包含 notified 阶段
- 未完成闭环或历史中间态 request_id 可显示 in_progress，并允许 notified missing warning

## 8. 已知边界

部分历史 request_id 只有 received、normalized、analyzed、planned、policy_checked，未进入 dispatched、executed、reviewed、notified 阶段时，session_status 会显示 in_progress。

这类情况在 regress_investigation_sessions.py 中会作为 warning 展示，不作为失败处理。

## 9. 下一阶段

v6.1 收尾后，下一阶段进入 v6.2。

v6.2 参考 MCPyATS，目标是建立 Tool Registry 与 Parser Registry，优先解决 CLI 输出结构化问题。
