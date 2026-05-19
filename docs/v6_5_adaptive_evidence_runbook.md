# NetAIOps webhook v6.5 Skill 约束下的自适应取证运维手册

## 1. 阶段定位

当前阶段：v6.5。

v6.5 的目标是在 v6.3 Skill 库和 v6.4 Skill Runtime 的基础上，建立 Skill 约束下的自适应取证能力。

当前 v6.5 只启用 dry-run 规划，不真正执行补充取证命令。

## 2. 当前已完成能力

v6.5 已新增以下能力：

- netaiops/adaptive_evidence_policy.py
- netaiops/adaptive_evidence_planner.py
- netaiops/adaptive_session_context.py
- netaiops/adaptive_evidence_api.py
- tools/plan_adaptive_evidence.py
- tools/show_investigation_adaptive_context.py
- tools/simulate_adaptive_missing_evidence.py
- tools/validate_adaptive_evidence_api.py
- tools/regress_v6_5_adaptive_missing_sample.sh
- tools/regress_v6_5.sh
- tests/fixtures/adaptive_missing_facts/
- tests/test_adaptive_evidence_policy.py
- tests/test_adaptive_evidence_planner.py
- tests/test_adaptive_session_context.py
- tests/test_adaptive_missing_facts_sample.py
- tests/test_adaptive_evidence_api.py

## 3. 核心原则

v6.5 自适应取证必须满足以下原则：

- 必须命中 Skill。
- 只能使用 Skill allowed_tools 中声明的 Tool。
- 只能使用 Skill allowed_capabilities 中声明的 capability。
- 只能使用 commands.yaml 中声明的命令模板。
- Tool 必须是 readonly。
- candidate 必须 readonly=true。
- 禁止 configure terminal、shutdown、clear counters、reload 等危险命令。
- 当前阶段 dispatch_enabled 必须为 false。
- 当前阶段 adaptive_execution_enabled 必须为 false。
- 当前阶段只生成 dry-run plan，不真实执行命令。

## 4. 当前模式

当前模式固定为：

    skill_constrained_dry_run

典型字段：

    stage: v6.5
    mode: skill_constrained_dry_run
    dispatch_enabled: false
    dry_run_only: true
    readonly_only: true
    policy_verdict: pass
    policy_violations: []

## 5. 自适应取证计划

针对真实 request_id 生成 adaptive plan：

    python tools/plan_adaptive_evidence.py --rid <request_id> --write

查看某个 request_id 的 adaptive context：

    python tools/show_investigation_adaptive_context.py --rid <request_id> --write-plan-file

计划文件位置：

    data/adaptive_plans/<request_id>.adaptive.plan.json

## 6. 缺失 facts 模拟样例

v6.5 已补充脱敏模拟样例：

    tests/fixtures/adaptive_missing_facts/

该样例模拟 review facts 缺少接口状态、速率、错误计数和聚合信息。

执行回归：

    bash tools/regress_v6_5_adaptive_missing_sample.sh

期望生成 3 条 dry-run 候选命令：

    show interfaces TenGigabitEthernet1/0/1
    show interfaces TenGigabitEthernet1/0/1 counters errors
    show etherchannel summary

这些命令不会被真实执行，只作为候选计划输出。

## 7. HTTP API

v6.5 新增只读 API：

查看真实 request_id 的 adaptive plan：

    curl -s "http://127.0.0.1:18080/v6/adaptive/plan/<request_id>" | python -m json.tool

查看缺失 facts 模拟样例：

    curl -s "http://127.0.0.1:18080/v6/adaptive/simulate/missing-facts" | python -m json.tool

校验 API：

    python tools/validate_adaptive_evidence_api.py --rid <request_id>

## 8. 一键回归

执行 v6.5 回归：

    bash tools/regress_v6_5.sh

指定 request_id：

    RID=<request_id> bash tools/regress_v6_5.sh

## 9. 验收关键词

v6.5 验收时重点看：

    Ran 83 tests
    OK

    "stage": "v6.5"
    "mode": "skill_constrained_dry_run"
    "dispatch_enabled": false
    "dry_run_only": true
    "readonly_only": true
    "policy_verdict": "pass"
    "policy_violations": []

    "simulate_candidate_count": 3

    show interfaces TenGigabitEthernet1/0/1
    show interfaces TenGigabitEthernet1/0/1 counters errors
    show etherchannel summary

    v6.5 missing-facts sample regression PASS
    v6.4 regression PASS
    v6.5 regression PASS
    status: ok

## 10. 当前边界

v6.5 当前仍然只做 dry-run 规划。

v6.5 不真实执行 adaptive candidates。

v6.5 不改变现有 MCP 主执行链路。

v6.5 不让 LLM 自由生成命令。

v6.5 当前主要围绕 interface_utilization_high Skill。

## 11. 下一阶段

v6.5 收尾后，下一阶段进入 v6.6。

v6.6 目标是固化回归、发布和维护体系，包括：

- 整合 v6.1 到 v6.5 全量回归入口。
- 补充生产发布检查清单。
- 补充回滚方案。
- 补充维护手册。
- 统一更新 README_STATUS。
- 在确认稳定后统一提交 Git。
