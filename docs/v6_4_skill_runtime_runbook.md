# NetAIOps webhook v6.4 Skill Runtime 运维手册

## 1. 阶段定位

当前阶段：v6.4。

v6.4 参考 Anthropic Skills 的渐进加载思想，实现 NetAIOps 自有 Skill Runtime。

本阶段目标不是改变现有生产执行链路，而是把 v6.3 已建设的 Skill 包按需加载起来，避免每次调查都完整读取全部 Skill 内容。

## 2. 当前已完成能力

v6.4 已新增以下能力：

- netaiops/skill_runtime.py
- netaiops/skill_runtime_session_context.py
- netaiops/skill_runtime_api.py
- tools/show_skill_runtime.py
- tools/show_investigation_skill_runtime.py
- tools/validate_skill_runtime_api.py
- tools/regress_v6_4.sh
- tests/test_skill_runtime.py
- tests/test_skill_runtime_session_context.py
- tests/test_skill_runtime_api.py

## 3. 渐进加载层级

当前 Skill Runtime 支持 5 个加载层级：

    metadata
    instructions
    commands
    evidence
    schema

含义如下：

metadata：

    只加载 Skill 元信息，例如 name、version、family、risk_level、description、path。

instructions：

    加载 SKILL.md 内容。

commands：

    加载 commands.yaml 内容。

evidence：

    加载 evidence_rules.yaml 内容。

schema：

    加载 output_schema.json 内容。

## 4. 默认 Session 行为

Investigation Session 中默认只持久化 metadata：

    loaded_levels: ["metadata"]
    content_embedded: false
    content_policy: metadata_only_in_investigation_session

这样可以避免把完整 SKILL.md、commands.yaml、evidence_rules.yaml 写进每个 session 文件。

## 5. HTTP API

v6.4 新增只读 API：

查看 Skill Runtime 索引：

    curl -s "http://127.0.0.1:18080/v6/skills/runtime" | python -m json.tool

校验 Skill Runtime：

    curl -s "http://127.0.0.1:18080/v6/skills/runtime/validate" | python -m json.tool

按 family 加载：

    curl -s "http://127.0.0.1:18080/v6/skills/runtime/family/interface_or_link_utilization_high?levels=metadata" | python -m json.tool

按 family 按需加载 commands：

    curl -s "http://127.0.0.1:18080/v6/skills/runtime/family/interface_or_link_utilization_high?levels=metadata,commands" | python -m json.tool

按 skill 加载完整上下文：

    curl -s "http://127.0.0.1:18080/v6/skills/runtime/skill/interface_utilization_high?levels=metadata,instructions,commands,evidence,schema" | python -m json.tool

## 6. CLI 工具

查看 Skill Runtime 索引：

    python tools/show_skill_runtime.py --index

校验 Skill Runtime：

    python tools/show_skill_runtime.py --validate

按 family 查看 metadata：

    python tools/show_skill_runtime.py --family interface_or_link_utilization_high --levels metadata

按 skill 查看完整 Runtime：

    python tools/show_skill_runtime.py --skill interface_utilization_high --levels metadata,instructions,commands,evidence,schema

查看某个 request_id 的 Investigation Runtime Context：

    python tools/show_investigation_skill_runtime.py --rid <request_id> --levels metadata

校验 Runtime API：

    python tools/validate_skill_runtime_api.py

## 7. API 行为说明

当 levels=metadata 时：

    content_embedded: false

当 levels 包含 instructions、commands、evidence 或 schema 时：

    content_embedded: true

这是预期行为，表示 API 按需返回了 Skill 文件内容。

但是 Investigation Session 默认仍只持久化 metadata，不持久化完整内容。

## 8. 验收关键词

v6.4 验收时重点看：

    Ran 60 tests
    OK

    "verdict": "pass"
    "runtime_version": "v6.4.0"
    "load_strategy": "progressive_loading"
    "skill_count": 1

    "loaded_levels": [
      "metadata"
    ]

    "content_embedded": false

    "family_commands_loaded_levels": [
      "metadata",
      "commands"
    ]

    "family_commands_content_embedded": true

    "skill_full_loaded_levels": [
      "metadata",
      "instructions",
      "commands",
      "evidence",
      "schema"
    ]

    "skill_full_content_embedded": true

    v6.3 regression PASS
    v6.4 regression PASS
    status: ok

## 9. 当前边界

v6.4 当前只提供只读 Runtime 查询能力。

v6.4 不改变当前 MCP 执行链路，不改变 capability 规划逻辑，不启用自适应补充取证。

v6.4 仍然只围绕当前第一个 Skill：

    interface_utilization_high

## 10. 下一阶段

v6.4 收尾后，下一阶段进入 v6.5。

v6.5 目标是 Skill 约束下的自适应取证：

- 只能在 matched Skill 的 allowed_capabilities 内补充取证
- 只能使用 readonly Tool
- 只能使用 commands.yaml 中声明的命令模板
- 必须经过 safety_policy
- 必须限制 extra_rounds 和 extra_commands
