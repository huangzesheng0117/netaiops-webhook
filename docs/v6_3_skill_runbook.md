# NetAIOps webhook v6.3 Skill 体系运维手册

## 1. 阶段定位

当前阶段：v6.3。

v6.3 参考 claude-network-skills 的设计思想，但不依赖 Claude，不直接引入外部 Skill Runtime。

本阶段目标是建设 NetAIOps 自有网络 Skill 库，把告警 family、允许 capability、允许 Tool、命令模板、Parser、证据规则、输出字段和人工复核条件沉淀为可维护的 Skill 包。

v6.3 仍然不改变现有生产执行链路，不启用自适应补充取证。

## 2. 当前已完成能力

v6.3 已新增以下能力：

- skills/interface_utilization_high/SKILL.md
- skills/interface_utilization_high/commands.yaml
- skills/interface_utilization_high/evidence_rules.yaml
- skills/interface_utilization_high/output_schema.json
- skills/interface_utilization_high/examples/
- netaiops/skill_registry.py
- netaiops/skill_binding_validator.py
- netaiops/skill_session_context.py
- netaiops/skill_compliance_validator.py
- tools/validate_skills.py
- tools/validate_skill_bindings.py
- tools/show_investigation_skill_context.py
- tools/validate_skill_compliance.py
- tools/regress_v6_3.sh

## 3. 当前 Skill 包

当前已建设的 Skill：

    interface_utilization_high

对应 family：

    interface_or_link_utilization_high

适用场景：

- 接口利用率过高
- 互联网线路利用率过高
- 专线链路利用率过高
- 单接口或多接口利用率告警
- 需要结合设备侧速率、错误包、聚合关系、Prometheus 窗口证据判断的场景

## 4. Skill 文件说明

SKILL.md：

    记录适用范围、调查目标、判断逻辑、禁止动作、人工复核条件。

commands.yaml：

    记录允许调用的 Tool、允许 capability、平台命令模板、Parser、只读限制和禁止命令模式。

evidence_rules.yaml：

    记录 required_facts、preferred_facts、状态判断规则、流量判断规则、质量判断规则和人工复核条件。

output_schema.json：

    记录 Skill 期望输出字段、判断字段和通知中应出现的关键行。

examples/：

    存放脱敏后的告警、命令输出和期望 review 样例。

## 5. Skill Binding 校验

Skill Binding 校验用于检查：

- family 是否能匹配到 Skill
- Skill 中声明的 Tool 是否存在于 Tool Registry
- Skill 中声明的 Parser 是否存在于 Parser Registry
- Skill 中声明的 capability 是否能在当前 registry 文本中找到
- Skill 是否保持 readonly 风险级别

常用命令：

    python tools/validate_skill_bindings.py
    python tools/validate_skill_bindings.py --skill interface_utilization_high
    python tools/validate_skill_bindings.py --skill interface_utilization_high --graph

当前允许存在的 warning：

    capability not found in current registry text scan: parse_cli_output
    capability not found in current registry text scan: prometheus_interface_window
    capability not found in current registry text scan: show_interface_aggregation

这些 warning 当前来自文本扫描能力不完整，不是阻断性问题。

## 6. Investigation Session Skill Context

v6.3 已支持把 Skill Context 写入 Investigation Session。

查看命令：

    python tools/show_investigation_skill_context.py --rid <request_id>

也可以通过 API 查看：

    curl -s "http://127.0.0.1:18080/v6/investigation/<request_id>" | python -m json.tool

期望字段：

    matched: true
    family: interface_or_link_utilization_high
    skill_name: interface_utilization_high
    binding_verdict: pass
    violations: []

## 7. Skill Compliance 校验

Skill Compliance 校验用于检查某个 request_id 的实际 execution 和 review 是否符合 Skill 约束。

校验内容包括：

- 实际执行命令是否符合 commands.yaml 模板
- 每条命令是否已 parsed
- parser 是否在 Skill 声明范围内
- required_facts 是否齐全
- parsed_fact_sources 是否覆盖 Skill 声明的 Parser
- 通知关键字段是否覆盖 output_schema.json 的 required_lines

常用命令：

    python tools/validate_skill_compliance.py --rid <request_id>

当前非严格模式下允许 notification required lines 作为 warning：

    notification required lines missing: 综合执行结果判断

如果未来希望通知字段也强制严格通过，可使用：

    python tools/validate_skill_compliance.py --rid <request_id> --strict-notification

## 8. v6.3 一键回归

执行 v6.3 回归：

    bash tools/regress_v6_3.sh

指定 request_id 执行 v6.3 回归：

    RID=<request_id> bash tools/regress_v6_3.sh

## 9. 验收关键词

v6.3 验收时重点看：

    Ran 44 tests
    OK

    "verdict": "pass"
    "skill_count": 1

    "skill_name": "interface_utilization_high"
    "family": "interface_or_link_utilization_high"
    "risk_level": "readonly"
    "stage": "v6.3"

    "missing_tools": []
    "missing_parsers": []

    "matched": true
    "binding_verdict": "pass"
    "violations": []

    "command_count": 5
    "parsed_count": 5
    "skipped_count": 0
    "error_count": 0
    "unmatched_count": 0

    v6.2 regression PASS
    v6.3 regression PASS
    status: ok

## 10. 当前边界

v6.3 当前只建设了第一个 Skill：

    interface_utilization_high

当前 v6.3 不改变生产执行链路，不自动按 Skill 重新规划命令，不启用自适应补充取证。

Skill Compliance 当前默认非严格校验通知字段，通知 required_lines 缺失会作为 warning 展示。

## 11. 下一阶段

v6.3 收尾后，下一阶段进入 v6.4。

v6.4 参考 Anthropic Skills 的渐进加载思想，实现 Skill Runtime：

- 只常驻加载 Skill metadata
- 命中 family 后再加载 SKILL.md
- 需要生成命令时再加载 commands.yaml
- 需要判断证据时再加载 evidence_rules.yaml
- 需要校验输出时再加载 output_schema.json
