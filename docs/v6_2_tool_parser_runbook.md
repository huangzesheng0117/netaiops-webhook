# NetAIOps webhook v6.2 Tool / Parser 体系运维手册

## 1. 阶段定位

当前阶段：v6.2。

v6.2 参考 MCPyATS 的 Tool / Parser 体系设计，但不直接引入 MCPyATS 整套框架。

本阶段目标是把现有 MCP-Netmiko、Prometheus、Parser 等能力抽象成 Tool Registry，并把 CLI 原始输出逐步解析成结构化 parsed facts，减少 evidence_facts.py 对 raw output 正则的依赖。

## 2. 当前已完成能力

v6.2 已新增以下模块：

- netaiops/tool_registry.py
- netaiops/parser_registry.py
- netaiops/execution_parser_enricher.py
- netaiops/evidence_parsed_facts.py
- netaiops/parsers/cisco_interface.py
- netaiops/parsers/cisco_interface_counters.py
- netaiops/parsers/cisco_etherchannel.py
- tools/validate_tool_registry.py
- tools/validate_parser_registry.py
- tools/enrich_execution_parsed.py
- tools/verify_evidence_parsed_facts.py
- tools/regress_v6_2.sh

## 3. Tool Registry

当前注册的 Tool 包括：

- mcp_netmiko_run_show
- prometheus_range_query
- parser_parse_cli_output
- elastic_log_window_query
- cmdb_device_lookup

当前启用的 Tool：

- mcp_netmiko_run_show
- prometheus_range_query
- parser_parse_cli_output

当前保留但未启用的 Tool：

- elastic_log_window_query
- cmdb_device_lookup

当前阶段所有 Tool 的 risk_level 必须为 readonly。

## 4. Parser Registry

当前已启用 3 个 Parser：

- cisco_show_interfaces
- cisco_show_interfaces_counters_errors
- cisco_etherchannel_summary

当前重点覆盖接口利用率类告警中常用的 5 条只读取证命令：

- show interfaces TenGigabitEthernet1/0/1
- show interfaces TenGigabitEthernet2/0/1
- show interfaces TenGigabitEthernet1/0/1 counters errors
- show interfaces TenGigabitEthernet2/0/1 counters errors
- show etherchannel summary

在已验证样例中，5 条命令应全部为 parsed，不应再出现 skipped。

## 5. Execution Parsed Enrichment

v6.2 已支持把 parser_registry 的结果旁路写入 execution 文件：

    data/execution/*.execution.json

每条 command_results 应包含 parsed 字段。

典型状态：

    parsed: 5
    skipped: 0

## 6. Evidence Parsed-first

v6.2 已支持 evidence_facts 优先读取 parsed facts。

目标效果：

    parsed_facts_enabled: true
    facts_source_preference: parsed_first_raw_fallback

parsed_fact_sources 应包含：

    cisco_show_interfaces
    cisco_show_interfaces_counters_errors
    cisco_etherchannel_summary

raw output 仍作为 fallback，不直接移除。

## 7. 常用命令

进入环境：

    cd /opt/netaiops-webhook
    source venv/bin/activate

校验 Tool Registry：

    python tools/validate_tool_registry.py

校验 Parser Registry：

    python tools/validate_parser_registry.py --sample --rid <request_id>

对指定 request_id 写入 parsed facts：

    python tools/enrich_execution_parsed.py --rid <request_id>

验证 evidence 是否优先使用 parsed facts：

    python tools/verify_evidence_parsed_facts.py --rid <request_id>

执行 v6.2 一键回归：

    bash tools/regress_v6_2.sh

指定 request_id 执行 v6.2 回归：

    RID=<request_id> bash tools/regress_v6_2.sh

## 8. 验收关键词

v6.2 验收时重点看以下关键词：

    Ran 28 tests
    OK

    "verdict": "pass"

    "parser_count": 3
    "enabled_parser_count": 3

    "parse_status_counts": {
      "parsed": 5
    }

    "parsed_facts_enabled": true
    "facts_source_preference": "parsed_first_raw_fallback"

    v6.1 regression PASS

    v6.2 regression PASS

## 9. 当前边界

v6.2 当前主要覆盖 Cisco IOS / IOS-XE 接口利用率类命令。

NX-OS、ACI、H3C、Huawei、F5 等平台 Parser 后续继续扩展。

当前 v6.2 不改变命令生成逻辑，不改变 safety_policy，不改变 MCP 只读取证边界。

## 10. 下一阶段

v6.2 收尾后，下一阶段进入 v6.3。

v6.3 参考 claude-network-skills，目标是建设 NetAIOps 网络 Skill 库，把 family、capability、command、parser、evidence、review 规则沉淀为可维护的 Skill 包。
