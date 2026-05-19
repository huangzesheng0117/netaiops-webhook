from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolSpec:
    tool_name: str
    description: str
    risk_level: str
    input_schema: dict[str, str]
    output_schema: dict[str, str]
    timeout: int = 30
    allowed_families: list[str] = field(default_factory=list)
    enabled: bool = True


READONLY_TOOLS: list[ToolSpec] = [
    ToolSpec(
        tool_name="mcp_netmiko_run_show",
        description="通过 MCP-Netmiko 对网络设备执行只读 show 命令。",
        risk_level="readonly",
        input_schema={
            "device_ip": "string",
            "hostname": "string",
            "command": "string",
            "platform": "string",
        },
        output_schema={
            "status": "string",
            "output": "string",
            "error": "string",
            "started_at": "string",
            "finished_at": "string",
        },
        timeout=45,
        allowed_families=[
            "interface_or_link_utilization_high",
            "interface_down_or_flap",
            "bgp_neighbor_down",
            "f5_pool_member_down",
            "optical_power_alarm",
        ],
    ),
    ToolSpec(
        tool_name="prometheus_range_query",
        description="查询 Prometheus 告警时间窗口指标趋势。",
        risk_level="readonly",
        input_schema={
            "query": "string",
            "start": "string",
            "end": "string",
            "step": "string",
        },
        output_schema={
            "status": "string",
            "series": "array",
            "error": "string",
        },
        timeout=30,
        allowed_families=[
            "interface_or_link_utilization_high",
            "interface_down_or_flap",
            "bgp_neighbor_down",
            "f5_pool_member_down",
        ],
    ),
    ToolSpec(
        tool_name="elastic_log_window_query",
        description="查询 ELK/Elastic 告警时间窗口日志证据。",
        risk_level="readonly",
        input_schema={
            "index": "string",
            "query": "string",
            "start": "string",
            "end": "string",
        },
        output_schema={
            "status": "string",
            "logs": "array",
            "error": "string",
        },
        timeout=30,
        allowed_families=[
            "interface_or_link_utilization_high",
            "interface_down_or_flap",
            "bgp_neighbor_down",
            "f5_pool_member_down",
            "optical_power_alarm",
        ],
        enabled=False,
    ),
    ToolSpec(
        tool_name="cmdb_device_lookup",
        description="查询设备资产、角色、平台、机房和业务归属信息。",
        risk_level="readonly",
        input_schema={
            "device_ip": "string",
            "hostname": "string",
        },
        output_schema={
            "status": "string",
            "device": "object",
            "error": "string",
        },
        timeout=20,
        allowed_families=[
            "interface_or_link_utilization_high",
            "interface_down_or_flap",
            "bgp_neighbor_down",
            "f5_pool_member_down",
            "aci_endpoint_missing",
            "optical_power_alarm",
        ],
        enabled=False,
    ),
    ToolSpec(
        tool_name="parser_parse_cli_output",
        description="将网络设备 CLI 原始输出解析为结构化 parsed facts。",
        risk_level="readonly",
        input_schema={
            "platform": "string",
            "command": "string",
            "output": "string",
        },
        output_schema={
            "status": "string",
            "parser": "string",
            "parsed": "object",
            "error": "string",
        },
        timeout=10,
        allowed_families=[
            "interface_or_link_utilization_high",
            "interface_down_or_flap",
            "bgp_neighbor_down",
            "optical_power_alarm",
        ],
    ),
]


def list_tools(include_disabled: bool = True) -> list[dict[str, Any]]:
    result = []
    for tool in READONLY_TOOLS:
        if not include_disabled and not tool.enabled:
            continue
        result.append(asdict(tool))
    return result


def get_tool(tool_name: str) -> dict[str, Any] | None:
    for tool in READONLY_TOOLS:
        if tool.tool_name == tool_name:
            return asdict(tool)
    return None


def list_tools_for_family(family: str, include_disabled: bool = False) -> list[dict[str, Any]]:
    result = []
    for tool in READONLY_TOOLS:
        if not include_disabled and not tool.enabled:
            continue
        if family in tool.allowed_families:
            result.append(asdict(tool))
    return result


def validate_tool_registry() -> dict[str, Any]:
    violations: list[str] = []
    warnings: list[str] = []
    seen: set[str] = set()

    for tool in READONLY_TOOLS:
        if not tool.tool_name:
            violations.append("tool_name is empty")

        if tool.tool_name in seen:
            violations.append(f"duplicate tool_name: {tool.tool_name}")
        seen.add(tool.tool_name)

        if tool.risk_level != "readonly":
            violations.append(f"{tool.tool_name}: risk_level must be readonly in current NetAIOps stage")

        if not tool.input_schema:
            violations.append(f"{tool.tool_name}: input_schema is empty")

        if not tool.output_schema:
            violations.append(f"{tool.tool_name}: output_schema is empty")

        if tool.timeout <= 0:
            violations.append(f"{tool.tool_name}: timeout must be positive")

        if not tool.allowed_families:
            warnings.append(f"{tool.tool_name}: allowed_families is empty")

    return {
        "verdict": "fail" if violations else "pass",
        "tool_count": len(READONLY_TOOLS),
        "enabled_tool_count": len([x for x in READONLY_TOOLS if x.enabled]),
        "violations": violations,
        "warnings": warnings,
        "tools": list_tools(include_disabled=True),
    }
