import re
from typing import Any, Dict, List, Optional

from netaiops.evidence_facts import build_interface_evidence_summary


ROUTING_FAMILIES = {
    "bgp_neighbor_down",
    "ospf_neighbor_down",
    "routing_neighbor_down",
}

DEVICE_RESOURCE_FAMILIES = {
    "device_cpu_high",
    "device_memory_high",
}

F5_FAMILIES = {
    "f5_pool_member_down",
}


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def extract_output_text(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, dict):
        for key in ("output", "result", "text"):
            if value.get(key):
                return extract_output_text(value.get(key))
        return safe_text(value)

    if isinstance(value, list):
        parts = [extract_output_text(x) for x in value]
        return "\n".join([x for x in parts if x])

    return safe_text(value)


def get_family(execution_data: Dict[str, Any]) -> str:
    return safe_text(
        ((execution_data.get("family_result") or {}).get("family"))
        or ((execution_data.get("classification") or {}).get("family"))
        or ((execution_data.get("classification") or {}).get("playbook_type"))
        or ((execution_data.get("playbook") or {}).get("playbook_id"))
    )


def result_by_capability(command_results: List[Dict[str, Any]], capability: str) -> Dict[str, Any]:
    for item in command_results or []:
        if safe_text(item.get("capability")) == capability:
            return item
    return {}


def first_match(pattern: str, text: str, flags: int = re.IGNORECASE) -> str:
    m = re.search(pattern, text or "", flags)
    if not m:
        return ""
    if m.groups():
        return safe_text(m.group(1))
    return safe_text(m.group(0))


def parse_percent_values(text: str) -> List[float]:
    values: List[float] = []
    for m in re.finditer(r"(\d+(?:\.\d+)?)\s*%", text or ""):
        try:
            values.append(float(m.group(1)))
        except Exception:
            pass
    return values


def parse_bgp_state(text: str) -> str:
    text = text or ""

    for state in [
        "Established",
        "Idle",
        "Active",
        "Connect",
        "OpenSent",
        "OpenConfirm",
    ]:
        if re.search(rf"\b{state}\b", text, flags=re.IGNORECASE):
            return state

    m = re.search(r"BGP\s+state\s*=\s*([A-Za-z]+)", text, flags=re.IGNORECASE)
    if m:
        return m.group(1)

    return ""


def parse_ospf_state(text: str) -> str:
    text = text or ""

    for state in [
        "FULL",
        "2-WAY",
        "EXSTART",
        "EXCHANGE",
        "LOADING",
        "DOWN",
        "INIT",
        "ATTEMPT",
    ]:
        if re.search(rf"\b{state}\b", text, flags=re.IGNORECASE):
            return state

    return ""


def build_routing_evidence_summary(execution_data: Dict[str, Any]) -> Dict[str, Any]:
    family = get_family(execution_data)
    command_results = execution_data.get("command_results", []) or []
    target_scope = execution_data.get("target_scope", {}) or {}

    peer_ip = safe_text(target_scope.get("peer_ip"))
    key_findings: List[str] = []
    recommendations: List[str] = []
    notify_lines: List[str] = []
    facts: Dict[str, Any] = {
        "peer_ip": peer_ip,
    }

    bgp_result = result_by_capability(command_results, "show_bgp_peer_detail")
    ospf_result = result_by_capability(command_results, "show_ospf_peer_detail")
    route_result = result_by_capability(command_results, "show_route_to_peer")
    ping_result = result_by_capability(command_results, "ping_peer")
    int_brief_result = result_by_capability(command_results, "show_interface_brief")
    config_result = result_by_capability(command_results, "show_bgp_config_snippet")

    if bgp_result:
        output = extract_output_text(bgp_result.get("output"))
        state = parse_bgp_state(output)
        if state:
            facts["bgp_state"] = state
            line = f"BGP邻居状态：peer={peer_ip or '未知'} state={state}"
            key_findings.append(line)
            notify_lines.append(line)

            if state.lower() != "established":
                recommendations.append("BGP 邻居未处于 Established，建议继续核查对端状态、链路连通性、BFD、ACL/安全策略及近期配置变更。")
            else:
                recommendations.append("BGP 邻居当前已恢复到 Established，建议结合告警时间窗口判断是否为短时抖动。")

        uptime = first_match(r"(up for\s+[^\n,]+)", output)
        if uptime:
            facts["bgp_uptime"] = uptime
            key_findings.append(f"BGP邻居运行时间：{uptime}")

        received_prefixes = first_match(r"(\d+)\s+accepted prefixes", output)
        if received_prefixes:
            facts["accepted_prefixes"] = received_prefixes
            key_findings.append(f"BGP已接收前缀数：{received_prefixes}")

    if ospf_result:
        output = extract_output_text(ospf_result.get("output"))
        state = parse_ospf_state(output)
        if state:
            facts["ospf_state"] = state
            line = f"OSPF邻接状态：peer={peer_ip or '未知'} state={state}"
            key_findings.append(line)
            notify_lines.append(line)

            if state.upper() != "FULL":
                recommendations.append("OSPF 邻接未处于 FULL，建议核查接口状态、Hello/Dead timer、area、认证、MTU 和对端状态。")
            else:
                recommendations.append("OSPF 邻接当前为 FULL，建议结合告警时间窗口判断是否为短时邻接抖动。")

    if route_result:
        output = extract_output_text(route_result.get("output"))
        has_route = bool(re.search(r"Routing entry|via|Known via|direct|attached|路由", output, flags=re.IGNORECASE))
        facts["route_to_peer_observed"] = has_route
        if has_route:
            key_findings.append(f"到邻居地址 {peer_ip or '未知'} 的路由查询存在有效返回。")
            notify_lines.append(f"到邻居地址 {peer_ip or '未知'} 的路由查询存在有效返回。")
        else:
            key_findings.append(f"到邻居地址 {peer_ip or '未知'} 的路由查询未观察到明确有效路由。")
            recommendations.append("核查本机到邻居地址的路由可达性，确认是否存在下一跳、直连接口或VRF问题。")

    if ping_result:
        output = extract_output_text(ping_result.get("output"))
        ping_success = bool(re.search(r"Success rate is\s+([1-9]\d?|100)\s+percent|bytes from|ttl=", output, flags=re.IGNORECASE))
        facts["ping_success"] = ping_success
        if ping_success:
            key_findings.append(f"到邻居地址 {peer_ip or '未知'} 的 ping 存在成功响应。")
            notify_lines.append(f"到邻居地址 {peer_ip or '未知'} 的 ping 存在成功响应。")
        else:
            key_findings.append(f"到邻居地址 {peer_ip or '未知'} 的 ping 未观察到成功响应。")
            recommendations.append("如果 ping 失败，需结合控制面策略确认是否禁 ping；若未禁 ping，则继续核查链路和对端可达性。")

    if int_brief_result:
        output = extract_output_text(int_brief_result.get("output"))
        if output:
            facts["interface_brief_collected"] = True
            key_findings.append("已采集接口概要信息，可用于辅助判断本端接口状态。")

    if config_result:
        output = extract_output_text(config_result.get("output"))
        if output:
            facts["config_snippet_collected"] = True
            key_findings.append("已采集路由协议相关配置片段，可用于核对邻居配置。")

    if not key_findings:
        return {
            "has_facts": False,
            "family": family,
            "facts": facts,
            "key_findings": [],
            "recommendations": [],
            "notify_lines": [],
            "conclusion": "",
        }

    if not recommendations:
        recommendations.append("结合邻居状态、路由可达性、接口状态和近期变更记录继续判断根因。")

    if family == "ospf_neighbor_down":
        conclusion = "OSPF邻接只读取证完成；请结合邻接状态、接口状态和日志时间线判断是否为邻接抖动或配置/链路问题。"
    else:
        state = facts.get("bgp_state") or facts.get("ospf_state") or "未知"
        conclusion = f"路由邻居只读取证完成；当前邻居状态={state}。建议结合告警时间窗口判断是持续中断还是短时抖动。"

    return {
        "has_facts": True,
        "family": family,
        "facts": facts,
        "key_findings": key_findings[:8],
        "recommendations": recommendations[:6],
        "notify_lines": notify_lines[:5],
        "conclusion": conclusion,
    }


def build_device_resource_evidence_summary(execution_data: Dict[str, Any]) -> Dict[str, Any]:
    family = get_family(execution_data)
    command_results = execution_data.get("command_results", []) or []

    cpu_result = result_by_capability(command_results, "show_device_cpu")
    mem_result = result_by_capability(command_results, "show_device_memory")

    facts: Dict[str, Any] = {}
    key_findings: List[str] = []
    recommendations: List[str] = []
    notify_lines: List[str] = []

    if cpu_result:
        output = extract_output_text(cpu_result.get("output"))
        values = parse_percent_values(output)
        if values:
            facts["cpu_percent_values"] = values[:10]
            max_cpu = max(values)
            facts["cpu_max_percent"] = max_cpu
            line = f"CPU取证：采集到CPU百分比，最大值约 {max_cpu:.2f}%"
            key_findings.append(line)
            notify_lines.append(line)
            if max_cpu >= 80:
                recommendations.append("CPU 当前或近期仍偏高，建议继续核查控制面协议、异常流量、日志风暴和高CPU进程。")
            else:
                recommendations.append("CPU 取证时未观察到明显高位，建议结合告警时间窗口判断是否为瞬时峰值。")
        elif output:
            facts["cpu_output_collected"] = True
            key_findings.append("已采集CPU相关输出，但未解析到明确百分比。")

    if mem_result:
        output = extract_output_text(mem_result.get("output"))
        values = parse_percent_values(output)
        if values:
            facts["memory_percent_values"] = values[:10]
            max_mem = max(values)
            facts["memory_max_percent"] = max_mem
            line = f"内存取证：采集到内存百分比，最大值约 {max_mem:.2f}%"
            key_findings.append(line)
            notify_lines.append(line)
            if max_mem >= 80:
                recommendations.append("内存当前或近期仍偏高，建议继续核查异常进程、会话规模和内存泄漏风险。")
            else:
                recommendations.append("内存取证时未观察到明显高位，建议结合告警时间窗口判断是否为瞬时峰值。")
        elif output:
            facts["memory_output_collected"] = True
            key_findings.append("已采集内存相关输出，但未解析到明确百分比。")

    if not key_findings:
        return {
            "has_facts": False,
            "family": family,
            "facts": facts,
            "key_findings": [],
            "recommendations": [],
            "notify_lines": [],
            "conclusion": "",
        }

    if not recommendations:
        recommendations.append("结合资源趋势、进程状态和告警时间窗口继续判断是否持续异常。")

    conclusion = "设备资源类只读取证完成；已采集CPU/内存相关输出，建议结合告警窗口趋势判断是否为持续异常或瞬时峰值。"

    return {
        "has_facts": True,
        "family": family,
        "facts": facts,
        "key_findings": key_findings[:8],
        "recommendations": recommendations[:6],
        "notify_lines": notify_lines[:5],
        "conclusion": conclusion,
    }


def build_f5_evidence_summary(execution_data: Dict[str, Any]) -> Dict[str, Any]:
    family = get_family(execution_data)
    command_results = execution_data.get("command_results", []) or []

    pool_list_result = result_by_capability(command_results, "show_f5_pool_list")
    members_result = result_by_capability(command_results, "show_f5_pool_members")
    config_result = result_by_capability(command_results, "show_f5_pool_config")
    conn_result = result_by_capability(command_results, "show_f5_connections")
    perf_result = result_by_capability(command_results, "show_f5_performance")

    facts: Dict[str, Any] = {}
    key_findings: List[str] = []
    recommendations: List[str] = []
    notify_lines: List[str] = []

    combined_output = "\n".join(
        extract_output_text(x.get("output"))
        for x in [pool_list_result, members_result, config_result, conn_result, perf_result]
        if x
    )

    if combined_output:
        down_count = len(re.findall(r"\bdown\b", combined_output, flags=re.IGNORECASE))
        up_count = len(re.findall(r"\bup\b", combined_output, flags=re.IGNORECASE))
        disabled_count = len(re.findall(r"\bdisabled\b", combined_output, flags=re.IGNORECASE))
        available_count = len(re.findall(r"\bavailable\b", combined_output, flags=re.IGNORECASE))

        facts["keyword_down_count"] = down_count
        facts["keyword_up_count"] = up_count
        facts["keyword_disabled_count"] = disabled_count
        facts["keyword_available_count"] = available_count

        line = f"F5状态关键词统计：down={down_count}，up={up_count}，disabled={disabled_count}，available={available_count}"
        key_findings.append(line)
        notify_lines.append(line)

        if down_count > 0:
            recommendations.append("F5 输出中存在 down 关键字，建议重点核查 pool member 健康检查、后端服务端口和节点可达性。")
        else:
            recommendations.append("F5 输出中未明显观察到 down 关键字，建议结合告警时间窗口判断是否已恢复或对象匹配是否准确。")

    if members_result:
        key_findings.append("已采集 F5 pool member 状态输出。")
    if config_result:
        key_findings.append("已采集 F5 pool 配置输出。")
    if conn_result:
        key_findings.append("已采集 F5 connection 相关输出。")
    if perf_result:
        key_findings.append("已采集 F5 性能相关输出。")

    if not key_findings:
        return {
            "has_facts": False,
            "family": family,
            "facts": facts,
            "key_findings": [],
            "recommendations": [],
            "notify_lines": [],
            "conclusion": "",
        }

    if not recommendations:
        recommendations.append("结合 pool/member 状态、monitor 结果、后端服务健康和应用侧日志继续判断。")

    conclusion = "F5 pool member 只读取证完成；已采集 pool/member/config/connection/performance 相关输出，建议结合健康检查和后端服务状态继续判断。"

    return {
        "has_facts": True,
        "family": family,
        "facts": facts,
        "key_findings": key_findings[:8],
        "recommendations": recommendations[:6],
        "notify_lines": notify_lines[:5],
        "conclusion": conclusion,
    }


def build_family_evidence_summary(execution_data: Dict[str, Any]) -> Dict[str, Any]:
    family = get_family(execution_data)

    if family in ROUTING_FAMILIES:
        return build_routing_evidence_summary(execution_data)

    if family in DEVICE_RESOURCE_FAMILIES:
        return build_device_resource_evidence_summary(execution_data)

    if family in F5_FAMILIES:
        return build_f5_evidence_summary(execution_data)

    return build_interface_evidence_summary(execution_data)
