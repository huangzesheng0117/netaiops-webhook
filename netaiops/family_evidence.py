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

# ===== v5 expanded family evidence parser begin =====
# 说明：
# 为第六批/第七批新增 family 增加 evidence parser。
# 覆盖范围：
# - hardware_fan_abnormal
# - hardware_power_abnormal
# - hardware_temperature_high
# - chassis_slot_or_module_abnormal
# - optical_power_abnormal
# - device_disk_high
# - dns_request_rate_anomaly
# - dns_response_rate_anomaly
# - f5_connection_rate_anomaly
# - ha_or_cluster_state_abnormal
# - cimc_hardware_abnormal

import re as _v8_re
from typing import Any as _V8Any, Dict as _V8Dict, List as _V8List


try:
    _v8_original_build_family_evidence_summary = build_family_evidence_summary
except NameError:
    _v8_original_build_family_evidence_summary = None


V8_HARDWARE_FAMILIES = {
    "hardware_fan_abnormal",
    "hardware_power_abnormal",
    "hardware_temperature_high",
    "chassis_slot_or_module_abnormal",
    "optical_power_abnormal",
    "device_disk_high",
    "cimc_hardware_abnormal",
}

V8_DNS_FAMILIES = {
    "dns_request_rate_anomaly",
    "dns_response_rate_anomaly",
}

V8_F5_METRIC_FAMILIES = {
    "f5_connection_rate_anomaly",
}

V8_HA_FAMILIES = {
    "ha_or_cluster_state_abnormal",
}


def _v8_safe_text(value: _V8Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _v8_get_family(execution_data: _V8Dict[str, _V8Any]) -> str:
    return _v8_safe_text(
        ((execution_data.get("family_result") or {}).get("family"))
        or ((execution_data.get("classification") or {}).get("family"))
        or ((execution_data.get("classification") or {}).get("playbook_type"))
        or ((execution_data.get("playbook") or {}).get("playbook_id"))
    )


def _v8_extract_command_outputs(execution_data: _V8Dict[str, _V8Any]) -> _V8List[_V8Dict[str, str]]:
    rows = []

    for item in execution_data.get("command_results", []) or []:
        if not isinstance(item, dict):
            continue

        command = _v8_safe_text(item.get("command"))
        capability = _v8_safe_text(item.get("capability"))
        output = _v8_safe_text(item.get("output"))
        error = _v8_safe_text(item.get("error"))

        judge = item.get("judge", {}) or {}
        status = _v8_safe_text(
            judge.get("final_status")
            or item.get("final_status")
            or item.get("dispatch_status")
            or item.get("status")
        )

        rows.append(
            {
                "capability": capability,
                "command": command,
                "output": output,
                "error": error,
                "status": status,
                "hard_error": str(bool(judge.get("hard_error"))),
            }
        )

    return rows


def _v8_all_output_text(execution_data: _V8Dict[str, _V8Any]) -> str:
    parts = []

    for row in _v8_extract_command_outputs(execution_data):
        for key in ("command", "output", "error"):
            value = _v8_safe_text(row.get(key))
            if value:
                parts.append(value)

    return "\n".join(parts)


def _v8_count_keywords(text: str, keywords: _V8List[str]) -> int:
    count = 0
    for keyword in keywords:
        if not keyword:
            continue
        count += len(_v8_re.findall(_v8_re.escape(keyword), text or "", flags=_v8_re.IGNORECASE))
    return count


def _v8_find_lines(text: str, patterns: _V8List[str], limit: int = 8) -> _V8List[str]:
    result = []
    seen = set()

    for line in (text or "").splitlines():
        line_text = line.strip()
        if not line_text:
            continue

        for pattern in patterns:
            if _v8_re.search(pattern, line_text, flags=_v8_re.IGNORECASE):
                if line_text not in seen:
                    seen.add(line_text)
                    result.append(line_text)
                break

        if len(result) >= limit:
            break

    return result


def _v8_status_keyword_summary(text: str) -> _V8Dict[str, int]:
    abnormal_keywords = [
        "fail",
        "failed",
        "failure",
        "fault",
        "faulty",
        "abnormal",
        "critical",
        "warning",
        "warn",
        "down",
        "absent",
        "not present",
        "notpresent",
        "removed",
        "shutdown",
        "bad",
        "alarm",
        "error",
    ]

    normal_keywords = [
        "ok",
        "normal",
        "good",
        "up",
        "present",
        "active",
        "standby",
        "ready",
        "online",
    ]

    return {
        "abnormal_keyword_count": _v8_count_keywords(text, abnormal_keywords),
        "normal_keyword_count": _v8_count_keywords(text, normal_keywords),
    }


def _v8_first_number(pattern: str, text: str):
    m = _v8_re.search(pattern, text or "", flags=_v8_re.IGNORECASE)
    if not m:
        return None

    try:
        return float(m.group(1))
    except Exception:
        return None


def _v8_build_hardware_evidence_summary(execution_data: _V8Dict[str, _V8Any]) -> _V8Dict[str, _V8Any]:
    family = _v8_get_family(execution_data)
    text = _v8_all_output_text(execution_data)
    rows = _v8_extract_command_outputs(execution_data)

    facts: _V8Dict[str, _V8Any] = {
        "command_count": len(rows),
        "family": family,
    }

    key_findings: _V8List[str] = []
    notify_lines: _V8List[str] = []
    recommendations: _V8List[str] = []

    status_summary = _v8_status_keyword_summary(text)
    facts.update(status_summary)

    if rows:
        key_findings.append(f"已采集硬件/环境类只读输出 {len(rows)} 条。")
        notify_lines.append(f"硬件/环境类取证：已执行 {len(rows)} 条只读命令。")
    else:
        key_findings.append("该告警已归类为硬件/环境类告警，当前未产生 MCP 设备命令输出。")
        notify_lines.append("硬件/环境类取证：当前未产生 MCP 设备命令输出，建议结合 Prometheus 指标窗口确认。")

    abnormal_lines = _v8_find_lines(
        text,
        [
            r"fail|failed|failure|fault|faulty",
            r"abnormal|critical|warning|alarm|error",
            r"down|absent|not\s+present|removed",
            r"fan|power|temperature|temp|module|slot|transceiver|rx|tx|disk|storage",
        ],
        limit=8,
    )

    if abnormal_lines:
        facts["suspicious_lines"] = abnormal_lines
        notify_lines.append("疑似异常输出：" + "；".join(abnormal_lines[:3]))
        key_findings.append("硬件输出中存在疑似异常关键字或相关状态行。")

    if family == "hardware_fan_abnormal":
        notify_lines.append(
            f"风扇状态关键词统计：abnormal={status_summary['abnormal_keyword_count']}，normal={status_summary['normal_keyword_count']}"
        )
        recommendations.append("重点核查风扇模块状态、转速、是否缺失或故障；如持续异常，建议联系现场或厂商处理。")

    elif family == "hardware_power_abnormal":
        notify_lines.append(
            f"电源状态关键词统计：abnormal={status_summary['abnormal_keyword_count']}，normal={status_summary['normal_keyword_count']}"
        )
        recommendations.append("重点核查电源模块输入、冗余状态和是否存在 failed/absent；如单电源异常，评估冗余风险。")

    elif family == "hardware_temperature_high":
        temp_values = []
        for m in _v8_re.finditer(r"(-?\d+(?:\.\d+)?)\s*(?:C|celsius|degree)", text or "", flags=_v8_re.IGNORECASE):
            try:
                temp_values.append(float(m.group(1)))
            except Exception:
                pass

        if temp_values:
            facts["temperature_values"] = temp_values[:20]
            facts["temperature_max"] = max(temp_values)
            notify_lines.append(f"温度取证：采集到温度值，最高约 {max(temp_values):.2f}℃。")
        else:
            notify_lines.append("温度取证：已采集环境输出，但未解析到明确温度数值。")

        recommendations.append("核查设备进风/出风、机柜环境温度、风扇状态和模块温度阈值。")

    elif family == "chassis_slot_or_module_abnormal":
        notify_lines.append(
            f"机框/板卡状态关键词统计：abnormal={status_summary['abnormal_keyword_count']}，normal={status_summary['normal_keyword_count']}"
        )
        recommendations.append("重点核查板卡 online/active/standby 状态、模块告警、主控/线卡重启或拔插记录。")

    elif family == "optical_power_abnormal":
        optical_values = []
        for m in _v8_re.finditer(r"(-?\d+(?:\.\d+)?)\s*dBm", text or "", flags=_v8_re.IGNORECASE):
            try:
                optical_values.append(float(m.group(1)))
            except Exception:
                pass

        if optical_values:
            facts["optical_dbm_values"] = optical_values[:20]
            facts["optical_dbm_min"] = min(optical_values)
            facts["optical_dbm_max"] = max(optical_values)
            notify_lines.append(
                f"光功率取证：解析到 dBm 数值，min={min(optical_values):.2f} dBm，max={max(optical_values):.2f} dBm。"
            )
        else:
            notify_lines.append("光功率取证：已采集光模块/接口输出，但未解析到明确 dBm 数值。")

        recommendations.append("核查收发光功率、光模块型号、光纤跳线、对端端口光功率和是否接近阈值。")

    elif family == "device_disk_high":
        percent_values = []
        for m in _v8_re.finditer(r"(\d+(?:\.\d+)?)\s*%", text or "", flags=_v8_re.IGNORECASE):
            try:
                percent_values.append(float(m.group(1)))
            except Exception:
                pass

        if percent_values:
            facts["disk_percent_values"] = percent_values[:20]
            facts["disk_percent_max"] = max(percent_values)
            notify_lines.append(f"磁盘取证：采集到空间百分比，最大值约 {max(percent_values):.2f}%。")
        else:
            notify_lines.append("磁盘取证：已采集存储/文件系统输出，但未解析到明确百分比。")

        recommendations.append("核查日志、core 文件、临时文件、历史包和文件系统剩余空间，避免影响设备运行。")

    elif family == "cimc_hardware_abnormal":
        notify_lines.append(
            f"CIMC硬件状态关键词统计：abnormal={status_summary['abnormal_keyword_count']}，normal={status_summary['normal_keyword_count']}"
        )
        recommendations.append("结合 CIMC 硬件健康、主板、处理器、存储控制器、电源和风扇状态继续确认。")

    if not recommendations:
        recommendations.append("结合 Prometheus 指标窗口、设备环境输出和近期日志继续判断硬件状态是否持续异常。")

    conclusion = "硬件/环境类只读取证完成；建议结合异常关键字、Prometheus窗口指标和现场/厂商硬件状态继续确认。"

    return {
        "has_facts": True,
        "family": family,
        "facts": facts,
        "key_findings": key_findings[:10],
        "recommendations": recommendations[:8],
        "notify_lines": notify_lines[:8],
        "conclusion": conclusion,
    }


def _v8_build_dns_evidence_summary(execution_data: _V8Dict[str, _V8Any]) -> _V8Dict[str, _V8Any]:
    family = _v8_get_family(execution_data)
    text = _v8_all_output_text(execution_data)
    rows = _v8_extract_command_outputs(execution_data)

    facts = {
        "family": family,
        "command_count": len(rows),
        "evidence_mode": "prometheus_and_elastic_preferred",
    }

    key_findings = [
        "DNS请求/响应类告警主要依赖 Prometheus 指标窗口和 Elastic 日志窗口判断。",
    ]

    notify_lines = [
        "DNS类取证：该类告警以指标窗口和日志窗口为主，MCP设备命令不是首要证据。",
    ]

    recommendations = [
        "优先查看 Prometheus 告警窗口内 DNS QPS、响应率、成功率、失败率和突增/突降幅度。",
        "结合 Elastic DNS 日志查看源IP分布、请求域名分布、错误码、超时和异常请求峰值。",
    ]

    if rows:
        facts["mcp_command_collected"] = True
        notify_lines.append(f"DNS类补充取证：已采集 MCP 输出 {len(rows)} 条。")

    nums = []
    for m in _v8_re.finditer(r"(\d+(?:\.\d+)?)", text or ""):
        try:
            nums.append(float(m.group(1)))
        except Exception:
            pass

    if nums:
        facts["number_values_sample"] = nums[:20]

    if family == "dns_request_rate_anomaly":
        conclusion = "DNS请求率异常已归类；建议以 Prometheus 请求率窗口和 DNS 日志源分布作为主要证据。"
    else:
        conclusion = "DNS响应率异常已归类；建议以 Prometheus 响应率/成功率窗口和 DNS 日志错误分布作为主要证据。"

    return {
        "has_facts": True,
        "family": family,
        "facts": facts,
        "key_findings": key_findings,
        "recommendations": recommendations,
        "notify_lines": notify_lines,
        "conclusion": conclusion,
    }


def _v8_build_f5_connection_evidence_summary(execution_data: _V8Dict[str, _V8Any]) -> _V8Dict[str, _V8Any]:
    family = _v8_get_family(execution_data)
    text = _v8_all_output_text(execution_data)
    rows = _v8_extract_command_outputs(execution_data)

    facts: _V8Dict[str, _V8Any] = {
        "family": family,
        "command_count": len(rows),
    }

    key_findings = []
    notify_lines = []
    recommendations = []

    if rows:
        key_findings.append(f"已采集 F5 连接/性能类只读输出 {len(rows)} 条。")
        notify_lines.append(f"F5连接类取证：已执行 {len(rows)} 条只读命令。")
    else:
        key_findings.append("F5连接类告警已归类，当前未产生 MCP 设备命令输出。")
        notify_lines.append("F5连接类取证：当前未产生 MCP 设备命令输出，建议结合 Prometheus 指标窗口。")

    current_conn = _v8_first_number(r"(?:current|cur|active).*?(?:conn|connection).*?(\d+)", text)
    if current_conn is None:
        current_conn = _v8_first_number(r"(?:conn|connection).*?(\d+)", text)

    if current_conn is not None:
        facts["current_connection_candidate"] = current_conn
        notify_lines.append(f"F5连接数取证：解析到连接数候选值 {current_conn:.0f}。")

    suspicious_lines = _v8_find_lines(
        text,
        [
            r"connection|conn|client|server|throughput|performance",
            r"current|active|total|max|drop|reset",
        ],
        limit=8,
    )

    if suspicious_lines:
        facts["connection_related_lines"] = suspicious_lines
        key_findings.append("F5输出中存在连接/性能相关状态行。")

    recommendations.append("结合 Prometheus 连接数窗口判断是持续高连接、瞬时峰值还是已恢复。")
    recommendations.append("如连接数异常持续，继续核查 VS、pool、客户端源分布、后端响应和连接复用情况。")

    conclusion = "F5连接数异常只读取证完成；建议结合连接数指标窗口和 F5 性能输出判断是否持续异常。"

    return {
        "has_facts": True,
        "family": family,
        "facts": facts,
        "key_findings": key_findings[:10],
        "recommendations": recommendations[:8],
        "notify_lines": notify_lines[:8],
        "conclusion": conclusion,
    }


def _v8_build_ha_evidence_summary(execution_data: _V8Dict[str, _V8Any]) -> _V8Dict[str, _V8Any]:
    family = _v8_get_family(execution_data)
    text = _v8_all_output_text(execution_data)
    rows = _v8_extract_command_outputs(execution_data)

    facts: _V8Dict[str, _V8Any] = {
        "family": family,
        "command_count": len(rows),
    }

    key_findings = []
    notify_lines = []
    recommendations = []

    active_count = _v8_count_keywords(text, ["active"])
    standby_count = _v8_count_keywords(text, ["standby"])
    failover_count = _v8_count_keywords(text, ["failover", "failed", "failure"])
    split_count = _v8_count_keywords(text, ["split", "split-brain"])

    facts.update(
        {
            "active_keyword_count": active_count,
            "standby_keyword_count": standby_count,
            "failover_keyword_count": failover_count,
            "split_keyword_count": split_count,
        }
    )

    if rows:
        notify_lines.append(f"HA/集群取证：已执行 {len(rows)} 条只读命令。")
    else:
        notify_lines.append("HA/集群取证：当前未产生 MCP 设备命令输出，建议结合 Prometheus/日志窗口。")

    notify_lines.append(
        f"HA状态关键词统计：active={active_count}，standby={standby_count}，failover={failover_count}，split={split_count}"
    )

    state_lines = _v8_find_lines(
        text,
        [
            r"active|standby|failover|cluster|ha|traffic-group|redundancy|master|backup",
        ],
        limit=8,
    )

    if state_lines:
        facts["ha_state_lines"] = state_lines
        key_findings.append("HA/集群输出中存在主备、failover 或 redundancy 相关状态行。")

    recommendations.append("核查当前主备角色、同步状态、failover 原因、心跳链路和最近主备切换日志。")
    recommendations.append("如存在 active/standby 不一致或频繁 failover，建议结合业务影响和双机同步状态继续排查。")

    conclusion = "HA/集群状态只读取证完成；建议结合主备角色、同步状态和日志窗口判断是否发生切换或异常。"

    return {
        "has_facts": True,
        "family": family,
        "facts": facts,
        "key_findings": key_findings[:10],
        "recommendations": recommendations[:8],
        "notify_lines": notify_lines[:8],
        "conclusion": conclusion,
    }


if _v8_original_build_family_evidence_summary is not None:
    def build_family_evidence_summary(execution_data: _V8Dict[str, _V8Any]) -> _V8Dict[str, _V8Any]:
        family = _v8_get_family(execution_data)

        if family in V8_HARDWARE_FAMILIES:
            return _v8_build_hardware_evidence_summary(execution_data)

        if family in V8_DNS_FAMILIES:
            return _v8_build_dns_evidence_summary(execution_data)

        if family in V8_F5_METRIC_FAMILIES:
            return _v8_build_f5_connection_evidence_summary(execution_data)

        if family in V8_HA_FAMILIES:
            return _v8_build_ha_evidence_summary(execution_data)

        return _v8_original_build_family_evidence_summary(execution_data)
# ===== v5 expanded family evidence parser end =====

# ===== v7.8 optical power evidence parser begin =====
# 目标：
# - 针对 show interface Ethernet1/10 transceiver details 输出解析 Tx Power / Rx Power。
# - 区分收光异常和发光异常。
# - 输出更准确的 notify_lines、key_findings、recommendations、conclusion。
import re as _v78e_re
from typing import Any as _V78EAny, Dict as _V78EDict, List as _V78EList

try:
    _v78e_original_build_family_evidence_summary = build_family_evidence_summary
except NameError:
    _v78e_original_build_family_evidence_summary = None


def _v78e_safe_text(value: _V78EAny) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _v78e_get_family(execution_data: _V78EDict[str, _V78EAny]) -> str:
    return _v78e_safe_text(
        ((execution_data.get("family_result") or {}).get("family"))
        or ((execution_data.get("classification") or {}).get("family"))
        or ((execution_data.get("classification") or {}).get("playbook_type"))
        or ((execution_data.get("playbook") or {}).get("playbook_id"))
    )


def _v78e_extract_command_outputs(execution_data: _V78EDict[str, _V78EAny]) -> _V78EList[_V78EDict[str, str]]:
    rows = []

    for item in execution_data.get("command_results", []) or []:
        if not isinstance(item, dict):
            continue

        rows.append({
            "capability": _v78e_safe_text(item.get("capability")),
            "command": _v78e_safe_text(item.get("command")),
            "output": _v78e_safe_text(item.get("output")),
            "error": _v78e_safe_text(item.get("error")),
            "status": _v78e_safe_text(item.get("dispatch_status") or item.get("status")),
        })

    return rows


def _v78e_all_text(execution_data: _V78EDict[str, _V78EAny]) -> str:
    parts = []
    for row in _v78e_extract_command_outputs(execution_data):
        for key in ("command", "output", "error"):
            value = _v78e_safe_text(row.get(key))
            if value:
                parts.append(value)
    return "\n".join(parts)


def _v78e_float(value):
    try:
        return float(str(value).strip())
    except Exception:
        return None


def _v78e_status_by_threshold(current, high_alarm, low_alarm, high_warning, low_warning, marker):
    marker = _v78e_safe_text(marker)

    if marker == "++":
        return "high_alarm"
    if marker == "--":
        return "low_alarm"
    if marker == "+":
        return "high_warning"
    if marker == "-":
        return "low_warning"

    if current is None:
        return "unknown"

    if high_alarm is not None and current >= high_alarm:
        return "high_alarm"
    if low_alarm is not None and current <= low_alarm:
        return "low_alarm"
    if high_warning is not None and current >= high_warning:
        return "high_warning"
    if low_warning is not None and current <= low_warning:
        return "low_warning"

    return "normal"


def _v78e_parse_transceiver_details(text: str) -> _V78EDict[str, _V78EAny]:
    facts: _V78EDict[str, _V78EAny] = {}

    m = _v78e_re.search(r"^\s*(Ethernet\S+)\s*$", text or "", flags=_v78e_re.I | _v78e_re.M)
    if m:
        facts["interface"] = m.group(1)

    if _v78e_re.search(r"transceiver\s+is\s+present", text or "", flags=_v78e_re.I):
        facts["transceiver_present"] = True
    elif _v78e_re.search(r"transceiver\s+is\s+not\s+present|not\s+inserted|absent", text or "", flags=_v78e_re.I):
        facts["transceiver_present"] = False

    for key, pattern in [
        ("transceiver_type", r"\btype\s+is\s+([^\n]+)"),
        ("transceiver_vendor", r"\bname\s+is\s+([^\n]+)"),
        ("transceiver_part_number", r"\bpart number\s+is\s+([^\n]+)"),
        ("transceiver_serial_number", r"\bserial number\s+is\s+([^\n]+)"),
        ("transceiver_product_id", r"\bcisco product id\s+is\s+([^\n]+)"),
    ]:
        m = _v78e_re.search(pattern, text or "", flags=_v78e_re.I)
        if m:
            facts[key] = m.group(1).strip()

    row_pattern = _v78e_re.compile(
        r"^\s*(Temperature|Voltage|Current|Tx\s+Power|Rx\s+Power)\s+"
        r"(-?\d+(?:\.\d+)?)\s+([A-Za-z]+)\s*([+\-]{1,2})?\s+"
        r"(-?\d+(?:\.\d+)?)\s+[A-Za-z]+\s+"
        r"(-?\d+(?:\.\d+)?)\s+[A-Za-z]+\s+"
        r"(-?\d+(?:\.\d+)?)\s+[A-Za-z]+\s+"
        r"(-?\d+(?:\.\d+)?)\s+[A-Za-z]+",
        flags=_v78e_re.I | _v78e_re.M,
    )

    measurements = {}

    for m in row_pattern.finditer(text or ""):
        raw_name = _v78e_re.sub(r"\s+", " ", m.group(1).strip()).lower()
        key = {
            "temperature": "temperature",
            "voltage": "voltage",
            "current": "bias_current",
            "tx power": "tx_power",
            "rx power": "rx_power",
        }.get(raw_name, raw_name.replace(" ", "_"))

        current = _v78e_float(m.group(2))
        unit = m.group(3)
        marker = _v78e_safe_text(m.group(4))
        high_alarm = _v78e_float(m.group(5))
        low_alarm = _v78e_float(m.group(6))
        high_warning = _v78e_float(m.group(7))
        low_warning = _v78e_float(m.group(8))

        status = _v78e_status_by_threshold(
            current=current,
            high_alarm=high_alarm,
            low_alarm=low_alarm,
            high_warning=high_warning,
            low_warning=low_warning,
            marker=marker,
        )

        item = {
            "current": current,
            "unit": unit,
            "marker": marker,
            "high_alarm": high_alarm,
            "low_alarm": low_alarm,
            "high_warning": high_warning,
            "low_warning": low_warning,
            "status": status,
        }

        measurements[key] = item

        prefix = key
        facts[f"{prefix}_current"] = current
        facts[f"{prefix}_unit"] = unit
        facts[f"{prefix}_status"] = status
        facts[f"{prefix}_high_alarm"] = high_alarm
        facts[f"{prefix}_low_alarm"] = low_alarm
        facts[f"{prefix}_high_warning"] = high_warning
        facts[f"{prefix}_low_warning"] = low_warning

    if measurements:
        facts["measurements"] = measurements

    m = _v78e_re.search(r"Transmit Fault Count\s*=\s*(\d+)", text or "", flags=_v78e_re.I)
    if m:
        try:
            facts["transmit_fault_count"] = int(m.group(1))
        except Exception:
            pass

    return facts


def _v78e_fmt_measure(name, item):
    if not item:
        return ""

    current = item.get("current")
    unit = item.get("unit") or ""
    status = item.get("status") or "unknown"
    low_alarm = item.get("low_alarm")
    high_alarm = item.get("high_alarm")
    low_warning = item.get("low_warning")
    high_warning = item.get("high_warning")

    return (
        f"{name}={current} {unit}，status={status}，"
        f"alarm_low={low_alarm}，alarm_high={high_alarm}，"
        f"warn_low={low_warning}，warn_high={high_warning}"
    )


def _v78e_build_optical_evidence_summary(execution_data: _V78EDict[str, _V78EAny]) -> _V78EDict[str, _V78EAny]:
    family = _v78e_get_family(execution_data)
    text = _v78e_all_text(execution_data)
    rows = _v78e_extract_command_outputs(execution_data)

    facts = _v78e_parse_transceiver_details(text)
    facts["family"] = family
    facts["command_count"] = len(rows)

    target_scope = execution_data.get("target_scope") or {}
    interface = _v78e_safe_text(facts.get("interface")) or _v78e_safe_text(target_scope.get("interface"))

    measurements = facts.get("measurements") or {}
    tx = measurements.get("tx_power") or {}
    rx = measurements.get("rx_power") or {}

    key_findings = []
    notify_lines = []
    recommendations = []

    if rows:
        notify_lines.append(f"光功率取证：已执行 {len(rows)} 条只读命令，优先查看接口光模块 DDM 信息。")
        key_findings.append(f"已采集接口 {interface or '未知接口'} 的光模块/光功率只读输出。")
    else:
        notify_lines.append("光功率取证：当前未产生 MCP 设备命令输出，无法判断收发光。")
        key_findings.append("光功率告警需要执行接口 transceiver details 命令补充证据。")

    if interface:
        notify_lines.append(f"光功率接口：{interface}")

    if facts.get("transceiver_present") is False:
        notify_lines.append("光模块状态：transceiver not present / absent。")
        key_findings.append("接口未检测到光模块或光模块缺失。")
        recommendations.append("优先确认本端光模块是否在位、是否被拔出或识别异常。")

    if tx or rx:
        tx_line = _v78e_fmt_measure("Tx Power", tx)
        rx_line = _v78e_fmt_measure("Rx Power", rx)

        if tx_line:
            notify_lines.append("发光功率：" + tx_line)
        if rx_line:
            notify_lines.append("收光功率：" + rx_line)

    tx_status = _v78e_safe_text(tx.get("status"))
    rx_status = _v78e_safe_text(rx.get("status"))

    if rx_status in ("low_alarm", "low_warning"):
        level = "低告警" if rx_status == "low_alarm" else "低预警"
        key_findings.append(
            f"接口 {interface or '未知接口'} 收光功率异常：Rx Power={rx.get('current')} {rx.get('unit')}，"
            f"低告警阈值={rx.get('low_alarm')}，低预警阈值={rx.get('low_warning')}，状态={rx_status}。"
        )
        recommendations.append(
            f"本端收光功率处于{level}：优先检查对端发光功率、对端端口/光模块、链路中间 ODF/跳纤/光纤衰耗、跳线弯折或端面污染。"
        )
        recommendations.append(
            "建议两端同时执行 transceiver details 对比：本端 Rx 低时，重点看对端 Tx 是否偏低；如对端 Tx 正常，则重点排查中间链路和本端接收侧。"
        )

    elif rx_status in ("high_alarm", "high_warning"):
        level = "高告警" if rx_status == "high_alarm" else "高预警"
        key_findings.append(
            f"接口 {interface or '未知接口'} 收光功率过高：Rx Power={rx.get('current')} {rx.get('unit')}，状态={rx_status}。"
        )
        recommendations.append(
            f"本端收光功率处于{level}：检查链路距离是否过短、是否需要衰减器、对端发光是否过强。"
        )

    if tx_status in ("low_alarm", "low_warning"):
        level = "低告警" if tx_status == "low_alarm" else "低预警"
        key_findings.append(
            f"接口 {interface or '未知接口'} 发光功率异常：Tx Power={tx.get('current')} {tx.get('unit')}，"
            f"低告警阈值={tx.get('low_alarm')}，低预警阈值={tx.get('low_warning')}，状态={tx_status}。"
        )
        recommendations.append(
            f"本端发光功率处于{level}：优先检查本端光模块发射侧、端口状态、光模块温度/电流，必要时更换本端光模块或跳线后复测。"
        )
        recommendations.append(
            "让对端同步查看 Rx Power：如果对端收光也低，基本可定位为本端发光或中间链路问题。"
        )

    elif tx_status in ("high_alarm", "high_warning"):
        level = "高告警" if tx_status == "high_alarm" else "高预警"
        key_findings.append(
            f"接口 {interface or '未知接口'} 发光功率过高：Tx Power={tx.get('current')} {tx.get('unit')}，状态={tx_status}。"
        )
        recommendations.append(
            f"本端发光功率处于{level}：检查光模块型号、对端接收能力和链路距离，避免对端收光过强。"
        )

    if tx_status == "normal" and rx_status == "normal":
        key_findings.append(f"接口 {interface or '未知接口'} 当前 Tx/Rx 光功率均在阈值范围内。")
        recommendations.append("当前设备侧光功率未见越限，建议结合 Prometheus 告警窗口确认是否为瞬时抖动或已恢复。")

    if not recommendations:
        recommendations.append("已采集光模块 DDM 输出，但未解析到明确 Tx/Rx 越限；建议人工复核完整 transceiver details 输出和告警窗口。")

    if rx_status in ("low_alarm", "low_warning", "high_alarm", "high_warning"):
        conclusion = "光功率只读取证完成；本端收光功率异常，下一步应优先对比对端发光与链路衰耗。"
    elif tx_status in ("low_alarm", "low_warning", "high_alarm", "high_warning"):
        conclusion = "光功率只读取证完成；本端发光功率异常，下一步应优先检查本端光模块发射侧和对端收光。"
    else:
        conclusion = "光功率只读取证完成；未解析到明确收发光越限，建议结合告警窗口和完整输出继续确认。"

    return {
        "has_facts": True,
        "family": family,
        "facts": facts,
        "key_findings": key_findings[:10],
        "recommendations": recommendations[:8],
        "notify_lines": notify_lines[:8],
        "conclusion": conclusion,
    }


if _v78e_original_build_family_evidence_summary is not None:
    def build_family_evidence_summary(execution_data):
        family = _v78e_get_family(execution_data)
        if family == "optical_power_abnormal":
            return _v78e_build_optical_evidence_summary(execution_data)
        return _v78e_original_build_family_evidence_summary(execution_data)
# ===== v7.8 optical power evidence parser end =====

# ===== v7.9 interface error delta evidence enrichment begin =====
try:
    _v79_original_build_family_evidence_summary = build_family_evidence_summary
except NameError:
    _v79_original_build_family_evidence_summary = None

if _v79_original_build_family_evidence_summary is not None:
    def build_family_evidence_summary(execution_data):
        summary = _v79_original_build_family_evidence_summary(execution_data)
        try:
            family = (
                ((execution_data.get("family_result") or {}).get("family"))
                or ((execution_data.get("classification") or {}).get("family"))
                or ((execution_data.get("classification") or {}).get("playbook_type"))
                or ""
            )
            if family == "interface_packet_loss_or_discards_high":
                from netaiops.interface_error_delta import enrich_summary_with_delta
                summary = enrich_summary_with_delta(summary, execution_data)
        except Exception:
            pass
        return summary
# ===== v7.9 interface error delta evidence enrichment end =====
