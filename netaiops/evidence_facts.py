import re
from typing import Any, Dict, List, Optional


INTERFACE_FAMILIES = {
    "interface_or_link_utilization_high",
    "interface_or_link_traffic_drop",
    "interface_packet_loss_or_discards_high",
    "interface_status_or_flap",
    "interface_flap",
}


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def parse_int(value: str) -> Optional[int]:
    try:
        return int(str(value).replace(",", "").strip())
    except Exception:
        return None


def first_match(pattern: str, text: str, flags: int = re.IGNORECASE) -> str:
    m = re.search(pattern, text or "", flags)
    if not m:
        return ""
    if m.groups():
        return safe_text(m.group(1))
    return safe_text(m.group(0))


def parse_interface_detail(output: str) -> Dict[str, Any]:
    text = output or {}
    if not isinstance(text, str):
        text = str(text)

    facts: Dict[str, Any] = {}

    m = re.search(r"^(Ethernet\S+)\s+is\s+(\S+)", text, flags=re.IGNORECASE | re.MULTILINE)
    if m:
        facts["interface"] = m.group(1)
        facts["oper_status"] = m.group(2)

    admin = first_match(r"admin state is\s+([^,\n]+)", text)
    if admin:
        facts["admin_status"] = admin

    desc = first_match(r"Port description is\s+(.+)", text)
    if desc:
        facts["description"] = desc

    po = first_match(r"Belongs to\s+(po\d+)", text)
    if po:
        facts["port_channel"] = po

    m = re.search(r"input rate\s+([0-9,]+)\s+bps.*?output rate\s+([0-9,]+)\s+bps", text, flags=re.IGNORECASE | re.DOTALL)
    if m:
        facts["input_rate_bps"] = parse_int(m.group(1))
        facts["output_rate_bps"] = parse_int(m.group(2))

    m = re.search(r"txload\s+(\d+)/255,\s+rxload\s+(\d+)/255", text, flags=re.IGNORECASE)
    if m:
        facts["txload_255"] = parse_int(m.group(1))
        facts["rxload_255"] = parse_int(m.group(2))

    for key, pattern in [
        ("crc", r"(\d+)\s+CRC\b"),
        ("input_error", r"(\d+)\s+input error\b"),
        ("input_discard", r"(\d+)\s+input discard\b"),
        ("output_error", r"(\d+)\s+output error\b"),
        ("output_discard", r"(\d+)\s+output discard\b"),
        ("output_buffer_drops", r"(\d+)\s+output buffer drops\b"),
        ("output_total_drops", r"(\d+)\s+output total drops\b"),
        ("interface_resets", r"(\d+)\s+interface resets\b"),
    ]:
        value = first_match(pattern, text)
        if value:
            facts[key] = parse_int(value)

    flapped = first_match(r"Last link flapped\s+([^\n]+)", text)
    if flapped:
        facts["last_link_flapped"] = flapped

    return facts


def parse_portchannel_summary(output: str, interface: str = "", port_channel: str = "") -> Dict[str, Any]:
    text = output or ""
    interface = safe_text(interface)
    port_channel = safe_text(port_channel)

    facts: Dict[str, Any] = {}

    if port_channel:
        po_num = re.sub(r"(?i)^po", "", port_channel)
        pattern = rf"^\s*\d+\s+Po{re.escape(po_num)}\(([^)]+)\).*"
        m = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)
        if m:
            facts["port_channel"] = f"Po{po_num}"
            facts["port_channel_state"] = m.group(1)
            line = m.group(0).strip()
            facts["port_channel_line"] = line

            if interface:
                short_if = interface.replace("Ethernet", "Eth")
                if re.search(rf"{re.escape(short_if)}\(([^)]+)\)", line, flags=re.IGNORECASE):
                    member_state = re.search(rf"{re.escape(short_if)}\(([^)]+)\)", line, flags=re.IGNORECASE).group(1)
                    facts["member_interface"] = interface
                    facts["member_state"] = member_state

    return facts


def result_by_capability(command_results: List[Dict[str, Any]], capability: str) -> Dict[str, Any]:
    for item in command_results or []:
        if safe_text(item.get("capability")) == capability:
            return item
    return {}


def build_interface_evidence_summary(execution_data: Dict[str, Any]) -> Dict[str, Any]:
    family = safe_text(
        ((execution_data.get("family_result") or {}).get("family"))
        or ((execution_data.get("classification") or {}).get("family"))
        or ((execution_data.get("classification") or {}).get("playbook_type"))
    )

    if family not in INTERFACE_FAMILIES:
        return {
            "has_facts": False,
            "family": family,
            "facts": {},
            "key_findings": [],
            "recommendations": [],
            "notify_lines": [],
            "conclusion": "",
        }

    command_results = execution_data.get("command_results", []) or []
    detail_result = result_by_capability(command_results, "show_interface_detail")
    pc_result = result_by_capability(command_results, "show_portchannel_summary")

    detail_facts = parse_interface_detail(safe_text(detail_result.get("output")))
    pc_facts = parse_portchannel_summary(
        safe_text(pc_result.get("output")),
        interface=safe_text(detail_facts.get("interface")) or safe_text((execution_data.get("target_scope") or {}).get("interface")),
        port_channel=safe_text(detail_facts.get("port_channel")),
    )

    facts = {
        **detail_facts,
        **pc_facts,
    }

    key_findings: List[str] = []
    recommendations: List[str] = []
    notify_lines: List[str] = []

    interface = safe_text(facts.get("interface")) or safe_text((execution_data.get("target_scope") or {}).get("interface"))
    oper_status = safe_text(facts.get("oper_status"))
    admin_status = safe_text(facts.get("admin_status"))
    desc = safe_text(facts.get("description"))
    port_channel = safe_text(facts.get("port_channel"))
    pc_state = safe_text(facts.get("port_channel_state"))
    member_state = safe_text(facts.get("member_state"))

    input_rate = facts.get("input_rate_bps")
    output_rate = facts.get("output_rate_bps")
    output_total_drops = facts.get("output_total_drops")
    output_buffer_drops = facts.get("output_buffer_drops")
    crc = facts.get("crc")
    input_error = facts.get("input_error")
    output_error = facts.get("output_error")
    last_flap = safe_text(facts.get("last_link_flapped"))

    if interface or oper_status or admin_status:
        line = f"接口状态：{interface or '未知接口'} oper={oper_status or '未知'} admin={admin_status or '未知'}"
        key_findings.append(line)
        notify_lines.append(line)

    if desc:
        key_findings.append(f"接口描述/对端信息：{desc}")

    if input_rate is not None or output_rate is not None:
        line = f"取证时实时速率：input={input_rate if input_rate is not None else '未知'} bps，output={output_rate if output_rate is not None else '未知'} bps。"
        key_findings.append(line)
        notify_lines.append(line)

    if port_channel:
        line = f"聚合关系：{interface or '该接口'} 属于 {port_channel}"
        if pc_state:
            line += f"，聚合口状态={pc_state}"
        if member_state:
            line += f"，成员状态={member_state}"
        key_findings.append(line)
        notify_lines.append(line)

    error_parts = []
    if crc is not None:
        error_parts.append(f"CRC={crc}")
    if input_error is not None:
        error_parts.append(f"input_error={input_error}")
    if output_error is not None:
        error_parts.append(f"output_error={output_error}")
    if output_total_drops is not None:
        error_parts.append(f"output_total_drops={output_total_drops}")
    if output_buffer_drops is not None:
        error_parts.append(f"output_buffer_drops={output_buffer_drops}")

    if error_parts:
        line = "接口错误/丢弃计数：" + "，".join(error_parts)
        key_findings.append(line)
        notify_lines.append(line)

    if last_flap:
        key_findings.append(f"最近链路抖动时间：{last_flap}")

    if output_rate is not None and output_rate < 1_000_000:
        key_findings.append("本次取证时接口出向实时速率已经较低，建议结合 Prometheus 历史窗口确认告警触发时是否为瞬时峰值或已恢复。")
        recommendations.append("对比告警触发时间点前后 5-15 分钟的接口出向速率曲线，确认高利用率是否持续存在。")

    if isinstance(output_total_drops, int) and output_total_drops > 0:
        key_findings.append(f"发现累计 output total drops={output_total_drops}，需要结合清零时间和增长速率判断是否仍在持续增长。")
        recommendations.append("重点观察 output drops 是否持续递增；如果持续增长，进一步核查拥塞、队列、上联聚合和对端流量来源。")

    if isinstance(output_buffer_drops, int) and output_buffer_drops > 0:
        recommendations.append("检查接口队列/缓冲相关计数及是否存在微突发流量。")

    if pc_state and "U" in pc_state and member_state and "P" in member_state:
        key_findings.append("聚合口和成员口状态正常，当前证据不支持聚合成员异常。")

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

    conclusion_parts = []
    if interface:
        conclusion_parts.append(f"{interface} 只读取证完成")
    else:
        conclusion_parts.append("接口只读取证完成")

    if oper_status or admin_status:
        conclusion_parts.append(f"接口状态 oper={oper_status or '未知'} / admin={admin_status or '未知'}")

    if output_rate is not None:
        conclusion_parts.append(f"取证时 output rate={output_rate} bps")

    if isinstance(output_total_drops, int) and output_total_drops > 0:
        conclusion_parts.append(f"存在累计 output drops={output_total_drops}")

    conclusion = "；".join(conclusion_parts) + "。建议结合告警时间窗口的指标曲线判断是否为持续高利用率或瞬时峰值。"

    if not recommendations:
        recommendations.append("结合告警时间窗口继续核查接口流量趋势、对端流量来源和业务高峰情况。")

    return {
        "has_facts": True,
        "family": family,
        "facts": facts,
        "key_findings": key_findings[:8],
        "recommendations": recommendations[:6],
        "notify_lines": notify_lines[:6],
        "conclusion": conclusion,
    }
