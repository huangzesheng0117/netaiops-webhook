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

# ===== v5 interface traffic facts enhancement begin =====
# 增强接口类告警的流量/利用率事实提炼。
# 目标：
# 1. 从 show interface 输出中解析 input/output rate。
# 2. 从 BW / bandwidth 中解析接口带宽。
# 3. 根据告警方向计算当前设备侧估算利用率。
# 4. 在 evidence_summary.notify_lines 中补充更贴近“利用率告警”的事实。
import re as _v5_re
from typing import Any as _V5Any, Dict as _V5Dict, List as _V5List, Optional as _V5Optional


try:
    _v5_original_build_interface_evidence_summary = build_interface_evidence_summary
except NameError:
    _v5_original_build_interface_evidence_summary = None


def _v5_safe_text(value: _V5Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _v5_parse_number(value: str) -> _V5Optional[float]:
    try:
        return float(str(value).replace(",", "").strip())
    except Exception:
        return None


def _v5_unit_to_bps(value: float, unit: str) -> int:
    unit_l = _v5_safe_text(unit).lower()

    if unit_l in ("bps", "bit/sec", "bits/sec", "bit/s", "bits/s"):
        return int(value)

    if unit_l in ("kbps", "kbit/sec", "kbits/sec", "kbit/s", "kbits/s", "k"):
        return int(value * 1000)

    if unit_l in ("mbps", "mbit/sec", "mbits/sec", "mbit/s", "mbits/s", "m"):
        return int(value * 1000 * 1000)

    if unit_l in ("gbps", "gbit/sec", "gbits/sec", "gbit/s", "gbits/s", "g"):
        return int(value * 1000 * 1000 * 1000)

    return int(value)


def _v5_parse_rate_bps(label: str, text: str) -> _V5Optional[int]:
    patterns = [
        rf"(?:5\s+minute|30\s+seconds|30\s+second|1\s+minute)?\s*{label}\s+rate\s+([0-9,]+(?:\.[0-9]+)?)\s*(bps|bits/sec|bit/sec|bits/s|bit/s|Kbps|Kbit/sec|Kbits/sec|Mbps|Mbit/sec|Mbits/sec|Gbps|Gbit/sec|Gbits/sec)",
        rf"{label}\s*:\s*([0-9,]+(?:\.[0-9]+)?)\s*(bps|bits/sec|bit/sec|bits/s|bit/s|Kbps|Kbit/sec|Kbits/sec|Mbps|Mbit/sec|Mbits/sec|Gbps|Gbit/sec|Gbits/sec)",
    ]

    for pattern in patterns:
        m = _v5_re.search(pattern, text or "", flags=_v5_re.IGNORECASE)
        if not m:
            continue

        num = _v5_parse_number(m.group(1))
        if num is None:
            continue

        return _v5_unit_to_bps(num, m.group(2))

    return None


def _v5_parse_bandwidth_bps(text: str) -> _V5Optional[int]:
    patterns = [
        r"\bBW\s+([0-9,]+(?:\.[0-9]+)?)\s*(Kbit|Kbit/sec|Mbit|Mbit/sec|Gbit|Gbit/sec|bps|bits/sec)",
        r"\bbandwidth\s+([0-9,]+(?:\.[0-9]+)?)\s*(Kbit|Kbit/sec|Mbit|Mbit/sec|Gbit|Gbit/sec|bps|bits/sec)",
        r"\b([0-9,]+(?:\.[0-9]+)?)\s*(Gb/s|Mbps|Gbps|Mbit/sec|Gbit/sec)\b",
    ]

    for pattern in patterns:
        m = _v5_re.search(pattern, text or "", flags=_v5_re.IGNORECASE)
        if not m:
            continue

        num = _v5_parse_number(m.group(1))
        if num is None:
            continue

        unit = m.group(2).lower().replace("gb/s", "gbps")

        if unit == "kbit":
            unit = "kbit/sec"
        elif unit == "mbit":
            unit = "mbit/sec"
        elif unit == "gbit":
            unit = "gbit/sec"

        return _v5_unit_to_bps(num, unit)

    return None


def _v5_parse_interface_status(text: str) -> _V5Dict[str, str]:
    facts: _V5Dict[str, str] = {}

    m = _v5_re.search(
        r"^\s*([A-Za-z]+[A-Za-z0-9\/\.\-]+|port-channel\d+|Port-channel\d+|Po\d+)\s+is\s+([^,\n]+)",
        text or "",
        flags=_v5_re.IGNORECASE | _v5_re.MULTILINE,
    )
    if m:
        facts["interface"] = m.group(1)
        facts["oper_status"] = m.group(2).strip()

    m = _v5_re.search(r"line protocol\s+is\s+([^,\n]+)", text or "", flags=_v5_re.IGNORECASE)
    if m and not facts.get("oper_status"):
        facts["oper_status"] = m.group(1).strip()

    m = _v5_re.search(r"admin state is\s+([^,\n]+)", text or "", flags=_v5_re.IGNORECASE)
    if m:
        facts["admin_status"] = m.group(1).strip()

    if not facts.get("admin_status"):
        if _v5_re.search(r"administratively\s+down", text or "", flags=_v5_re.IGNORECASE):
            facts["admin_status"] = "down"
        elif facts.get("oper_status"):
            facts["admin_status"] = "up"

    return facts


def _v5_guess_alarm_direction(execution_data: _V5Dict[str, _V5Any]) -> str:
    target_scope = execution_data.get("target_scope", {}) or {}

    text = " ".join(
        [
            _v5_safe_text(target_scope.get("direction")),
            _v5_safe_text(target_scope.get("alarm_type")),
            _v5_safe_text(target_scope.get("raw_text")),
            _v5_safe_text(target_scope.get("summary")),
            _v5_safe_text(((execution_data.get("event") or {}).get("raw_text"))),
            _v5_safe_text(((execution_data.get("event") or {}).get("alarm_type"))),
            _v5_safe_text(((execution_data.get("classification") or {}).get("alarm_type"))),
        ]
    )

    if "入向" in text or "入方向" in text or "inbound" in text.lower() or "input" in text.lower():
        return "in"

    if "出向" in text or "出方向" in text or "outbound" in text.lower() or "output" in text.lower():
        return "out"

    return ""


def _v5_collect_interface_outputs(execution_data: _V5Dict[str, _V5Any]) -> str:
    outputs: _V5List[str] = []

    for item in execution_data.get("command_results", []) or []:
        capability = _v5_safe_text(item.get("capability"))
        command = _v5_safe_text(item.get("command"))
        output = _v5_safe_text(item.get("output"))

        if not output:
            continue

        if capability in (
            "show_interface_detail",
            "show_interface_error_counters",
            "show_interface_brief",
        ):
            outputs.append(output)
            continue

        if "show interface" in command.lower() or "display interface" in command.lower():
            outputs.append(output)

    return "\n".join(outputs)


def _v5_percent(value: int, bandwidth: int) -> float:
    if not bandwidth:
        return 0.0
    return round((float(value) / float(bandwidth)) * 100.0, 2)


def _v5_format_bps(value: _V5Optional[int]) -> str:
    if value is None:
        return "未知"

    v = float(value)

    if v >= 1000 * 1000 * 1000:
        return f"{v / 1000 / 1000 / 1000:.2f} Gbps"

    if v >= 1000 * 1000:
        return f"{v / 1000 / 1000:.2f} Mbps"

    if v >= 1000:
        return f"{v / 1000:.2f} Kbps"

    return f"{int(v)} bps"



# ===== v5 interface traffic fact scope guard begin =====
# 只有流量/利用率类 family 才展示接口带宽、实时速率、估算利用率和流量判断。
# 接口状态变化、接口 flap、错包/丢包类告警不展示这些流量类事实，避免误导值班人员。
V5_TRAFFIC_METRIC_FAMILIES = {
    "interface_or_link_utilization_high",
    "interface_or_link_traffic_drop",
}


def _v5_get_execution_family(execution_data):
    if not isinstance(execution_data, dict):
        return ""

    return _v5_safe_text(
        ((execution_data.get("family_result") or {}).get("family"))
        or ((execution_data.get("classification") or {}).get("family"))
        or ((execution_data.get("classification") or {}).get("playbook_type"))
        or ((execution_data.get("playbook") or {}).get("playbook_id"))
    )


def _v5_should_add_interface_traffic_facts(execution_data):
    family = _v5_get_execution_family(execution_data)

    if family in V5_TRAFFIC_METRIC_FAMILIES:
        return True

    # 老数据可能没有 family_result，做一个兜底判断：
    # 只有明确出现“利用率 / 流量突降 / traffic drop / utilization”时才开启。
    if not family:
        target_scope = execution_data.get("target_scope", {}) or {}
        blob = " ".join(
            [
                _v5_safe_text(target_scope.get("alarm_type")),
                _v5_safe_text(target_scope.get("raw_text")),
                _v5_safe_text((execution_data.get("event") or {}).get("alarm_type")),
                _v5_safe_text((execution_data.get("event") or {}).get("raw_text")),
            ]
        ).lower()

        if (
            "利用率" in blob
            or "流量突降" in blob
            or "utilization" in blob
            or "traffic drop" in blob
        ):
            return True

    return False
# ===== v5 interface traffic fact scope guard end =====

def _v5_enrich_interface_traffic_summary(
    summary: _V5Dict[str, _V5Any],
    execution_data: _V5Dict[str, _V5Any],
) -> _V5Dict[str, _V5Any]:
    summary = dict(summary or {})

    if not _v5_should_add_interface_traffic_facts(execution_data):
        return summary

    outputs = _v5_collect_interface_outputs(execution_data)
    if not outputs:
        return summary

    facts = dict(summary.get("facts", {}) or {})
    notify_lines = list(summary.get("notify_lines", []) or [])
    key_findings = list(summary.get("key_findings", []) or [])
    recommendations = list(summary.get("recommendations", []) or [])

    parsed_status = _v5_parse_interface_status(outputs)
    for key, value in parsed_status.items():
        if value and (not facts.get(key) or _v5_safe_text(facts.get(key)) == "未知"):
            facts[key] = value

    input_rate = facts.get("input_rate_bps")
    output_rate = facts.get("output_rate_bps")
    bandwidth = facts.get("bandwidth_bps")

    parsed_input_rate = _v5_parse_rate_bps("input", outputs)
    parsed_output_rate = _v5_parse_rate_bps("output", outputs)
    parsed_bandwidth = _v5_parse_bandwidth_bps(outputs)

    if input_rate is None and parsed_input_rate is not None:
        input_rate = parsed_input_rate
        facts["input_rate_bps"] = parsed_input_rate

    if output_rate is None and parsed_output_rate is not None:
        output_rate = parsed_output_rate
        facts["output_rate_bps"] = parsed_output_rate

    if bandwidth is None and parsed_bandwidth is not None:
        bandwidth = parsed_bandwidth
        facts["bandwidth_bps"] = parsed_bandwidth

    direction = _v5_guess_alarm_direction(execution_data)
    if direction:
        facts["alarm_direction"] = direction

    input_util = None
    output_util = None

    if isinstance(bandwidth, int) and bandwidth > 0:
        if isinstance(input_rate, int):
            input_util = _v5_percent(input_rate, bandwidth)
            facts["input_utilization_percent_estimated"] = input_util

        if isinstance(output_rate, int):
            output_util = _v5_percent(output_rate, bandwidth)
            facts["output_utilization_percent_estimated"] = output_util

    inserted_lines: _V5List[str] = []

    if direction:
        inserted_lines.append(f"告警方向：{'入向' if direction == 'in' else '出向'}")

    if bandwidth:
        inserted_lines.append(f"接口带宽：{_v5_format_bps(bandwidth)}")

    if input_rate is not None or output_rate is not None:
        inserted_lines.append(
            f"设备侧实时速率：input={_v5_format_bps(input_rate)}，output={_v5_format_bps(output_rate)}"
        )

    if input_util is not None or output_util is not None:
        inserted_lines.append(
            f"设备侧估算利用率：input={input_util if input_util is not None else '未知'}%，"
            f"output={output_util if output_util is not None else '未知'}%"
        )

    if direction == "in" and input_util is not None:
        if input_util >= 80:
            inserted_lines.append(f"流量判断：取证时入向利用率约 {input_util}%，仍处于高利用率状态。")
            recommendations.insert(0, "取证时设备侧入向利用率仍偏高，建议继续定位入向流量来源、业务高峰和上联链路容量。")
        else:
            inserted_lines.append(f"流量判断：取证时入向利用率约 {input_util}%，低于80%阈值，更像瞬时峰值或已恢复。")
            recommendations.insert(0, "取证时设备侧入向利用率已低于阈值，建议结合告警时间窗口指标确认是否为瞬时峰值。")

    if direction == "out" and output_util is not None:
        if output_util >= 80:
            inserted_lines.append(f"流量判断：取证时出向利用率约 {output_util}%，仍处于高利用率状态。")
            recommendations.insert(0, "取证时设备侧出向利用率仍偏高，建议继续定位出向流量来源、业务高峰和上联链路容量。")
        else:
            inserted_lines.append(f"流量判断：取证时出向利用率约 {output_util}%，低于80%阈值，更像瞬时峰值或已恢复。")
            recommendations.insert(0, "取证时设备侧出向利用率已低于阈值，建议结合告警时间窗口指标确认是否为瞬时峰值。")

    if inserted_lines:
        new_notify_lines = []
        for line in notify_lines:
            new_notify_lines.append(line)
            if line.startswith("接口状态"):
                for item in inserted_lines:
                    new_notify_lines.append(item)

        if not any(line in new_notify_lines for line in inserted_lines):
            new_notify_lines = inserted_lines + new_notify_lines

        notify_lines = new_notify_lines

        key_findings = inserted_lines + key_findings

    summary["facts"] = facts
    summary["notify_lines"] = notify_lines[:10]
    summary["key_findings"] = key_findings[:14]

    dedup_recommendations = []
    seen = set()
    for item in recommendations:
        value = _v5_safe_text(item)
        if not value or value in seen:
            continue
        seen.add(value)
        dedup_recommendations.append(value)

    summary["recommendations"] = dedup_recommendations[:8]

    conclusion = _v5_safe_text(summary.get("conclusion"))
    if direction == "in" and input_util is not None:
        summary["conclusion"] = (
            conclusion
            + f" 设备侧取证时入向估算利用率约 {input_util}%。"
        ).strip()

    if direction == "out" and output_util is not None:
        summary["conclusion"] = (
            conclusion
            + f" 设备侧取证时出向估算利用率约 {output_util}%。"
        ).strip()

    return summary


if _v5_original_build_interface_evidence_summary is not None:
    def build_interface_evidence_summary(execution_data: _V5Dict[str, _V5Any]) -> _V5Dict[str, _V5Any]:
        base_summary = _v5_original_build_interface_evidence_summary(execution_data)
        return _v5_enrich_interface_traffic_summary(base_summary, execution_data)
# ===== v5 interface traffic facts enhancement end =====

# ===== v5 business bandwidth facts enhancement begin =====
# 增强“告警口径带宽”解析：
# 1. 从告警名、raw_text、labels、annotations、Prometheus expression 中解析 100M / 300M / 1G 等业务带宽。
# 2. 如果解析到业务带宽，则同时计算物理接口口径利用率和告警业务口径利用率。
# 3. 避免只按设备物理接口 10G 计算而掩盖 300M/100M 线路告警口径。
import json as _v5b_json
from pathlib import Path as _V5BPath
from typing import Any as _V5BAny, Dict as _V5BDict, List as _V5BList, Optional as _V5BOptional, Tuple as _V5BTuple

try:
    _v5b_original_build_interface_evidence_summary = build_interface_evidence_summary
except NameError:
    _v5b_original_build_interface_evidence_summary = None


_V5B_BASE_DIR = _V5BPath("/opt/netaiops-webhook")
_V5B_DATA_DIR = _V5B_BASE_DIR / "data"
_V5B_NORMALIZED_DIR = _V5B_DATA_DIR / "normalized"
_V5B_ANALYSIS_DIR = _V5B_DATA_DIR / "analysis"


def _v5b_safe_text(value: _V5BAny) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        try:
            return _v5b_json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)
    return str(value).strip()


def _v5b_find_file_by_request_id(directory: _V5BPath, request_id: str, suffix: str) -> _V5BOptional[_V5BPath]:
    try:
        files = list(directory.glob(f"*_{request_id}.{suffix}"))
        if files:
            return files[0]
    except Exception:
        pass
    return None


def _v5b_load_json(path: _V5BOptional[_V5BPath]) -> _V5BDict[str, _V5BAny]:
    if not path or not path.exists():
        return {}
    try:
        return _v5b_json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _v5b_load_event_context(request_id: str) -> _V5BDict[str, _V5BAny]:
    normalized_file = _v5b_find_file_by_request_id(_V5B_NORMALIZED_DIR, request_id, "json")
    normalized_data = _v5b_load_json(normalized_file)

    events = normalized_data.get("events", []) or []
    if events and isinstance(events[0], dict):
        event = dict(events[0])
        event["_normalized_file"] = str(normalized_file)
        return event

    analysis_file = _v5b_find_file_by_request_id(_V5B_ANALYSIS_DIR, request_id, "analysis.json")
    analysis_data = _v5b_load_json(analysis_file)
    event = analysis_data.get("event", {}) or {}
    if isinstance(event, dict):
        event = dict(event)
        event["_analysis_file"] = str(analysis_file)
        return event

    return {}


def _v5b_collect_alarm_context_text(execution_data: _V5BDict[str, _V5BAny]) -> _V5BTuple[str, str]:
    request_id = _v5b_safe_text(execution_data.get("request_id"))
    target_scope = execution_data.get("target_scope", {}) or {}
    event_in_execution = execution_data.get("event", {}) or {}
    classification = execution_data.get("classification", {}) or {}
    family_result = execution_data.get("family_result", {}) or {}

    loaded_event = _v5b_load_event_context(request_id)

    parts: _V5BList[str] = []
    source_parts: _V5BList[str] = []

    for source_name, obj in [
        ("target_scope", target_scope),
        ("execution_event", event_in_execution),
        ("normalized_event", loaded_event),
        ("classification", classification),
        ("family_result", family_result),
    ]:
        if not isinstance(obj, dict):
            continue

        for key in (
            "alarm_type",
            "raw_text",
            "summary",
            "description",
            "expr",
            "expression",
            "query",
            "generatorURL",
            "generator_url",
            "if_alias",
            "ifAlias",
            "object_name",
        ):
            value = _v5b_safe_text(obj.get(key))
            if value:
                parts.append(value)
                source_parts.append(f"{source_name}.{key}")

        labels = obj.get("labels")
        if isinstance(labels, dict):
            parts.append(_v5b_safe_text(labels))
            source_parts.append(f"{source_name}.labels")

        annotations = obj.get("annotations")
        if isinstance(annotations, dict):
            parts.append(_v5b_safe_text(annotations))
            source_parts.append(f"{source_name}.annotations")

    return " ".join(parts), ",".join(source_parts)


def _v5b_unit_to_bps(value: float, unit: str) -> int:
    unit_l = _v5b_safe_text(unit).lower().replace("bit/sec", "bps").replace("bits/sec", "bps")

    if unit_l in ("k", "kb", "kbps", "kbit", "kbits", "kbit/s", "kbits/s"):
        return int(value * 1000)

    if unit_l in ("m", "mb", "mbps", "mbit", "mbits", "mbit/s", "mbits/s"):
        return int(value * 1000 * 1000)

    if unit_l in ("g", "gb", "gbps", "gbit", "gbits", "gbit/s", "gbits/s"):
        return int(value * 1000 * 1000 * 1000)

    if unit_l in ("bps", "bit/s", "bits/s"):
        return int(value)

    return int(value)


def _v5b_parse_number(value: str) -> _V5BOptional[float]:
    try:
        return float(str(value).replace(",", "").strip())
    except Exception:
        return None


def _v5b_parse_business_bandwidth_from_text(text: str) -> _V5BTuple[_V5BOptional[int], str, str]:
    text = _v5b_safe_text(text)
    if not text:
        return None, "", ""

    candidates: _V5BList[_V5BTuple[int, int, str, str]] = []

    # 优先匹配明显的业务带宽表达，例如 CTC_300M、_100M_利用率、带宽300M、线路1G
    pattern = _v5_re.compile(
        r"(?<![A-Za-z0-9])([0-9]+(?:\.[0-9]+)?)\s*(G|Gbps|Gbit|Gbits|M|Mbps|Mbit|Mbits|K|Kbps|Kbit|Kbits)(?![A-Za-z0-9])",
        flags=_v5_re.IGNORECASE,
    )

    for m in pattern.finditer(text):
        num = _v5b_parse_number(m.group(1))
        unit = m.group(2)

        if num is None:
            continue

        bps = _v5b_unit_to_bps(num, unit)

        # 过滤过小值，避免误识别。
        if bps < 1000 * 1000:
            continue

        left = text[max(0, m.start() - 20):m.start()]
        right = text[m.end():m.end() + 30]
        context = left + m.group(0) + right

        score = 0
        if any(x in context for x in ("线路", "带宽", "利用率", "CTC", "GDS", "电信", "联通", "移动", "互联网", "专线", "出口", "入向", "出向")):
            score += 20
        if "_" in context or "-" in context:
            score += 5
        if "80%" in context or "超过" in context:
            score += 5

        candidates.append((score, bps, m.group(0), context))

    if candidates:
        candidates.sort(key=lambda x: (x[0], x[1]), reverse=True)
        _, bps, raw, context = candidates[0]
        return bps, raw, context

    return None, "", ""


def _v5b_parse_threshold_percent(text: str) -> _V5BOptional[float]:
    patterns = [
        r"超过\s*([0-9]+(?:\.[0-9]+)?)\s*%",
        r">\s*([0-9]+(?:\.[0-9]+)?)\s*%",
        r"利用率.*?([0-9]+(?:\.[0-9]+)?)\s*%",
    ]

    for pattern in patterns:
        m = _v5_re.search(pattern, text or "", flags=_v5_re.IGNORECASE)
        if m:
            return _v5b_parse_number(m.group(1))

    return None


def _v5b_parse_query_threshold_bps(text: str) -> _V5BOptional[float]:
    # 例如：sum(irate(ifHCInOctets[2m]))*8 > 80000000
    m = _v5_re.search(r">\s*([0-9]+(?:\.[0-9]+)?(?:e[0-9]+)?)", text or "", flags=_v5_re.IGNORECASE)
    if not m:
        return None

    try:
        return float(m.group(1))
    except Exception:
        return None


def _v5b_infer_business_bandwidth_from_threshold(text: str) -> _V5BTuple[_V5BOptional[int], str, str]:
    threshold_percent = _v5b_parse_threshold_percent(text)
    threshold_bps = _v5b_parse_query_threshold_bps(text)

    if not threshold_percent or not threshold_bps:
        return None, "", ""

    if threshold_percent <= 0:
        return None, "", ""

    bps = int(threshold_bps / (threshold_percent / 100.0))
    if bps < 1000 * 1000:
        return None, "", ""

    return bps, f"threshold={threshold_bps},percent={threshold_percent}", "prometheus_threshold_inference"


def _v5b_format_bps(value: _V5BOptional[int]) -> str:
    if value is None:
        return "未知"

    v = float(value)

    if v >= 1000 * 1000 * 1000:
        return f"{v / 1000 / 1000 / 1000:.2f} Gbps"

    if v >= 1000 * 1000:
        return f"{v / 1000 / 1000:.2f} Mbps"

    if v >= 1000:
        return f"{v / 1000:.2f} Kbps"

    return f"{int(v)} bps"


def _v5b_percent(value: int, bandwidth: int) -> float:
    if not bandwidth:
        return 0.0
    return round((float(value) / float(bandwidth)) * 100.0, 2)


def _v5b_insert_after_line(lines: _V5BList[str], startswith_text: str, insert_lines: _V5BList[str]) -> _V5BList[str]:
    if not insert_lines:
        return lines

    out: _V5BList[str] = []
    inserted = False

    for line in lines:
        out.append(line)
        if not inserted and _v5b_safe_text(line).startswith(startswith_text):
            out.extend(insert_lines)
            inserted = True

    if not inserted:
        out = insert_lines + out

    return out


def _v5b_enrich_business_bandwidth_summary(
    summary: _V5BDict[str, _V5BAny],
    execution_data: _V5BDict[str, _V5BAny],
) -> _V5BDict[str, _V5BAny]:
    summary = dict(summary or {})

    if not _v5_should_add_interface_traffic_facts(execution_data):
        return summary

    facts = dict(summary.get("facts", {}) or {})

    context_text, context_source = _v5b_collect_alarm_context_text(execution_data)

    business_bandwidth, raw_bandwidth_text, bandwidth_context = _v5b_parse_business_bandwidth_from_text(context_text)
    business_bandwidth_source = "alarm_text"

    if business_bandwidth is None:
        business_bandwidth, raw_bandwidth_text, bandwidth_context = _v5b_infer_business_bandwidth_from_threshold(context_text)
        business_bandwidth_source = "prometheus_threshold_inference"

    if business_bandwidth is None:
        return summary

    facts["business_bandwidth_bps"] = business_bandwidth
    facts["business_bandwidth_text"] = raw_bandwidth_text
    facts["business_bandwidth_source"] = business_bandwidth_source
    facts["business_bandwidth_context"] = bandwidth_context
    facts["business_bandwidth_context_source"] = context_source

    input_rate = facts.get("input_rate_bps")
    output_rate = facts.get("output_rate_bps")
    direction = _v5b_safe_text(facts.get("alarm_direction"))

    input_business_util = None
    output_business_util = None

    if isinstance(input_rate, int):
        input_business_util = _v5b_percent(input_rate, business_bandwidth)
        facts["input_utilization_percent_business_estimated"] = input_business_util

    if isinstance(output_rate, int):
        output_business_util = _v5b_percent(output_rate, business_bandwidth)
        facts["output_utilization_percent_business_estimated"] = output_business_util

    notify_lines = list(summary.get("notify_lines", []) or [])
    key_findings = list(summary.get("key_findings", []) or [])
    recommendations = list(summary.get("recommendations", []) or [])

    # 避免“接口带宽”歧义，解析到业务带宽后，把原有物理带宽展示改名。
    new_notify_lines = []
    for line in notify_lines:
        if _v5b_safe_text(line).startswith("接口带宽："):
            new_notify_lines.append(line.replace("接口带宽：", "接口物理带宽：", 1))
        else:
            new_notify_lines.append(line)

    notify_lines = new_notify_lines

    insert_lines: _V5BList[str] = [
        f"告警口径带宽：{_v5b_format_bps(business_bandwidth)}（来源：{business_bandwidth_source}）"
    ]

    if input_business_util is not None or output_business_util is not None:
        insert_lines.append(
            f"按告警口径估算利用率：input={input_business_util if input_business_util is not None else '未知'}%，"
            f"output={output_business_util if output_business_util is not None else '未知'}%"
        )

    if direction == "in" and input_business_util is not None:
        if input_business_util >= 80:
            insert_lines.append(f"告警口径流量判断：取证时入向利用率约 {input_business_util}%，仍处于高利用率状态。")
            recommendations.insert(0, "按告警口径计算，取证时入向利用率仍偏高，建议继续定位入向流量来源、业务高峰和线路容量。")
        else:
            insert_lines.append(f"告警口径流量判断：取证时入向利用率约 {input_business_util}%，低于80%阈值，更像瞬时峰值或已恢复。")
            recommendations.insert(0, "按告警口径计算，取证时入向利用率已低于阈值，建议结合 Prometheus 告警窗口确认是否为瞬时峰值。")

    if direction == "out" and output_business_util is not None:
        if output_business_util >= 80:
            insert_lines.append(f"告警口径流量判断：取证时出向利用率约 {output_business_util}%，仍处于高利用率状态。")
            recommendations.insert(0, "按告警口径计算，取证时出向利用率仍偏高，建议继续定位出向流量来源、业务高峰和线路容量。")
        else:
            insert_lines.append(f"告警口径流量判断：取证时出向利用率约 {output_business_util}%，低于80%阈值，更像瞬时峰值或已恢复。")
            recommendations.insert(0, "按告警口径计算，取证时出向利用率已低于阈值，建议结合 Prometheus 告警窗口确认是否为瞬时峰值。")

    notify_lines = _v5b_insert_after_line(notify_lines, "接口物理带宽", insert_lines)

    key_findings = insert_lines + key_findings

    dedup_recommendations = []
    seen = set()
    for item in recommendations:
        value = _v5b_safe_text(item)
        if not value or value in seen:
            continue
        seen.add(value)
        dedup_recommendations.append(value)

    summary["facts"] = facts
    summary["notify_lines"] = notify_lines[:14]
    summary["key_findings"] = key_findings[:18]
    summary["recommendations"] = dedup_recommendations[:8]

    conclusion = _v5b_safe_text(summary.get("conclusion"))
    if direction == "in" and input_business_util is not None:
        summary["conclusion"] = (
            conclusion
            + f" 告警口径带宽为 {_v5b_format_bps(business_bandwidth)}，按告警口径取证时入向估算利用率约 {input_business_util}%。"
        ).strip()

    if direction == "out" and output_business_util is not None:
        summary["conclusion"] = (
            conclusion
            + f" 告警口径带宽为 {_v5b_format_bps(business_bandwidth)}，按告警口径取证时出向估算利用率约 {output_business_util}%。"
        ).strip()

    return summary


if _v5b_original_build_interface_evidence_summary is not None:
    def build_interface_evidence_summary(execution_data: _V5BDict[str, _V5BAny]) -> _V5BDict[str, _V5BAny]:
        base_summary = _v5b_original_build_interface_evidence_summary(execution_data)
        return _v5b_enrich_business_bandwidth_summary(base_summary, execution_data)
# ===== v5 business bandwidth facts enhancement end =====

# ===== v5 non-traffic family rate fact final filter begin =====
# 上一层 guard 已经限制了大部分流量/利用率事实，但旧版基础解析中仍可能生成：
# “取证时实时速率：input=... output=...”
# 这里做最终兜底过滤：
# 只有 interface_or_link_utilization_high / interface_or_link_traffic_drop 才允许展示速率/利用率事实。
# 其他 family 一律过滤带宽、速率、利用率、流量判断等 notify_lines / key_findings / conclusion 片段。

try:
    _v11_original_build_interface_evidence_summary = build_interface_evidence_summary
except NameError:
    _v11_original_build_interface_evidence_summary = None


V11_TRAFFIC_FACT_KEYWORDS = [
    "接口带宽",
    "接口物理带宽",
    "设备侧实时速率",
    "设备侧估算利用率",
    "取证时实时速率",
    "流量判断",
    "告警口径带宽",
    "按告警口径估算利用率",
    "告警口径流量判断",
    "Prometheus告警窗口入向速率",
    "Prometheus告警窗口出向速率",
]


V11_TRAFFIC_FACT_KEYS = [
    "input_rate_bps",
    "output_rate_bps",
    "bandwidth_bps",
    "business_bandwidth_bps",
    "business_bandwidth_text",
    "business_bandwidth_source",
    "business_bandwidth_context",
    "business_bandwidth_context_source",
    "input_utilization_percent_estimated",
    "output_utilization_percent_estimated",
    "input_utilization_percent_business_estimated",
    "output_utilization_percent_business_estimated",
]


def _v11_safe_text(value):
    if value is None:
        return ""
    return str(value).strip()


def _v11_is_traffic_family(execution_data):
    try:
        return bool(_v5_should_add_interface_traffic_facts(execution_data))
    except Exception:
        family = _v11_safe_text(
            ((execution_data.get("family_result") or {}).get("family"))
            or ((execution_data.get("classification") or {}).get("family"))
            or ((execution_data.get("classification") or {}).get("playbook_type"))
            or ((execution_data.get("playbook") or {}).get("playbook_id"))
        )

        return family in {
            "interface_or_link_utilization_high",
            "interface_or_link_traffic_drop",
        }


def _v11_line_has_traffic_fact(line):
    text = _v11_safe_text(line)
    return any(keyword in text for keyword in V11_TRAFFIC_FACT_KEYWORDS)


def _v11_filter_lines(lines):
    result = []

    for line in lines or []:
        if _v11_line_has_traffic_fact(line):
            continue
        result.append(line)

    return result


def _v11_filter_conclusion(conclusion):
    text = _v11_safe_text(conclusion)
    if not text:
        return text

    # 按中文句号/分号做轻量切分，去掉含速率/利用率事实的句子。
    parts = []
    current = ""

    for ch in text:
        current += ch
        if ch in "。；;":
            parts.append(current.strip())
            current = ""

    if current.strip():
        parts.append(current.strip())

    filtered = [
        part for part in parts
        if not _v11_line_has_traffic_fact(part)
        and "output rate" not in part.lower()
        and "input rate" not in part.lower()
        and "rate=" not in part.lower()
    ]

    if filtered:
        return "".join(filtered).strip()

    # 如果全部被过滤，保留一个不含速率的兜底结论。
    return "接口状态类只读取证完成；建议结合接口状态、聚合关系和日志时间线判断是否存在链路抖动、模块异常或链路切换。"


def _v11_filter_non_traffic_summary(summary, execution_data):
    if _v11_is_traffic_family(execution_data):
        return summary

    summary = dict(summary or {})

    summary["notify_lines"] = _v11_filter_lines(summary.get("notify_lines", []) or [])
    summary["key_findings"] = _v11_filter_lines(summary.get("key_findings", []) or [])
    summary["recommendations"] = _v11_filter_lines(summary.get("recommendations", []) or [])

    facts = dict(summary.get("facts", {}) or {})
    for key in V11_TRAFFIC_FACT_KEYS:
        facts.pop(key, None)
    summary["facts"] = facts

    summary["conclusion"] = _v11_filter_conclusion(summary.get("conclusion"))

    return summary


if _v11_original_build_interface_evidence_summary is not None:
    def build_interface_evidence_summary(execution_data):
        base_summary = _v11_original_build_interface_evidence_summary(execution_data)
        return _v11_filter_non_traffic_summary(base_summary, execution_data)
# ===== v5 non-traffic family rate fact final filter end =====

# ===== v5 non-traffic family recommendation final filter begin =====
# 小修说明：
# 非流量/利用率类接口告警不应再出现：
# 高利用率、速率曲线、瞬时峰值、Prometheus历史窗口、告警窗口指标曲线等建议话术。
# 这些话术只保留给 interface_or_link_utilization_high / interface_or_link_traffic_drop。

try:
    _v11b_original_build_interface_evidence_summary = build_interface_evidence_summary
except NameError:
    _v11b_original_build_interface_evidence_summary = None


V11B_TRAFFIC_RECOMMENDATION_KEYWORDS = [
    "高利用率",
    "利用率",
    "速率曲线",
    "流量趋势",
    "流量来源",
    "业务高峰",
    "瞬时峰值",
    "已恢复",
    "Prometheus",
    "指标曲线",
    "告警窗口",
    "时间窗口指标",
    "入向速率",
    "出向速率",
    "input rate",
    "output rate",
    "traffic",
    "utilization",
]


V11B_STATUS_RECOMMENDATIONS = [
    "核查接口当前 oper/admin 状态是否与告警状态一致。",
    "结合接口日志时间线确认是否存在链路 up/down、flap、模块异常或对端切换。",
    "如接口属于聚合链路，继续核查 port-channel 成员状态、LACP 状态和对端端口状态。",
    "必要时结合对端设备接口状态、光模块状态和链路物理层信息继续确认。",
]


def _v11b_safe_text(value):
    if value is None:
        return ""
    return str(value).strip()


def _v11b_is_traffic_family(execution_data):
    try:
        return bool(_v5_should_add_interface_traffic_facts(execution_data))
    except Exception:
        family = _v11b_safe_text(
            ((execution_data.get("family_result") or {}).get("family"))
            or ((execution_data.get("classification") or {}).get("family"))
            or ((execution_data.get("classification") or {}).get("playbook_type"))
            or ((execution_data.get("playbook") or {}).get("playbook_id"))
        )

        return family in {
            "interface_or_link_utilization_high",
            "interface_or_link_traffic_drop",
        }


def _v11b_has_traffic_recommendation_text(line):
    text = _v11b_safe_text(line)
    lower = text.lower()

    for keyword in V11B_TRAFFIC_RECOMMENDATION_KEYWORDS:
        if keyword in text or keyword.lower() in lower:
            return True

    return False


def _v11b_filter_recommendation_lines(lines):
    result = []
    seen = set()

    for line in lines or []:
        value = _v11b_safe_text(line)
        if not value:
            continue

        if _v11b_has_traffic_recommendation_text(value):
            continue

        if value in seen:
            continue

        seen.add(value)
        result.append(value)

    return result


def _v11b_status_conclusion(summary):
    facts = summary.get("facts", {}) or {}
    interface = _v11b_safe_text(facts.get("interface")) or "接口"
    oper = _v11b_safe_text(facts.get("oper_status")) or "未知"
    admin = _v11b_safe_text(facts.get("admin_status")) or "未知"

    return (
        f"{interface} 状态类只读取证完成；"
        f"接口状态 oper={oper} / admin={admin}。"
        "建议结合接口状态、聚合关系、对端端口和日志时间线判断是否存在链路抖动、模块异常或链路切换。"
    )


def _v11b_filter_non_traffic_recommendation_summary(summary, execution_data):
    if _v11b_is_traffic_family(execution_data):
        return summary

    summary = dict(summary or {})

    summary["notify_lines"] = _v11b_filter_recommendation_lines(summary.get("notify_lines", []) or [])
    summary["key_findings"] = _v11b_filter_recommendation_lines(summary.get("key_findings", []) or [])

    filtered_recommendations = _v11b_filter_recommendation_lines(summary.get("recommendations", []) or [])

    for item in V11B_STATUS_RECOMMENDATIONS:
        if item not in filtered_recommendations:
            filtered_recommendations.append(item)

    summary["recommendations"] = filtered_recommendations[:8]

    conclusion = _v11b_safe_text(summary.get("conclusion"))
    if _v11b_has_traffic_recommendation_text(conclusion):
        summary["conclusion"] = _v11b_status_conclusion(summary)

    return summary


if _v11b_original_build_interface_evidence_summary is not None:
    def build_interface_evidence_summary(execution_data):
        base_summary = _v11b_original_build_interface_evidence_summary(execution_data)
        return _v11b_filter_non_traffic_recommendation_summary(base_summary, execution_data)
# ===== v5 non-traffic family recommendation final filter end =====

# ===== v5 multi-interface traffic evidence aggregation begin =====
# 对 ifName=~"Te1/0/1|Te2/0/1" 这种多接口汇总告警：
# 1. 从 command_results 中分别解析每个接口 input/output rate。
# 2. 按多接口汇总计算设备侧总速率。
# 3. 如果告警文本里有 100M / 300M / 1G 业务带宽，按业务带宽计算汇总利用率。
# 4. 避免只展示第一个接口的速率和利用率。

import json as _v16e_json
import re as _v16e_re
import urllib.parse as _v16e_urlparse


try:
    _v16e_original_build_interface_evidence_summary = build_interface_evidence_summary
except NameError:
    _v16e_original_build_interface_evidence_summary = None


def _v16e_safe_text(value):
    if value is None:
        return ""

    if isinstance(value, (dict, list, tuple, set)):
        try:
            return _v16e_json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)

    return str(value).strip()


def _v16e_text_blob(execution_data):
    parts = []

    def walk(value, depth=0):
        if depth > 5:
            return

        if value is None:
            return

        if isinstance(value, dict):
            for k, v in value.items():
                parts.append(_v16e_safe_text(k))
                walk(v, depth + 1)
            return

        if isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item, depth + 1)
            return

        parts.append(_v16e_safe_text(value))

    walk(execution_data)
    return _v16e_urlparse.unquote(" ".join(x for x in parts if x))


def _v16e_split_interfaces(expr):
    expr = _v16e_safe_text(expr).strip().strip('"').strip("'")

    if "|" not in expr:
        return []

    result = []
    seen = set()

    for item in expr.split("|"):
        item = item.strip().strip('"').strip("'")
        if not item:
            continue

        if not _v16e_re.match(r"^[A-Za-z][A-Za-z0-9_\-./]+$", item):
            continue

        if item in seen:
            continue

        seen.add(item)
        result.append(item)

    if len(result) >= 2:
        return result

    return []


def _v16e_extract_multi_interfaces(execution_data):
    # 优先从 command_results 的 multi_interfaces 字段取。
    for item in execution_data.get("command_results", []) or []:
        if not isinstance(item, dict):
            continue

        interfaces = item.get("multi_interfaces")
        if isinstance(interfaces, list) and len(interfaces) >= 2:
            return [x for x in interfaces if _v16e_safe_text(x)]

    text = _v16e_text_blob(execution_data)

    patterns = [
        r'ifName\s*=~\s*"([^"]+\|[^"]+)"',
        r"ifName\s*=~\s*'([^']+\|[^']+)'",
        r'ifDescr\s*=~\s*"([^"]+\|[^"]+)"',
        r"ifDescr\s*=~\s*'([^']+\|[^']+)'",
    ]

    for pattern in patterns:
        m = _v16e_re.search(pattern, text, flags=_v16e_re.IGNORECASE)
        if not m:
            continue

        interfaces = _v16e_split_interfaces(m.group(1))
        if len(interfaces) >= 2:
            return interfaces

    return []


def _v16e_unit_to_bps(value, unit):
    unit = _v16e_safe_text(unit).lower()

    if unit in ("g", "gb", "gbps", "gbit", "gbits", "gbit/s", "gbits/s"):
        return int(float(value) * 1000 * 1000 * 1000)

    if unit in ("m", "mb", "mbps", "mbit", "mbits", "mbit/s", "mbits/s"):
        return int(float(value) * 1000 * 1000)

    if unit in ("k", "kb", "kbps", "kbit", "kbits", "kbit/s", "kbits/s"):
        return int(float(value) * 1000)

    return int(float(value))


def _v16e_parse_rate_bps(text, direction):
    text = _v16e_safe_text(text)

    if direction == "input":
        patterns = [
            r"(?:5\s+minute|30\s+second|300\s+second)?\s*input\s+rate\s+([0-9]+(?:\.[0-9]+)?)\s*(Gbps|Mbps|Kbps|bps|bits/sec|bit/sec)?",
            r"input\s*=\s*([0-9]+(?:\.[0-9]+)?)\s*(Gbps|Mbps|Kbps|bps)?",
        ]
    else:
        patterns = [
            r"(?:5\s+minute|30\s+second|300\s+second)?\s*output\s+rate\s+([0-9]+(?:\.[0-9]+)?)\s*(Gbps|Mbps|Kbps|bps|bits/sec|bit/sec)?",
            r"output\s*=\s*([0-9]+(?:\.[0-9]+)?)\s*(Gbps|Mbps|Kbps|bps)?",
        ]

    for pattern in patterns:
        m = _v16e_re.search(pattern, text, flags=_v16e_re.IGNORECASE)
        if not m:
            continue

        value = m.group(1)
        unit = m.group(2) or "bps"
        unit = unit.replace("bits/sec", "bps").replace("bit/sec", "bps")

        return _v16e_unit_to_bps(value, unit)

    return None


def _v16e_format_bps(value):
    if value is None:
        return "未知"

    value = float(value)

    if value >= 1000 * 1000 * 1000:
        return f"{value / 1000 / 1000 / 1000:.2f} Gbps"

    if value >= 1000 * 1000:
        return f"{value / 1000 / 1000:.2f} Mbps"

    if value >= 1000:
        return f"{value / 1000:.2f} Kbps"

    return f"{int(value)} bps"


def _v16e_percent(value, denominator):
    if not denominator:
        return None

    return round(float(value) / float(denominator) * 100.0, 2)


def _v16e_command_belongs_to_interface(command, interface):
    command = _v16e_safe_text(command)
    interface = _v16e_safe_text(interface)

    return bool(interface and interface in command)


def _v16e_collect_interface_rates(execution_data, interfaces):
    rates = {}

    for iface in interfaces:
        rates[iface] = {
            "input_rate_bps": None,
            "output_rate_bps": None,
        }

    for item in execution_data.get("command_results", []) or []:
        if not isinstance(item, dict):
            continue

        capability = _v16e_safe_text(item.get("capability"))
        command = _v16e_safe_text(item.get("command"))
        output = _v16e_safe_text(item.get("output"))

        if capability not in ("show_interface_detail", "show_interface_traffic_rate"):
            continue

        if not output:
            continue

        for iface in interfaces:
            if not _v16e_command_belongs_to_interface(command, iface):
                continue

            input_rate = _v16e_parse_rate_bps(output, "input")
            output_rate = _v16e_parse_rate_bps(output, "output")

            if input_rate is not None:
                rates[iface]["input_rate_bps"] = input_rate

            if output_rate is not None:
                rates[iface]["output_rate_bps"] = output_rate

    return rates


def _v16e_filter_old_single_interface_traffic_lines(lines):
    result = []

    drop_keywords = [
        "设备侧实时速率",
        "设备侧估算利用率",
        "取证时实时速率",
        "流量判断",
        "按告警口径估算利用率",
        "告警口径流量判断",
    ]

    for line in lines or []:
        text = _v16e_safe_text(line)
        if any(keyword in text for keyword in drop_keywords):
            continue
        result.append(line)

    return result


def _v16e_alarm_direction(summary, execution_data):
    facts = summary.get("facts", {}) or {}
    direction = _v16e_safe_text(facts.get("alarm_direction"))

    if direction:
        return direction

    text = _v16e_text_blob(execution_data)

    if "入向" in text or "input" in text.lower() or "inbound" in text.lower():
        return "in"

    if "出向" in text or "output" in text.lower() or "outbound" in text.lower():
        return "out"

    return ""


def _v16e_enrich_multi_interface_traffic_summary(summary, execution_data):
    summary = dict(summary or {})

    try:
        if not _v5_should_add_interface_traffic_facts(execution_data):
            return summary
    except Exception:
        family = _v16e_safe_text(
            ((execution_data.get("family_result") or {}).get("family"))
            or ((execution_data.get("classification") or {}).get("family"))
        )
        if family not in ("interface_or_link_utilization_high", "interface_or_link_traffic_drop"):
            return summary

    interfaces = _v16e_extract_multi_interfaces(execution_data)

    if len(interfaces) < 2:
        return summary

    rates = _v16e_collect_interface_rates(execution_data, interfaces)

    if not rates:
        return summary

    input_sum = 0
    output_sum = 0
    input_found = False
    output_found = False

    for iface in interfaces:
        item = rates.get(iface, {}) or {}

        if isinstance(item.get("input_rate_bps"), int):
            input_sum += item["input_rate_bps"]
            input_found = True

        if isinstance(item.get("output_rate_bps"), int):
            output_sum += item["output_rate_bps"]
            output_found = True

    if not input_found and not output_found:
        return summary

    facts = dict(summary.get("facts", {}) or {})
    business_bandwidth = facts.get("business_bandwidth_bps")
    direction = _v16e_alarm_direction(summary, execution_data)

    facts["multi_interfaces"] = interfaces
    facts["multi_interface_rates"] = rates

    if input_found:
        facts["aggregate_input_rate_bps"] = input_sum

    if output_found:
        facts["aggregate_output_rate_bps"] = output_sum

    input_business_util = None
    output_business_util = None

    if isinstance(business_bandwidth, int) and business_bandwidth > 0:
        if input_found:
            input_business_util = _v16e_percent(input_sum, business_bandwidth)
            facts["aggregate_input_utilization_percent_business_estimated"] = input_business_util

        if output_found:
            output_business_util = _v16e_percent(output_sum, business_bandwidth)
            facts["aggregate_output_utilization_percent_business_estimated"] = output_business_util

    notify_lines = _v16e_filter_old_single_interface_traffic_lines(summary.get("notify_lines", []) or [])
    key_findings = _v16e_filter_old_single_interface_traffic_lines(summary.get("key_findings", []) or [])

    new_lines = [
        "多接口汇总口径：本次告警涉及 " + "、".join(interfaces) + "，设备侧速率按这些接口汇总计算。",
        f"多接口汇总设备侧实时速率：input={_v16e_format_bps(input_sum) if input_found else '未知'}，output={_v16e_format_bps(output_sum) if output_found else '未知'}。",
    ]

    if input_business_util is not None or output_business_util is not None:
        new_lines.append(
            "多接口按告警口径估算利用率："
            f"input={input_business_util if input_business_util is not None else '未知'}%，"
            f"output={output_business_util if output_business_util is not None else '未知'}%。"
        )

    if direction == "in" and input_business_util is not None:
        if input_business_util >= 80:
            new_lines.append(f"多接口流量判断：取证时入向汇总利用率约 {input_business_util}%，仍处于高利用率状态。")
        else:
            new_lines.append(f"多接口流量判断：取证时入向汇总利用率约 {input_business_util}%，低于80%阈值，更像瞬时峰值或已恢复。")

    if direction == "out" and output_business_util is not None:
        if output_business_util >= 80:
            new_lines.append(f"多接口流量判断：取证时出向汇总利用率约 {output_business_util}%，仍处于高利用率状态。")
        else:
            new_lines.append(f"多接口流量判断：取证时出向汇总利用率约 {output_business_util}%，低于80%阈值，更像瞬时峰值或已恢复。")

    notify_lines.extend(new_lines)
    key_findings.extend(new_lines)

    summary["facts"] = facts
    summary["notify_lines"] = notify_lines[:16]
    summary["key_findings"] = key_findings[:20]

    conclusion = _v16e_safe_text(summary.get("conclusion"))
    if direction == "in" and input_business_util is not None:
        summary["conclusion"] = (
            conclusion
            + f" 多接口汇总后，取证时入向告警口径估算利用率约 {input_business_util}%。"
        ).strip()

    if direction == "out" and output_business_util is not None:
        summary["conclusion"] = (
            conclusion
            + f" 多接口汇总后，取证时出向告警口径估算利用率约 {output_business_util}%。"
        ).strip()

    return summary


if _v16e_original_build_interface_evidence_summary is not None:
    def build_interface_evidence_summary(execution_data):
        base_summary = _v16e_original_build_interface_evidence_summary(execution_data)
        return _v16e_enrich_multi_interface_traffic_summary(base_summary, execution_data)
# ===== v5 multi-interface traffic evidence aggregation end =====

# ===== v5 Cisco IOS-XE interface alias match for evidence begin =====
# 命令改成长接口名后，多接口汇总仍要能识别：
# Te1/0/1 == TenGigabitEthernet1/0/1
# Te2/0/1 == TenGigabitEthernet2/0/1

import re as _v17e_re


def _v17e_safe_text(value):
    if value is None:
        return ""
    return str(value).strip()


def _v17e_interface_aliases(interface):
    value = _v17e_safe_text(interface)

    if not value:
        return []

    aliases = {value}

    m = _v17e_re.match(r"^Te(\d+/\d+/\d+)$", value, flags=_v17e_re.IGNORECASE)
    if m:
        aliases.add("TenGigabitEthernet" + m.group(1))

    m = _v17e_re.match(r"^TenGigabitEthernet(\d+/\d+/\d+)$", value, flags=_v17e_re.IGNORECASE)
    if m:
        aliases.add("Te" + m.group(1))

    m = _v17e_re.match(r"^Gi(\d+/\d+/\d+)$", value, flags=_v17e_re.IGNORECASE)
    if m:
        aliases.add("GigabitEthernet" + m.group(1))

    m = _v17e_re.match(r"^GigabitEthernet(\d+/\d+/\d+)$", value, flags=_v17e_re.IGNORECASE)
    if m:
        aliases.add("Gi" + m.group(1))

    m = _v17e_re.match(r"^Fo(\d+/\d+/\d+)$", value, flags=_v17e_re.IGNORECASE)
    if m:
        aliases.add("FortyGigabitEthernet" + m.group(1))

    m = _v17e_re.match(r"^FortyGigabitEthernet(\d+/\d+/\d+)$", value, flags=_v17e_re.IGNORECASE)
    if m:
        aliases.add("Fo" + m.group(1))

    m = _v17e_re.match(r"^Po(\d+)$", value, flags=_v17e_re.IGNORECASE)
    if m:
        aliases.add("Port-channel" + m.group(1))

    m = _v17e_re.match(r"^Port-channel(\d+)$", value, flags=_v17e_re.IGNORECASE)
    if m:
        aliases.add("Po" + m.group(1))

    return sorted(aliases, key=len, reverse=True)


def _v16e_command_belongs_to_interface(command, interface):
    command = _v17e_safe_text(command)

    if not command:
        return False

    for alias in _v17e_interface_aliases(interface):
        if alias and alias in command:
            return True

    return False
# ===== v5 Cisco IOS-XE interface alias match for evidence end =====
