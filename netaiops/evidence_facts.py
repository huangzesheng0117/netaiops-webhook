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


def _v5_enrich_interface_traffic_summary(
    summary: _V5Dict[str, _V5Any],
    execution_data: _V5Dict[str, _V5Any],
) -> _V5Dict[str, _V5Any]:
    summary = dict(summary or {})

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
