#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple


MCP_LINE_RE = re.compile(r"^\s*\d+\.\s*通过MCP执行\s+(.+?)（状态：(.+?)），返回要点：(.+?)\s*$")


def _safe_text(value: Any) -> str:
    return "" if value is None else str(value)


def _is_cpu_text(text: str) -> bool:
    t = _safe_text(text)
    return (
        "CPU" in t
        and (
            "CPU利用率异常" in t
            or "CPU高利用率" in t
            or "Cisco CPU High" in t
            or "cisco_cpu_utilization_high" in t
            or "cpu_utilization_high" in t
        )
    )


def _status_ok(status: str) -> bool:
    return (status or "").strip().lower() in {"completed", "success", "ok", "done", "succeeded"}


def _strip_step(line: str) -> str:
    return re.sub(r"^\s*\d+\.\s*", "", _safe_text(line)).strip()


def _clean_stage_words(text: str) -> str:
    out = _safe_text(text)
    for old, new in {
        "第一批": "本次",
        "第二批": "补充",
        "第一波": "自动",
        "第二波": "补充",
        "stage-1": "internal-stage",
        "stage-2": "internal-stage",
    }.items():
        out = out.replace(old, new)
    return out


def _extract_context(text: str) -> Dict[str, str]:
    base = _safe_text(text)
    ctx: Dict[str, str] = {}

    patterns = [
        ("device_ip", r"设备：.*?（([0-9a-fA-F:\.]+)）"),
        ("hostname", r"设备：([^（\n]+)"),
        ("device_ip", r"\bdevice_ip\s*=\s*([0-9a-fA-F:\.]+)"),
        ("device_ip", r"\bip\s*=\s*([0-9a-fA-F:\.]+)"),
        ("cpu_value", r"\bCPU\s*=\s*([0-9]+(?:\.[0-9]+)?)\s*%"),
        ("cpu_value", r"CPU.*?([0-9]+(?:\.[0-9]+)?)\s*%"),
    ]

    for key, pat in patterns:
        if key in ctx:
            continue
        m = re.search(pat, base, re.I)
        if m:
            ctx[key] = m.group(1).strip("，。；;,. ")

    return ctx


def _render_placeholders(text: str, ctx: Dict[str, str]) -> str:
    out = _safe_text(text)
    mapping = {
        "device_ip": ctx.get("device_ip", ""),
        "ip": ctx.get("device_ip", ""),
        "instance": ctx.get("device_ip", ""),
        "hostname": ctx.get("hostname", ""),
        "cpu_value": ctx.get("cpu_value", ""),
    }
    for key, value in mapping.items():
        if value:
            out = out.replace("{" + key + "}", value)
    return out


def _split_sections(text: str) -> Tuple[str, str, str]:
    marker_analysis = "分析过程："
    marker_advice = "\n建议："
    if marker_analysis not in text or marker_advice not in text:
        return text, "", ""
    head, rest = text.split(marker_analysis, 1)
    analysis, advice = rest.split(marker_advice, 1)
    return head + marker_analysis + "\n", analysis.strip(), "建议：" + advice.lstrip()


def _parse_raw_mcp_lines(analysis: str) -> Tuple[List[str], List[Dict[str, str]], List[str]]:
    intro: List[str] = []
    items: List[Dict[str, str]] = []
    tails: List[str] = []

    for raw in analysis.splitlines():
        line = raw.strip()
        if not line:
            continue

        m = MCP_LINE_RE.match(line)
        if m:
            items.append({
                "command": m.group(1).strip(),
                "status": m.group(2).strip(),
                "snippet": m.group(3).strip(),
            })
            continue

        if "综合执行结果判断" in line:
            tails.append(_strip_step(line))
            continue

        if "通过MCP执行" not in line:
            intro.append(line)

    return intro, items, tails


def _parse_old_overview(analysis: str) -> Tuple[List[str], List[Dict[str, str]], List[str]]:
    intro: List[str] = []
    items: List[Dict[str, str]] = []
    tails: List[str] = []

    for raw in analysis.splitlines():
        line = raw.strip()
        if not line:
            continue

        if "取证事实：" in line:
            continue

        if "已完成MCP只读取证" in line:
            success_m = re.search(r"成功\s*(\d+)\s*条，具体内容为：(.+?)(?:。失败|；失败|失败\s*\d+\s*条|$)", line)
            failed_m = re.search(r"失败\s*(\d+)\s*条，具体内容为：(.+?)(?:。部分完成|；部分完成|部分完成|$)", line)

            if success_m:
                success_text = success_m.group(2).strip("。；; ")
                for cmd in [x.strip() for x in re.split(r"[；;]", success_text) if x.strip() and x.strip() != "无"]:
                    items.append({"command": cmd, "status": "completed", "snippet": ""})

            if failed_m:
                failed_text = failed_m.group(2).strip("。；; ")
                for cmd in [x.strip() for x in re.split(r"[；;]", failed_text) if x.strip() and x.strip() != "无"]:
                    items.append({"command": cmd, "status": "failed", "snippet": ""})
            continue

        if "综合执行结果判断" in line:
            tails.append(_strip_step(line))
            continue

        intro.append(line)

    return intro, items, tails


def _parse_analysis(analysis: str) -> Tuple[List[str], List[Dict[str, str]], List[str]]:
    intro, items, tails = _parse_raw_mcp_lines(analysis)
    if items:
        return intro, items, tails
    return _parse_old_overview(analysis)


def _extract_prometheus_block(text: str) -> str:
    t = _safe_text(text)
    markers = ["Prometheus窗口证据：", "Prometheus历史证据：", "Prometheus CPU", "Prometheus CPU历史证据："]
    start = -1
    for marker in markers:
        idx = t.find(marker)
        if idx >= 0:
            start = idx
            break

    if start < 0:
        return ""

    end_candidates = []
    for marker in ["\n建议：", "\n\n建议："]:
        idx = t.find(marker, start + 1)
        if idx > start:
            end_candidates.append(idx)

    end = min(end_candidates) if end_candidates else min(len(t), start + 1800)
    block = t[start:end].strip()
    return re.sub(r"\n{3,}", "\n\n", block)


def _summarize_prometheus(block: str) -> str:
    if not block:
        return ""

    text = re.sub(r"\s+", " ", block).strip()
    pieces = []

    status_m = re.search(r"状态：([^；。\n]+)", text)
    if status_m:
        pieces.append(f"Prometheus 查询状态为{status_m.group(1).strip()}。")

    current_m = re.search(r"当前值：\s*([0-9.]+\s*%?)", text)
    avg_m = re.search(r"窗口平均值：\s*([0-9.]+\s*%?)", text)
    max_m = re.search(r"窗口最大值：\s*([0-9.]+\s*%?)", text)
    min_m = re.search(r"窗口最小值：\s*([0-9.]+\s*%?)", text)
    trend_m = re.search(r"趋势判断：([^；。\n]+)", text)

    values = []
    if current_m:
        values.append(f"当前值 {current_m.group(1).strip()}")
    if avg_m:
        values.append(f"窗口平均值 {avg_m.group(1).strip()}")
    if max_m:
        values.append(f"窗口最大值 {max_m.group(1).strip()}")
    if min_m:
        values.append(f"窗口最小值 {min_m.group(1).strip()}")
    if trend_m:
        values.append(f"趋势判断为{trend_m.group(1).strip()}")

    if values:
        pieces.append("Prometheus 历史窗口显示：" + "，".join(values) + "。")
    else:
        pieces.append("已获取 Prometheus CPU 历史窗口证据，可用于判断 CPU 是瞬时尖峰、周期性尖峰还是持续高位。")

    return " ".join(pieces)


def _feature_suffix(item: Dict[str, str]) -> str:
    cmd = item.get("command", "")
    snip = item.get("snippet", "")
    if "show feature" not in cmd.lower():
        return cmd

    feats = []
    for name in ["bgp", "bfd", "ospf", "isis", "eigrp", "vpc", "lacp", "snmp", "telemetry"]:
        if re.search(rf"\b{name}\b.*?\benabled\b", snip, re.I):
            feats.append(name.upper())

    return f"{cmd}：{'、'.join(feats)}" if feats else cmd


def _build_command_overview(items: List[Dict[str, str]]) -> List[str]:
    ok_items = [x for x in items if _status_ok(x.get("status", ""))]
    failed_items = [x for x in items if not _status_ok(x.get("status", ""))]
    failed_list = "；".join(f'{x["command"]}（{x.get("status") or "failed"}）' for x in failed_items) or "无"

    lines = [
        f"本次共执行 {len(items)} 条只读命令，成功 {len(ok_items)} 条，具体如下："
    ]
    for item in ok_items:
        lines.append(_feature_suffix(item))
    lines.append(f"失败 {len(failed_items)} 条。失败命令：{failed_list}。")
    return lines


def _has_hard_error(items: List[Dict[str, str]], tails: List[str]) -> bool:
    text = " ".join([x.get("command", "") + " " + x.get("status", "") + " " + x.get("snippet", "") for x in items] + tails)
    keys = ["硬错误", "invalid command", "incomplete command", "ambiguous command", "syntax error", "not found", "unsupported", "权限", "failed"]
    return any(k.lower() in text.lower() for k in keys)


def _build_command_analysis(items: List[Dict[str, str]], ctx: Dict[str, str], prom_block: str) -> str:
    device_ip = ctx.get("device_ip") or "目标设备"
    cmd_text = " ".join(x.get("command", "") for x in items).lower()
    snippet_text = " ".join(x.get("snippet", "") for x in items)
    prom_summary = _summarize_prometheus(prom_block)

    dimensions = []
    if prom_block:
        dimensions.append("Prometheus 历史 CPU 窗口")
    if "system resources" in cmd_text:
        dimensions.append("系统资源与当前 CPU")
    if "processes cpu" in cmd_text:
        dimensions.append("进程 CPU 排行和 CPU 历史")
    if "logging" in cmd_text:
        dimensions.append("CPU/协议/管理面相关日志")
    if "processes memory" in cmd_text:
        dimensions.append("进程内存")
    if "control-plane" in cmd_text or "policy-map" in cmd_text or "punt" in cmd_text or "policer" in cmd_text:
        dimensions.append("CoPP/控制面/报文上送")
    if "snmp" in cmd_text:
        dimensions.append("SNMP 管理面压力")
    if "users" in cmd_text:
        dimensions.append("登录会话")
    if "bgp" in cmd_text or "ospf" in cmd_text or "isis" in cmd_text or "eigrp" in cmd_text:
        dimensions.append("路由协议状态")
    if "interface" in cmd_text and "errors" in cmd_text:
        dimensions.append("接口错误计数")

    dim_text = "、".join(dict.fromkeys(dimensions)) or "CPU 当前状态、进程排行、历史趋势、日志和控制面相关证据"

    parts = [f"本次已从 {dim_text} 等维度完成自动取证。"]

    if prom_summary:
        parts.append(prom_summary)
    else:
        parts.append("本次最终通知中暂未解析到 Prometheus CPU 历史窗口摘要，需要结合 prometheus_evidence 文件确认是否存在无数据、查询失败或证据未注入通知。")

    if re.search(r"\b(snmp|snmpd)\b", snippet_text, re.I):
        parts.append("证据中出现 SNMP 相关信息，需要关注监控轮询或管理面压力。")
    if re.search(r"\b(bgp|ospf|isis|eigrp|bfd)\b", snippet_text, re.I):
        parts.append("证据中出现路由协议或 BFD 相关信息，需要关注协议震荡是否推高 CPU。")
    if re.search(r"\b(cpu|high|over|threshold)\b", snippet_text, re.I):
        parts.append("设备输出或日志中包含 CPU/高利用率相关关键词，应结合 Prometheus 历史窗口和 CPU history 判断持续性。")

    parts.append(
        f"如果设备 {device_ip} 的 CPU 仍处于高位，应继续围绕高 CPU 进程、interrupt/punt、CoPP、SNMP 轮询、路由协议震荡、管理登录会话和版本缺陷进行复核。"
    )

    return " ".join(parts)


def _build_overall(items: List[Dict[str, str]], tails: List[str], ctx: Dict[str, str], prom_block: str) -> str:
    failed_items = [x for x in items if not _status_ok(x.get("status", ""))]
    hard_error = _has_hard_error(items, tails)

    parts = []
    if failed_items:
        parts.append(f"本次存在 {len(failed_items)} 条命令执行失败，需优先确认失败命令对结论的影响。")
    elif hard_error:
        parts.append("本次证据中出现设备侧硬错误或命令兼容性异常，需优先核对平台命令映射、对象是否存在以及权限是否充足。")
    else:
        parts.append("本次 CPU 只读命令已完成，当前证据可用于支撑第一轮 CPU 利用率异常判断。")

    if prom_block:
        parts.append("Prometheus 历史 CPU 证据已进入分析，可用于判断当前告警是瞬时、周期性还是持续高位。")
    else:
        parts.append("当前结论暂未整合到可读的 Prometheus CPU 历史摘要，结论边界需要保留。")

    parts.append("当前判断范围聚焦于 CPU 历史趋势、当前 CPU、进程排行、控制面压力、SNMP 管理面、协议震荡和设备资源状态。")

    cleaned_tails = []
    for t in tails:
        clean = t.replace("综合执行结果判断：", "").strip()
        if clean:
            cleaned_tails.append(clean)
    if cleaned_tails:
        parts.append(" ".join(cleaned_tails))

    return " ".join(parts)


def _default_cpu_meaning(ctx: Dict[str, str]) -> str:
    dev_ip = ctx.get("device_ip") or "目标设备"
    host = ctx.get("hostname") or "目标设备"
    return (
        f"告警含义分析：设备 {dev_ip}（{host}）出现 CPU 利用率异常，可能影响控制面处理能力、路由协议收敛、管理登录响应和监控采集稳定性。"
    )


def rewrite_cpu_notification_text(text: str) -> str:
    base = _clean_stage_words(_safe_text(text))
    if not _is_cpu_text(base):
        return base

    ctx = _extract_context(base)
    base = _render_placeholders(base, ctx)
    prom_block = _extract_prometheus_block(base)

    head, analysis, advice = _split_sections(base)
    if not analysis or not advice:
        return base

    intro_lines, items, tails = _parse_analysis(analysis)
    if not items:
        return base

    rendered_items = []
    for item in items:
        new = dict(item)
        new["command"] = _render_placeholders(new.get("command", ""), ctx).strip()
        new["snippet"] = _render_placeholders(new.get("snippet", ""), ctx).strip()
        rendered_items.append(new)
    items = rendered_items

    intro_clean = []
    for line in intro_lines:
        if "已完成MCP只读取证" in line or "取证事实" in line or "Prometheus" in line:
            continue
        intro_clean.append(_strip_step(_render_placeholders(line, ctx)))

    step1 = intro_clean[0] if intro_clean else (
        f"根据告警内容初步判断：设备 {ctx.get('hostname') or '目标设备'} CPU 利用率出现异常。"
    )

    step2 = ""
    for line in intro_clean[1:]:
        if "告警含义分析" in line:
            step2 = line
            break
    if not step2:
        step2 = _default_cpu_meaning(ctx)

    overview_lines = _build_command_overview(items)
    command_analysis = _build_command_analysis(items, ctx, prom_block)
    overall = _build_overall(items, tails, ctx, prom_block)

    advice_text = _clean_stage_words(_render_placeholders(advice.strip(), ctx))
    if advice_text.startswith("建议："):
        advice_body = advice_text[len("建议："):].lstrip()
    else:
        advice_body = advice_text

    lines = []
    lines.append(f"1. {step1}")
    lines.append(f"2. {step2}")
    lines.append(f"3. 命令执行概况：{overview_lines[0]}")
    lines.extend(overview_lines[1:])
    lines.append(f"4. 命令分析：{command_analysis}")
    lines.append(f"5. 综合执行结果判断：{overall}")

    final = head.rstrip() + "\n" + "\n".join(lines).rstrip() + "\n\n建议：\n" + advice_body.rstrip()
    return _clean_stage_words(_render_placeholders(final, ctx))


def apply_cpu_format_to_payload(value: Any) -> Any:
    if isinstance(value, str):
        return rewrite_cpu_notification_text(value)
    if isinstance(value, dict):
        result = {}
        for k, v in value.items():
            if k in {"text", "content", "body", "markdown", "message", "msg", "summary_text", "review_text"}:
                result[k] = apply_cpu_format_to_payload(v)
            elif isinstance(v, (dict, list)):
                result[k] = apply_cpu_format_to_payload(v)
            else:
                result[k] = v
        return result
    if isinstance(value, list):
        return [apply_cpu_format_to_payload(x) for x in value]
    return value

# ===== CPU Prometheus unavailable wording override begin =====
def _cpu_prom_block_unavailable(block: str) -> bool:
    text = _safe_text(block)
    return (
        "成功 0 项" in text
        or "no_successful_evidence" in text
        or "mapping_error" in text
        or "profile not found" in text
        or "失败/无数据 3 项" in text
        or "状态：不可用" in text
    )


def _summarize_prometheus(block: str) -> str:
    if not block:
        return ""

    if _cpu_prom_block_unavailable(block):
        return (
            "Prometheus CPU 历史窗口当前未拿到有效时间序列，不能用于判断 CPU 异常的持续性；"
            "本次结论以设备 CLI 取证为主，并需要继续核对指标映射、采集状态或 Prometheus 查询结果。"
        )

    text = re.sub(r"\s+", " ", block).strip()
    pieces = []

    status_m = re.search(r"状态：([^；。\n]+)", text)
    if status_m:
        pieces.append(f"Prometheus 查询状态为{status_m.group(1).strip()}。")

    current_m = re.search(r"当前值：\s*([0-9.]+\s*%?)", text)
    avg_m = re.search(r"窗口平均值：\s*([0-9.]+\s*%?)", text)
    max_m = re.search(r"窗口最大值：\s*([0-9.]+\s*%?)", text)
    min_m = re.search(r"窗口最小值：\s*([0-9.]+\s*%?)", text)
    trend_m = re.search(r"趋势判断：([^；。\n]+)", text)

    values = []
    if current_m:
        values.append(f"当前值 {current_m.group(1).strip()}")
    if avg_m:
        values.append(f"窗口平均值 {avg_m.group(1).strip()}")
    if max_m:
        values.append(f"窗口最大值 {max_m.group(1).strip()}")
    if min_m:
        values.append(f"窗口最小值 {min_m.group(1).strip()}")
    if trend_m:
        values.append(f"趋势判断为{trend_m.group(1).strip()}")

    if values:
        pieces.append("Prometheus 历史窗口显示：" + "，".join(values) + "。")
    else:
        pieces.append("已获取 Prometheus CPU 历史窗口证据，可用于判断 CPU 是瞬时尖峰、周期性尖峰还是持续高位。")

    return " ".join(pieces)


def _build_overall(items: List[Dict[str, str]], tails: List[str], ctx: Dict[str, str], prom_block: str) -> str:
    failed_items = [x for x in items if not _status_ok(x.get("status", ""))]
    hard_error = _has_hard_error(items, tails)
    prom_unavailable = _cpu_prom_block_unavailable(prom_block)

    parts = []
    if failed_items:
        parts.append(f"本次存在 {len(failed_items)} 条命令执行失败，需优先确认失败命令对结论的影响。")
    elif hard_error:
        parts.append("本次证据中出现设备侧硬错误或命令兼容性异常，需优先核对平台命令映射、对象是否存在以及权限是否充足。")
    else:
        parts.append("本次 CPU 只读命令已完成，当前证据可用于支撑第一轮 CPU 利用率异常判断。")

    if prom_block and not prom_unavailable:
        parts.append("Prometheus 历史 CPU 证据已进入分析，可用于判断当前告警是瞬时、周期性还是持续高位。")
    elif prom_block and prom_unavailable:
        parts.append("Prometheus CPU 历史窗口当前不可用，CPU 持续性判断需要以设备 CLI history 或后续修复后的 Prometheus 查询为准。")
    else:
        parts.append("当前结论暂未整合 Prometheus CPU 历史摘要，结论边界需要保留。")

    parts.append("当前判断范围聚焦于 CPU 历史趋势、当前 CPU、进程排行、控制面压力、SNMP 管理面、协议震荡和设备资源状态。")

    cleaned_tails = []
    for t in tails:
        clean = t.replace("综合执行结果判断：", "").strip()
        if clean:
            cleaned_tails.append(clean)
    if cleaned_tails:
        parts.append(" ".join(cleaned_tails))

    return " ".join(parts)
# ===== CPU Prometheus unavailable wording override end =====
