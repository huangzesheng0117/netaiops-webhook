#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple


MCP_LINE_RE = re.compile(r"^\s*\d+\.\s*通过MCP执行\s+(.+?)（状态：(.+?)），返回要点：(.+?)\s*$")


def _safe_text(value: Any) -> str:
    return "" if value is None else str(value)


def _is_bfd_text(text: str) -> bool:
    t = _safe_text(text)
    return (
        "BFD Neighbor Down" in t
        or "BFD邻居" in t
        or "bfd_neighbor_down" in t
        or "cisco_bfd_neighbor_down" in t
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
        ("peer_ip", r"\bBFD\s+peer\s*=\s*([0-9a-fA-F:\.]+)"),
        ("peer_ip", r"\bpeer\s*=\s*([0-9a-fA-F:\.]+)"),
        ("peer_ip", r"BFD邻居\s+([0-9a-fA-F:\.]+)"),
        ("peer_ip", r"邻居\s+([0-9a-fA-F:\.]+)\s+Down"),
        ("interface", r"\binterface\s*=\s*([A-Za-z]+[A-Za-z0-9\/\.\-]+)"),
        ("interface", r"接口\s*([A-Za-z]+[A-Za-z0-9\/\.\-]+)"),
        ("vrf", r"\bvrf\s*=\s*([A-Za-z0-9_\-]+)"),
        ("vrf", r"在\s*([A-Za-z0-9_\-]+)\s*VRF"),
    ]

    for key, pat in patterns:
        if key in ctx:
            continue
        m = re.search(pat, base, re.I)
        if m:
            ctx[key] = m.group(1).strip("，。；;,. ")

    ctx.setdefault("vrf", "default")
    return ctx


def _render_placeholders(text: str, ctx: Dict[str, str]) -> str:
    out = _safe_text(text)
    mapping = {
        "peer_ip": ctx.get("peer_ip", ""),
        "neighbor_ip": ctx.get("peer_ip", ""),
        "neighbor_id": ctx.get("peer_ip", ""),
        "vrf": ctx.get("vrf", "default"),
        "interface": ctx.get("interface", ""),
        "ifName": ctx.get("interface", ""),
        "if_name": ctx.get("interface", ""),
        "device_ip": ctx.get("device_ip", ""),
        "ip": ctx.get("device_ip", ""),
        "hostname": ctx.get("hostname", ""),
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


def _feature_suffix(item: Dict[str, str]) -> str:
    cmd = item.get("command", "")
    snip = item.get("snippet", "")
    if "show feature" not in cmd.lower():
        return cmd
    feats = []
    if re.search(r"\bbfd\b.*?\benabled\b", snip, re.I):
        feats.append("BFD")
    if re.search(r"\bbgp\b.*?\benabled\b", snip, re.I):
        feats.append("BGP")
    if re.search(r"\bospf\b.*?\benabled\b", snip, re.I):
        feats.append("OSPF")
    if re.search(r"\bisis\b.*?\benabled\b", snip, re.I):
        feats.append("ISIS")
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


def _build_command_analysis(items: List[Dict[str, str]], ctx: Dict[str, str]) -> str:
    peer = ctx.get("peer_ip") or "目标 peer"
    vrf = ctx.get("vrf") or "default"
    interface = ctx.get("interface") or ""

    cmd_text = " ".join(x.get("command", "") for x in items).lower()
    snippet_text = " ".join(x.get("snippet", "") for x in items)

    dimensions = []
    if "bfd clients" in cmd_text:
        dimensions.append("BFD client 注册情况")
    if "bfd neighbors" in cmd_text:
        dimensions.append("BFD 会话状态和 detail")
    if "logging" in cmd_text:
        dimensions.append("BFD/BGP/路由协议/链路日志")
    if "running-config | section bfd" in cmd_text:
        dimensions.append("BFD 全局配置")
    if "running-config interface" in cmd_text:
        dimensions.append("接口配置")
    if "show ip interface" in cmd_text:
        dimensions.append("三层接口状态")
    if "show interface" in cmd_text:
        dimensions.append("接口物理状态和错误计数")
    if "bgp" in cmd_text:
        dimensions.append("BGP 联动状态")
    if "ospf" in cmd_text:
        dimensions.append("OSPF 联动状态")
    if "port-channel" in cmd_text:
        dimensions.append("端口聚合状态")

    dim_text = "、".join(dict.fromkeys(dimensions)) or "BFD 会话、路由协议联动、日志和基础配置"

    parts = [f"本次已从 {dim_text} 等维度完成自动取证。"]

    if re.search(r"\bbfd\b.*?\benabled\b", snippet_text, re.I):
        parts.append("设备侧 BFD 功能已启用。")
    if re.search(r"\bbgp\b.*?\benabled\b", snippet_text, re.I):
        parts.append("设备侧 BGP 功能已启用，需关注 BFD 是否影响 BGP 邻居收敛。")

    if interface:
        parts.append(f"本次告警或取证上下文中包含接口 {interface}，可将 BFD 会话与该接口方向进行关联判断。")

    if "interval" in snippet_text.lower() and "multiplier" in snippet_text.lower():
        parts.append("证据中包含 BFD 定时器配置，应结合两端 interval、min_rx、multiplier 是否一致判断是否存在定时器不匹配或过于激进。")

    if "last reset" in snippet_text.lower() or "bfd adjacency" in snippet_text.lower():
        parts.append("证据中出现 BGP/BFD 联动信息，应结合 BGP last reset 或日志判断 BFD 是否触发上层邻居重置。")

    parts.append(
        f"如果 BFD 邻居仍未恢复，应继续围绕 {vrf} VRF 内 peer {peer} 的 BFD 会话状态、BFD 定时器、"
        "BFD echo、BGP/OSPF/ISIS 联动、对端状态、路径丢包和控制面丢包进行复核。"
    )

    return " ".join(parts)


def _build_overall(items: List[Dict[str, str]], tails: List[str], ctx: Dict[str, str]) -> str:
    failed_items = [x for x in items if not _status_ok(x.get("status", ""))]
    hard_error = _has_hard_error(items, tails)

    parts = []
    if failed_items:
        parts.append(f"本次存在 {len(failed_items)} 条命令执行失败，需优先确认失败命令对结论的影响。")
    elif hard_error:
        parts.append("本次证据中出现设备侧硬错误或命令兼容性异常，需优先核对平台命令映射、对象是否存在以及权限是否充足。")
    else:
        parts.append("本次 BFD 只读命令已完成，当前证据可用于支撑第一轮 BFD 邻居异常判断。")

    parts.append("当前判断范围聚焦于 BFD 会话状态、BFD detail、协议联动、BFD 定时器、近期日志和承载路径相关证据。")

    cleaned_tails = []
    for t in tails:
        clean = t.replace("综合执行结果判断：", "").strip()
        if clean:
            cleaned_tails.append(clean)
    if cleaned_tails:
        parts.append(" ".join(cleaned_tails))

    return " ".join(parts)


def _default_bfd_meaning(ctx: Dict[str, str]) -> str:
    dev_ip = ctx.get("device_ip") or "本地设备"
    host = ctx.get("hostname") or "本地设备"
    peer = ctx.get("peer_ip") or "目标 peer"
    vrf = ctx.get("vrf") or "default"
    return (
        f"告警含义分析：设备 {dev_ip}（{host}）与对端 BFD peer {peer} 在 {vrf} VRF 中的 BFD 会话异常，"
        "可能影响依赖 BFD 的 BGP/OSPF/ISIS 等路由协议快速收敛。"
    )


def rewrite_bfd_notification_text(text: str) -> str:
    base = _clean_stage_words(_safe_text(text))
    if not _is_bfd_text(base):
        return base

    ctx = _extract_context(base)
    base = _render_placeholders(base, ctx)

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
        if "已完成MCP只读取证" in line or "取证事实" in line:
            continue
        intro_clean.append(_strip_step(_render_placeholders(line, ctx)))

    step1 = intro_clean[0] if intro_clean else (
        f"根据告警内容初步判断：设备 {ctx.get('hostname') or '本地设备'} 上 BFD 邻居 {ctx.get('peer_ip') or '目标 peer'} 在 {ctx.get('vrf') or 'default'} VRF 中异常。"
    )

    step2 = ""
    for line in intro_clean[1:]:
        if "告警含义分析" in line:
            step2 = line
            break
    if not step2:
        step2 = _default_bfd_meaning(ctx)

    overview_lines = _build_command_overview(items)
    command_analysis = _build_command_analysis(items, ctx)
    overall = _build_overall(items, tails, ctx)

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


def apply_bfd_format_to_payload(value: Any) -> Any:
    if isinstance(value, str):
        return rewrite_bfd_notification_text(value)
    if isinstance(value, dict):
        result = {}
        for k, v in value.items():
            if k in {"text", "content", "body", "markdown", "message", "msg", "summary_text", "review_text"}:
                result[k] = apply_bfd_format_to_payload(v)
            elif isinstance(v, (dict, list)):
                result[k] = apply_bfd_format_to_payload(v)
            else:
                result[k] = v
        return result
    if isinstance(value, list):
        return [apply_bfd_format_to_payload(x) for x in value]
    return value
