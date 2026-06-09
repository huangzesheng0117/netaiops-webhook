#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple


MCP_LINE_RE = re.compile(r"^\s*\d+\.\s*通过MCP执行\s+(.+?)（状态：(.+?)），返回要点：(.+?)\s*$")


def _safe_text(value: Any) -> str:
    return "" if value is None else str(value)


def _is_disk_flash_text(text: str) -> bool:
    t = _safe_text(text)
    low = t.lower()
    # Disk/Flash 告警在不同阶段可能只保留 alertname、playbook_id、skill_name、
    # family、event_type 或中文描述，因此这里放宽命中条件，避免最终通知阶段未套用模板。
    strong_keys = [
        "cisco_device_disk_flash_usage_high",
        "device_disk_flash_usage_high",
        "disk_flash_usage_high",
        "device_filesystem_usage",
        "filesystem_usage_percent",
        "cisco flash high",
        "cisco disk high",
        "flash high",
        "disk high",
    ]
    cn_keys = [
        "设备flash使用率异常",
        "设备磁盘使用率异常",
        "磁盘/flash",
        "磁盘 / flash",
        "bootflash",
        "flash使用率",
        "磁盘使用率",
        "文件系统",
    ]
    return any(k in low for k in strong_keys) or any(k in t for k in cn_keys)


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
        ("filesystem", r"\bfilesystem\s*=\s*([A-Za-z0-9_:\-/\.]+)"),
        ("filesystem", r"\bfs\s*=\s*([A-Za-z0-9_:\-/\.]+)"),
        ("usage", r"(?:usage|使用率)\s*=\s*([0-9]+(?:\.[0-9]+)?)\s*%"),
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
        "filesystem": ctx.get("filesystem", ""),
        "fs": ctx.get("filesystem", ""),
        "usage": ctx.get("usage", ""),
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
    markers = ["Prometheus窗口证据：", "Prometheus历史证据：", "Prometheus filesystem", "Prometheus文件系统"]
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


def _prom_unavailable(block: str) -> bool:
    text = _safe_text(block)
    return (
        "成功 0 项" in text
        or "失败/无数据" in text
        or "no_successful_evidence" in text
        or "profile not found" in text
        or "状态：不可用" in text
        or "no data" in text.lower()
    )


def _summarize_prometheus(block: str) -> str:
    if not block:
        return ""

    if _prom_unavailable(block):
        return (
            "Prometheus 文件系统历史窗口当前未拿到有效时间序列，不能用于判断磁盘/Flash 使用率的历史趋势；"
            "本次结论以设备 CLI 只读取证为主，并需要继续核对 filesystem 指标采集、指标名和标签映射。"
        )

    text = re.sub(r"\s+", " ", block).strip()
    current_m = re.search(r"当前值：\s*([0-9.]+\s*%?)", text)
    avg_m = re.search(r"窗口平均值：\s*([0-9.]+\s*%?)", text)
    max_m = re.search(r"窗口最大值：\s*([0-9.]+\s*%?)", text)
    min_m = re.search(r"窗口最小值：\s*([0-9.]+\s*%?)", text)
    trend_m = re.search(r"趋势判断：([^；。\n]+)", text)

    vals = []
    if current_m:
        vals.append(f"当前值 {current_m.group(1).strip()}")
    if avg_m:
        vals.append(f"窗口平均值 {avg_m.group(1).strip()}")
    if max_m:
        vals.append(f"窗口最大值 {max_m.group(1).strip()}")
    if min_m:
        vals.append(f"窗口最小值 {min_m.group(1).strip()}")
    if trend_m:
        vals.append(f"趋势判断为{trend_m.group(1).strip()}")

    if vals:
        return "Prometheus 文件系统历史窗口显示：" + "，".join(vals) + "。"
    return "已获取 Prometheus 文件系统历史窗口证据，可用于判断空间使用率是持续高位、仍在增长还是已经恢复。"


def _build_command_overview(items: List[Dict[str, str]]) -> List[str]:
    ok_items = [x for x in items if _status_ok(x.get("status", ""))]
    failed_items = [x for x in items if not _status_ok(x.get("status", ""))]
    failed_list = "；".join(f'{x["command"]}（{x.get("status") or "failed"}）' for x in failed_items) or "无"

    lines = [
        f"本次共执行 {len(items)} 条只读命令，成功 {len(ok_items)} 条，具体如下："
    ]
    for item in ok_items:
        lines.append(item.get("command") or "-")
    lines.append(f"失败 {len(failed_items)} 条。失败命令：{failed_list}。")
    return lines


def _has_hard_error(items: List[Dict[str, str]], tails: List[str]) -> bool:
    text = " ".join([x.get("command", "") + " " + x.get("status", "") + " " + x.get("snippet", "") for x in items] + tails)
    keys = ["硬错误", "invalid command", "incomplete command", "ambiguous command", "syntax error", "not found", "unsupported", "权限", "failed"]
    return any(k.lower() in text.lower() for k in keys)


def _build_command_analysis(items: List[Dict[str, str]], ctx: Dict[str, str], prom_block: str) -> str:
    cmd_text = " ".join(x.get("command", "") for x in items).lower()
    snippet_text = " ".join(x.get("snippet", "") for x in items)
    prom_summary = _summarize_prometheus(prom_block)

    dimensions = []
    if prom_block:
        dimensions.append("Prometheus 文件系统历史窗口")
    if "show version" in cmd_text:
        dimensions.append("当前版本和运行镜像")
    if "show boot" in cmd_text:
        dimensions.append("boot 变量和启动依赖")
    if "dir bootflash" in cmd_text or "dir flash" in cmd_text:
        dimensions.append("bootflash/flash 当前空间和目录文件")
    if ".bin" in cmd_text or ".pkg" in cmd_text:
        dimensions.append("镜像/package 文件")
    if "tech" in cmd_text or "show*" in cmd_text:
        dimensions.append("show-tech/tech-support 文件")
    if "core" in cmd_text or "crash" in cmd_text:
        dimensions.append("core/crash 文件")
    if "log:" in cmd_text or "logging" in cmd_text:
        dimensions.append("日志文件和 filesystem 异常日志")

    dim_text = "、".join(dict.fromkeys(dimensions)) or "文件系统空间、启动依赖、大文件类型和日志异常"

    parts = [f"本次已从 {dim_text} 等维度完成自动取证。"]

    if prom_summary:
        parts.append(prom_summary)
    else:
        parts.append("本次最终通知中暂未解析到 Prometheus 文件系统历史窗口摘要，需要结合 prometheus_evidence 文件确认是否存在无数据、查询失败或证据未注入通知。")

    if re.search(r"(packages\.conf|boot variable|system image|bootflash:.*\.bin)", snippet_text, re.I):
        parts.append("证据中包含启动依赖相关信息，清理前必须确认 packages.conf、当前 boot 镜像和当前 package 文件不可误删。")

    if re.search(r"(core|crash)", snippet_text, re.I):
        parts.append("证据中出现 core/crash 相关信息，应先确认是否需要保留给 TAC 或用于故障分析，再考虑清理。")

    if re.search(r"(show.?tech|tech-support|\\.tar|\\.tgz|\\.gz)", snippet_text, re.I):
        parts.append("证据中出现 show-tech、tech-support 或压缩归档文件，应确认归档价值和保留策略后再处理。")

    if re.search(r"(no space|filesystem|write fail|copy fail|disk|space)", snippet_text, re.I):
        parts.append("日志或目录输出中出现空间/文件系统相关关键词，需要判断是否已影响 copy、write、core、install 等操作。")

    parts.append("本 playbook 只做只读定位，不自动执行 delete、install remove inactive、package clean、copy、erase 等清理或修改动作。")
    return " ".join(parts)


def _build_overall(items: List[Dict[str, str]], tails: List[str], ctx: Dict[str, str], prom_block: str) -> str:
    failed_items = [x for x in items if not _status_ok(x.get("status", ""))]
    hard_error = _has_hard_error(items, tails)
    prom_bad = _prom_unavailable(prom_block)

    parts = []
    if failed_items:
        parts.append(f"本次存在 {len(failed_items)} 条命令执行失败，需优先确认失败命令对结论的影响。")
    elif hard_error:
        parts.append("本次证据中出现设备侧硬错误或命令兼容性异常，需优先核对平台命令映射、文件系统对象是否存在以及权限是否充足。")
    else:
        parts.append("本次磁盘/Flash 只读命令已完成，当前证据可用于支撑第一轮空间使用率异常判断。")

    if prom_block and not prom_bad:
        parts.append("Prometheus 文件系统历史证据已进入分析，可用于判断空间使用率是持续高位、仍在增长还是已恢复。")
    elif prom_block and prom_bad:
        parts.append("Prometheus 文件系统历史窗口当前不可用，历史趋势判断需要以 CLI 目录信息和后续修复后的指标查询为准。")
    else:
        parts.append("当前结论暂未整合 Prometheus 文件系统历史摘要，结论边界需要保留。")

    parts.append("当前判断范围聚焦于具体 filesystem、当前版本与 boot 依赖、旧镜像/package、show-tech、core/crash、日志归档和文件系统异常。")
    parts.append("任何清理动作都必须在人工确认当前启动依赖和需保留文件后单独执行，不应由告警 playbook 自动清理。")

    cleaned_tails = []
    for t in tails:
        clean = t.replace("综合执行结果判断：", "").strip()
        if clean:
            cleaned_tails.append(clean)
    if cleaned_tails:
        parts.append(" ".join(cleaned_tails))

    return " ".join(parts)


def _default_meaning(ctx: Dict[str, str]) -> str:
    dev_ip = ctx.get("device_ip") or "目标设备"
    host = ctx.get("hostname") or "目标设备"
    fs = ctx.get("filesystem") or "磁盘/Flash 文件系统"
    return (
        f"告警含义分析：设备 {dev_ip}（{host}）的 {fs} 使用率异常偏高，可能影响镜像升级、配置保存、日志写入、core 文件生成、文件拷贝和故障取证。"
    )


def rewrite_disk_flash_notification_text(text: str) -> str:
    base = _clean_stage_words(_safe_text(text))
    if not _is_disk_flash_text(base):
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
        f"根据告警内容初步判断：设备 {ctx.get('hostname') or '目标设备'} 磁盘/Flash 使用率出现异常。"
    )

    step2 = ""
    for line in intro_clean[1:]:
        if "告警含义分析" in line:
            step2 = line
            break
    if not step2:
        step2 = _default_meaning(ctx)

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


def apply_disk_flash_format_to_payload(value: Any) -> Any:
    if isinstance(value, str):
        return rewrite_disk_flash_notification_text(value)
    if isinstance(value, dict):
        result = {}
        for k, v in value.items():
            if k in {"text", "content", "body", "markdown", "message", "msg", "summary_text", "review_text"}:
                result[k] = apply_disk_flash_format_to_payload(v)
            elif isinstance(v, (dict, list)):
                result[k] = apply_disk_flash_format_to_payload(v)
            else:
                result[k] = v
        return result
    if isinstance(value, list):
        return [apply_disk_flash_format_to_payload(x) for x in value]
    return value
