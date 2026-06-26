#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cisco interface down/status-abnormal notification formatter.

目标：
1. 命令执行概况中，成功/失败命令逐行展示。
2. 分析过程固定为：
   1 初步判断
   2 告警含义分析
   3 命令执行概况
   4 命令分析
   5 Prometheus窗口证据
   6 综合执行结果判断
3. 只改最终咚咚文本展示，不改变取证、Prometheus 查询、MCP 执行逻辑。
"""

from __future__ import annotations

import re
from typing import Iterable, List, Optional, Tuple


def _safe(value) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _is_interface_down_text(text: str) -> bool:
    value = _safe(text)
    if not value:
        return False

    positive_markers = [
        "Cisco Interface Down",
        "cisco_interface_down_or_oper_status",
        "interface_down_or_oper_status",
        "接口状态异常/Down",
        "接口状态异常",
        "端口状态异常",
        "接口Down",
        "端口Down",
    ]

    evidence_markers = [
        "show interface status err-disabled",
        "show interface counters errors",
        "show spanning-tree interface",
        "show port-channel summary",
        "接口状态：",
    ]

    if not any(m in value for m in positive_markers):
        return False

    # 避免误伤接口利用率/流量/错包/光功率等其他接口类告警。
    negative_markers = [
        "接口/链路利用率高",
        "接口利用率高",
        "流量突增",
        "流量突降",
        "错包",
        "丢包",
        "丢弃高",
        "光功率",
        "transceiver power alarm",
    ]
    if any(m in value for m in negative_markers) and "Cisco Interface Down" not in value:
        return False

    return any(m in value for m in evidence_markers)


def _split_command_list(value: str) -> List[str]:
    raw = _safe(value)
    if not raw or raw == "无":
        return []
    parts = [p.strip() for p in re.split(r"[；;]\s*", raw) if p.strip()]
    cleaned: List[str] = []
    seen = set()
    for item in parts:
        item = item.strip(" 。；;")
        if not item or item == "无":
            continue
        if item in seen:
            continue
        seen.add(item)
        cleaned.append(item)
    return cleaned


def _extract_command_overview(line: str) -> Tuple[Optional[str], List[str], List[str], List[str]]:
    value = _safe(line)
    if not value:
        return None, [], [], []

    m_total = re.search(r"共执行\s*(\d+)\s*条", value)
    m_success = re.search(r"成功\s*(\d+)\s*条", value)
    m_failed = re.search(r"失败\s*(\d+)\s*条", value)
    m_partial = re.search(r"部分完成\s*(\d+)\s*条", value)

    total = m_total.group(1) if m_total else "0"
    success = m_success.group(1) if m_success else "0"
    failed = m_failed.group(1) if m_failed else "0"
    partial = m_partial.group(1) if m_partial else "0"

    success_text = ""
    failed_text = ""
    partial_text = ""

    m = re.search(
        r"成功\s*\d+\s*条，具体内容为：(.+?)。失败\s*\d+\s*条，具体内容为：(.+?)。部分完成\s*\d+\s*条，具体内容为：(.+?)。",
        value,
        flags=re.S,
    )
    if m:
        success_text, failed_text, partial_text = m.group(1), m.group(2), m.group(3)
    else:
        m_success_text = re.search(r"成功\s*\d+\s*条，具体(?:内容为|如下)：(.+?)(?:。失败|$)", value, flags=re.S)
        m_failed_text = re.search(r"失败\s*\d+\s*条，具体内容为：(.+?)(?:。部分完成|$)", value, flags=re.S)
        m_partial_text = re.search(r"部分完成\s*\d+\s*条，具体内容为：(.+?)(?:。|$)", value, flags=re.S)
        success_text = m_success_text.group(1) if m_success_text else ""
        failed_text = m_failed_text.group(1) if m_failed_text else ""
        partial_text = m_partial_text.group(1) if m_partial_text else ""

    success_cmds = _split_command_list(success_text)
    failed_cmds = _split_command_list(failed_text)
    partial_cmds = _split_command_list(partial_text)

    lines = [
        f"3. 命令执行概况：本次共执行 {total} 条只读命令，成功 {success} 条，具体如下："
    ]
    if success_cmds:
        lines.extend(success_cmds)
    else:
        lines.append("无")

    if failed_cmds:
        lines.append(f"失败 {failed} 条。失败命令：")
        lines.extend(failed_cmds)
    else:
        lines.append(f"失败 {failed} 条。失败命令：无。")

    if partial_cmds:
        lines.append(f"部分完成 {partial} 条。部分完成命令：")
        lines.extend(partial_cmds)
    elif partial not in ("0", "", None):
        lines.append(f"部分完成 {partial} 条。部分完成命令：无。")

    return "\n".join(lines), success_cmds, failed_cmds, partial_cmds


def _extract_interface_state(text: str) -> Tuple[str, str, str]:
    value = _safe(text)

    patterns = [
        r"接口状态：\s*([A-Za-z]+[A-Za-z0-9\/\.\-:]*)\s+oper=([^\s，,；;]+)\s+admin=([^\s，,；;]+)",
        r"([A-Za-z]+[A-Za-z0-9\/\.\-:]*)\s+oper=([^\s，,；;]+)\s+admin=([^\s，,；;]+)",
    ]

    for pat in patterns:
        m = re.search(pat, value)
        if m:
            return m.group(1), m.group(2), m.group(3)

    m = re.search(r"接口\s+([A-Za-z]+[A-Za-z0-9\/\.\-:]*)", value)
    if m:
        return m.group(1), "未知", "未知"

    return "目标接口", "未知", "未知"


def _extract_initial_judgement(analysis_text: str, full_text: str) -> str:
    for line in analysis_text.splitlines():
        value = _safe(line)
        if not value:
            continue
        if "根据告警内容初步判断" in value:
            return re.sub(r"^\s*\d+[\.、]\s*", "1. ", value)

    iface, _, _ = _extract_interface_state(full_text)
    return f"1. 根据告警内容初步判断：Cisco 设备 {iface} 接口触发状态异常/Down 告警，需要结合历史状态、当前 CLI 取证和接口上下文判断是否仍处于异常、已恢复或属于瞬时抖动。"


def _build_alarm_meaning() -> str:
    return (
        "2. 告警含义分析：接口状态异常/Down 通常表示接口管理状态、物理链路、line protocol、"
        "err-disabled、Port-channel/LACP/vPC、VLAN/STP、光模块/线路或对端端口等任一环节存在异常。"
        "该类告警需要先区分 administratively down、down/down、up/down、err-disabled、suspended/notconnect/inactive "
        "以及 link-flap 等不同状态，不能直接默认判断为硬件故障。"
    )


def _build_command_analysis(full_text: str, success_cmds: List[str], failed_cmds: List[str]) -> str:
    iface, oper, admin = _extract_interface_state(full_text)

    dimensions = [
        "接口状态汇总",
        "目标接口详情",
        "接口配置",
        "err-disabled 状态",
        "近期接口日志",
        "错误计数",
        "光模块/收发光",
        "VLAN/Trunk",
        "STP",
        "Port-channel",
        "vPC",
        "模块状态",
    ]

    if oper != "未知" or admin != "未知":
        state_sentence = f"CLI 取证显示 {iface} 当前 oper={oper} / admin={admin}"
        if oper.lower() == "up" and admin.lower() == "up":
            state_sentence += "，说明本次仿真取证时接口当前处于 up/up 状态，告警可能已恢复、为历史瞬时抖动，或与告警触发时刻不一致"
        elif admin.lower() in {"down", "administratively", "admin-down", "disabled"}:
            state_sentence += "，更偏向管理关闭或配置禁用方向"
        elif oper.lower() in {"down", "notconnect", "inactive", "suspended", "err-disabled", "errdisabled"}:
            state_sentence += "，当前仍存在接口状态异常，需要继续结合日志、物理层、聚合和对端侧证据复核"
        else:
            state_sentence += "，需要结合平台状态枚举继续确认接口当前状态含义"
    else:
        state_sentence = f"CLI 取证未能从结构化事实中稳定提取 {iface} 的 oper/admin 状态，需要以目标接口详情和日志原文继续人工复核"

    failed_sentence = ""
    if failed_cmds:
        failed_sentence = "；失败命令为 " + "、".join(failed_cmds) + "，对应维度存在证据边界，但不影响已成功命令覆盖的第一轮接口状态判断"

    return (
        "4. 命令分析：本次已从 "
        + "、".join(dimensions)
        + " 等维度完成 Cisco 接口状态异常第一轮只读取证。"
        + state_sentence
        + failed_sentence
        + "。"
    )


def _parse_prom_block(full_text: str) -> Tuple[str, str]:
    value = _safe(full_text)
    marker = "Prometheus窗口证据："
    idx = value.find(marker)
    if idx < 0:
        return "", value

    before = value[:idx].rstrip()
    after = value[idx:]

    rec_idx = after.find("\n\n建议：")
    if rec_idx >= 0:
        prom = after[:rec_idx].strip()
        rest = after[rec_idx:].lstrip()
    else:
        prom = after.strip()
        rest = ""

    return prom, (before + ("\n\n" + rest if rest else "")).strip()


def _prom_summary_for_overall(prom_text: str) -> str:
    value = _safe(prom_text)
    if not value:
        return "Prometheus 窗口证据未展示，历史状态判断存在边界"

    current_oper = None
    m = re.search(r"-\s*oper_status:.*?当前值：\s*([0-9.]+)\s*status", value, flags=re.S)
    if m:
        try:
            current_oper = float(m.group(1))
        except Exception:
            current_oper = None

    if current_oper == 1.0:
        return "Prometheus ifOperStatus 当前值为 1，历史窗口显示接口当前处于 up 状态或已恢复"
    if current_oper == 2.0:
        return "Prometheus ifOperStatus 当前值为 2，历史窗口支持接口当前处于 down 状态"
    if "不可用" in value or "无数据" in value or "sidecar_overall_timeout" in value:
        return "Prometheus 窗口证据存在失败或无数据项，历史趋势判断存在边界"

    return "Prometheus 窗口证据已返回，可用于辅助判断接口状态、流量变化和错误计数趋势"


def _build_overall(full_text: str, prom_text: str, failed_cmds: List[str]) -> str:
    iface, oper, admin = _extract_interface_state(full_text)
    prom_sentence = _prom_summary_for_overall(prom_text)

    if oper.lower() == "up" and admin.lower() == "up":
        conclusion = (
            f"CLI 当前证据显示 {iface} 为 up/up，"
            f"{prom_sentence}。综合来看，本次取证未支持接口当前仍处于 Down 状态，"
            "更偏向告警触发后已恢复、瞬时链路抖动、监控状态滞后或仿真告警。"
        )
    elif oper.lower() in {"down", "notconnect", "inactive", "suspended", "err-disabled", "errdisabled"}:
        conclusion = (
            f"CLI 当前证据显示 {iface} oper={oper} / admin={admin}，"
            f"{prom_sentence}。综合来看，接口状态异常仍可能存在，应继续按物理层、err-disable、"
            "聚合/vPC、VLAN/STP、对端端口和模块状态方向收敛。"
        )
    elif admin.lower() in {"down", "administratively", "admin-down", "disabled"}:
        conclusion = (
            f"CLI 当前证据显示 {iface} admin={admin}，"
            f"{prom_sentence}。综合来看，需要优先核对该接口是否为计划内关闭、变更残留或配置禁用。"
        )
    else:
        conclusion = (
            f"CLI 当前证据未能稳定提取 {iface} 的明确状态，"
            f"{prom_sentence}。综合来看，当前结论存在边界，需要结合目标接口详情、日志时间线和对端状态继续复核。"
        )

    if failed_cmds:
        conclusion += " 本次存在少量失败命令，失败维度需要人工补充确认。"

    return "6. 综合执行结果判断：" + conclusion


def _normalize_prometheus_section(prom_text: str) -> str:
    value = _safe(prom_text)
    if not value:
        return "5. Prometheus窗口证据：\n- 状态：未展示\n- 原因：本次通知未携带 Prometheus runtime sidecar 摘要，历史窗口判断存在边界。"

    if value.startswith("Prometheus窗口证据："):
        return "5. " + value

    if value.startswith("5. Prometheus窗口证据："):
        return value

    return "5. Prometheus窗口证据：\n" + value


def _extract_analysis_and_recommendations(text: str) -> Tuple[str, str, str]:
    value = _safe(text)
    marker = "\n分析过程：\n"
    if marker not in value:
        return value, "", ""

    head, tail = value.split(marker, 1)

    rec_marker = "\n\n建议：\n"
    if rec_marker in tail:
        analysis, rec = tail.split(rec_marker, 1)
        return head, analysis.strip(), rec.strip()

    return head, tail.strip(), ""


def _clean_recommendations(rec_text: str) -> str:
    value = _safe(rec_text)
    if not value:
        return value

    lines = []
    for line in value.splitlines():
        item = _safe(line)
        if not item:
            continue

        # 去掉内部实现向建议。
        if "capability" in item.lower() or "平台类型识别" in item:
            continue

        item = re.sub(r"^\s*\d+[\.、]\s*", "", item).strip()
        if item and item not in lines:
            lines.append(item)

    if not lines:
        lines = [
            "核查接口当前 oper/admin 状态是否与告警状态一致。",
            "结合接口日志时间线确认是否存在链路 up/down、flap、模块异常或对端切换。",
            "如接口属于聚合链路，继续核查 Port-channel/LACP/vPC 成员状态和对端端口状态。",
            "必要时结合对端设备接口状态、光模块状态和链路物理层信息继续确认。",
        ]

    return "\n".join(f"{idx}. {item}" for idx, item in enumerate(lines, start=1))


def rewrite_interface_down_notification_text(text: str, request_id: Optional[str] = None) -> str:
    original = _safe(text)
    if not _is_interface_down_text(original):
        return original

    prom_text, text_without_prom = _parse_prom_block(original)
    head, analysis_text, rec_text = _extract_analysis_and_recommendations(text_without_prom)

    if not analysis_text:
        return original

    initial = _extract_initial_judgement(analysis_text, original)

    command_line = ""
    fact_lines: List[str] = []
    for raw_line in analysis_text.splitlines():
        line = _safe(raw_line)
        if not line:
            continue
        if "已完成MCP只读取证" in line or "命令执行概况" in line:
            command_line = line
            continue
        if "取证事实" in line or "接口状态：" in line:
            fact_lines.append(line)

    command_overview, success_cmds, failed_cmds, partial_cmds = _extract_command_overview(command_line)
    if not command_overview:
        command_overview = (
            "3. 命令执行概况：本次接口状态类只读取证已执行，"
            "但通知文本未能解析出完整成功/失败命令清单，请结合 execution 记录复核。"
        )
        success_cmds = []
        failed_cmds = []

    fact_text = "\n".join(fact_lines)
    source_for_state = fact_text + "\n" + original

    new_sections = [
        initial,
        _build_alarm_meaning(),
        command_overview,
        _build_command_analysis(source_for_state, success_cmds, failed_cmds),
        _normalize_prometheus_section(prom_text),
        _build_overall(source_for_state, prom_text, failed_cmds),
    ]

    result = head.rstrip() + "\n\n分析过程：\n" + "\n".join(new_sections)

    cleaned_rec = _clean_recommendations(rec_text)
    if cleaned_rec:
        result += "\n\n建议：\n" + cleaned_rec

    return result.strip()


def apply_interface_down_format_to_payload(payload: dict, request_id: Optional[str] = None) -> dict:
    # 当前主要依赖最终文本 guard；保留 payload 函数，便于后续扩展结构化字段。
    return payload or {}
