#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cisco hardware component fault notification formatter.

目标：
1. 命令执行概况中，成功/失败命令逐行展示。
2. 分析过程固定为：
   1 初步判断
   2 告警含义分析
   3 命令执行概况
   4 命令分析
   5 Prometheus窗口证据
   6 综合执行结果判断
3. Prometheus窗口证据放入第5点。
4. 不改变 Prometheus 查询、MCP 执行和 review 生成逻辑。
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple


def _safe(value) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _is_cisco_hardware_text(text: str) -> bool:
    value = _safe(text)
    if not value:
        return False

    positive = [
        "cisco_hardware_component_fault",
        "Cisco Hardware Component Fault",
        "Cisco Hardware Fault",
        "硬件部件故障",
        "硬件故障",
        "硬件异常",
        "风扇",
        "电源",
        "温度",
        "模块异常",
        "板卡异常",
        "线卡异常",
        "Supervisor异常",
        "FEX硬件异常",
    ]

    if not any(x in value for x in positive):
        return False

    evidence = [
        "show environment",
        "show module",
        "show inventory",
        "show diagnostic result",
        "硬件/环境类",
        "fan",
        "power",
        "temperature",
        "module",
    ]
    return any(x.lower() in value.lower() for x in evidence)


def _split_command_list(value: str) -> List[str]:
    raw = _safe(value)
    if not raw or raw == "无":
        return []
    parts = [p.strip() for p in re.split(r"[；;]\s*", raw) if p.strip()]
    result: List[str] = []
    seen = set()
    for item in parts:
        item = item.strip(" 。；;")
        if not item or item == "无":
            continue
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def _parse_summary_line(line: str) -> Tuple[Optional[str], List[str], List[str], List[str]]:
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

    success_cmds = _split_command_list(success_text)
    failed_cmds = _split_command_list(failed_text)
    partial_cmds = _split_command_list(partial_text)

    lines = [f"3. 命令执行概况：本次共执行 {total} 条只读命令，成功 {success} 条，具体如下："]
    lines.extend(success_cmds or ["无"])

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


def _parse_per_command_lines(analysis_text: str) -> Tuple[Optional[str], List[str], List[str], List[str]]:
    success_cmds: List[str] = []
    failed_cmds: List[str] = []
    partial_cmds: List[str] = []

    for raw_line in analysis_text.splitlines():
        line = _safe(raw_line)
        if "通过MCP执行" not in line:
            continue

        m = re.search(r"通过MCP执行\s+(.+?)(?:（状态：([^）]+)）|，|$)", line)
        if not m:
            continue

        cmd = m.group(1).strip()
        status = (m.group(2) or "").strip().lower()
        if not cmd:
            continue

        if "硬错误" in line or "执行失败" in line or status in ("failed", "failure", "error", "timeout"):
            failed_cmds.append(cmd)
        elif status in ("partial", "partially_completed"):
            partial_cmds.append(cmd)
        else:
            success_cmds.append(cmd)

    total = len(success_cmds) + len(failed_cmds) + len(partial_cmds)
    if total == 0:
        return None, [], [], []

    lines = [f"3. 命令执行概况：本次共执行 {total} 条只读命令，成功 {len(success_cmds)} 条，具体如下："]
    lines.extend(success_cmds or ["无"])

    if failed_cmds:
        lines.append(f"失败 {len(failed_cmds)} 条。失败命令：")
        lines.extend(failed_cmds)
    else:
        lines.append("失败 0 条。失败命令：无。")

    if partial_cmds:
        lines.append(f"部分完成 {len(partial_cmds)} 条。部分完成命令：")
        lines.extend(partial_cmds)

    return "\n".join(lines), success_cmds, failed_cmds, partial_cmds


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


def _normalize_prometheus_section(prom_text: str) -> str:
    value = _safe(prom_text)
    if not value:
        return "5. Prometheus窗口证据：\n- 状态：未展示\n- 原因：本次通知未携带 Prometheus runtime sidecar 摘要，硬件历史趋势判断存在边界。"
    if value.startswith("5. Prometheus窗口证据："):
        return value
    if value.startswith("Prometheus窗口证据："):
        return "5. " + value
    return "5. Prometheus窗口证据：\n" + value


def _extract_initial(analysis_text: str) -> str:
    for line in analysis_text.splitlines():
        value = _safe(line)
        if "根据告警内容初步判断" in value:
            return re.sub(r"^\s*\d+[\.、]\s*", "1. ", value)

    return (
        "1. 根据告警内容初步判断：Cisco 设备触发硬件部件故障类告警，"
        "需要先判断告警是否当前仍存在、属于风扇/电源/温度/模块/主控/PoE/FEX/传感器哪一类，"
        "以及是否已经影响冗余或业务。"
    )


def _build_alarm_meaning() -> str:
    return (
        "2. 告警含义分析：硬件部件故障类告警不应只根据 Hardware Fault 字样直接判断为设备硬件损坏，"
        "需要拆分为风扇、电源、温度、模块/线卡、Supervisor、PoE、FEX 或传感器等具体对象。"
        "同时需要区分单部件降级、冗余丢失、模块离线、温度 critical、多个设备同一时间异常等不同影响范围。"
        "对于电源 input lost、温度高、多设备同时告警等场景，应优先考虑外部供电、PDU/UPS、市电、空调和机柜风道因素。"
    )


def _find_suspicious_lines(text: str, limit: int = 5) -> List[str]:
    patterns = [
        r"fail|failed|failure|fault|faulty",
        r"critical|major|minor|warning|warn|alarm|abnormal",
        r"absent|not\s+present|removed|offline|powered-dn|shutdown",
        r"input\s+lost|redundancy\s+lost|insufficient",
        r"over\s*temp|temperature|fan|power|psu|module|supervisor|sensor|fex|poe|ilpower",
    ]

    result: List[str] = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        for pat in patterns:
            if re.search(pat, line, flags=re.I):
                clean = line[:180]
                if clean not in seen:
                    seen.add(clean)
                    result.append(clean)
                break
        if len(result) >= limit:
            break
    return result


def _infer_fault_class(text: str) -> str:
    lower = text.lower()
    if re.search(r"风扇|fan|fantray", lower):
        return "风扇/散热"
    if re.search(r"电源|power|psu|supply|input lost|capacity", lower):
        return "电源/供电"
    if re.search(r"温度|temperature|temp|thermal|overheat", lower):
        return "温度/散热环境"
    if re.search(r"模块|板卡|线卡|module|linecard|supervisor|fabric|fex|stack|slot", lower):
        return "模块/板卡/主控"
    if re.search(r"poe|ilpower", lower):
        return "PoE供电"
    return "泛硬件部件"


def _build_command_analysis(full_text: str, success_cmds: List[str], failed_cmds: List[str]) -> str:
    dimensions = [
        "设备时间与运行时间",
        "环境总览",
        "风扇状态",
        "电源输入/冗余",
        "温度传感器",
        "模块/主控/线卡状态",
        "硬件库存PID/SN",
        "系统资源",
        "硬件日志时间线",
        "core文件",
        "在线诊断结果",
    ]

    fault_class = _infer_fault_class(full_text)
    suspicious = _find_suspicious_lines(full_text, limit=3)

    if suspicious:
        suspicious_text = "；疑似异常或相关状态行包括：" + "；".join(suspicious)
    else:
        suspicious_text = "；当前通知摘要中未提取到明确 failed/critical/absent/offline 等异常状态行，需要结合完整命令原始输出复核"

    failed_text = ""
    if failed_cmds:
        failed_text = "；失败命令为 " + "、".join(failed_cmds) + "，对应维度存在证据边界"

    return (
        "4. 命令分析：本次已从 "
        + "、".join(dimensions)
        + " 等维度完成 Cisco 硬件部件故障第一轮只读取证。"
        + f"从告警文本和取证摘要看，当前更偏向 {fault_class} 方向"
        + suspicious_text
        + failed_text
        + "。"
    )


def _prom_summary(prom_text: str) -> str:
    value = _safe(prom_text)
    if not value:
        return "Prometheus 窗口证据未展示，历史趋势判断存在边界"

    if "不可用" in value or "无数据" in value or "failed" in value.lower() or "失败" in value:
        return "Prometheus 窗口证据存在失败或无数据项，硬件历史趋势判断存在边界"

    if "temperature_celsius" in value or "fan_state" in value or "power_state" in value:
        return "Prometheus 已返回硬件相关历史窗口证据，可辅助判断温度、风扇或电源状态是否持续异常"

    if "device_up" in value:
        return "Prometheus 已返回设备 up 历史状态，可辅助确认监控采集连续性"

    return "Prometheus 窗口证据已返回，可辅助判断告警是否持续、恢复或仅为瞬时异常"


def _build_overall(full_text: str, prom_text: str, failed_cmds: List[str]) -> str:
    fault_class = _infer_fault_class(full_text)
    suspicious = _find_suspicious_lines(full_text, limit=5)
    prom = _prom_summary(prom_text)

    if suspicious:
        conclusion = (
            f"CLI 取证摘要中存在硬件/环境相关异常或告警关键词，当前更偏向 {fault_class} 方向；"
            f"{prom}。综合来看，需要继续确认该异常是否仍存在、是否导致冗余丢失或模块/业务受影响。"
        )
    else:
        conclusion = (
            f"CLI 取证摘要中暂未提取到明确持续异常状态，当前更偏向已恢复、瞬时告警、仿真告警或需要查看完整原始输出确认；"
            f"{prom}。综合来看，本轮证据不足以直接判定硬件损坏。"
        )

    if re.search(r"input\s+lost|电源输入|psu|power", full_text, flags=re.I):
        conclusion += " 若为电源 input lost 或冗余丢失，应同步检查电源线、PDU、UPS、市电输入和机柜供电。"

    if re.search(r"temperature|temp|温度|thermal", full_text, flags=re.I):
        conclusion += " 若为温度异常，应同步检查机房温度、风道、风扇状态和机柜散热。"

    if failed_cmds:
        conclusion += " 本次存在失败命令，失败维度需要人工补充确认。"

    return "6. 综合执行结果判断：" + conclusion


def _clean_recommendations(rec_text: str) -> str:
    value = _safe(rec_text)
    lines: List[str] = []

    for raw in value.splitlines():
        item = _safe(raw)
        if not item:
            continue
        if "capability" in item.lower() or "平台命令映射" in item or "设备平台类型识别" in item:
            continue
        item = re.sub(r"^\s*\d+[\.、]\s*", "", item).strip()
        if item and item not in lines:
            lines.append(item)

    if not lines:
        lines = [
            "核查硬件告警当前是否仍存在，并确认具体对象是风扇、电源、温度、模块、主控、PoE 还是 FEX。",
            "如果为电源 input lost 或冗余丢失，优先检查电源线、PDU、UPS、市电输入和电源模块状态。",
            "如果为温度或风扇异常，优先检查机房温度、风道、风扇转速、进出风方向和是否存在灰尘/遮挡。",
            "如果为模块 offline、diagnostic fail 或 standby supervisor not ready，保留 show module、show diagnostic、show logging 和 inventory 输出，准备 TAC/RMA。",
            "如多台设备同一时间出现电源或温度异常，优先按机房环境或供电事件处理，而不是单台设备硬件更换。",
        ]

    return "\n".join(f"{idx}. {item}" for idx, item in enumerate(lines[:5], start=1))



def _normalize_cisco_temperature_display(text: str) -> str:
    """
    当前 Cisco SNMP exporter 中 entSensorValue 温度值常见为原始毫摄氏度，
    例如 33550 表示 33.55℃。只对 temperature_celsius 段落里的 celsius 数值做展示换算。
    """
    value = _safe(text)
    if not value or "temperature_celsius" not in value:
        return value

    lines = value.splitlines()
    out = []
    in_temp_block = False

    number_pattern = re.compile(r"([-+]?\d+(?:\.\d+)?)\s+celsius")

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("- temperature_celsius:"):
            in_temp_block = True
            out.append(line)
            continue

        if in_temp_block and stripped.startswith("- ") and not stripped.startswith("- temperature_celsius:"):
            in_temp_block = False

        if in_temp_block:
            def repl(match):
                raw = float(match.group(1))
                if abs(raw) >= 1000:
                    converted = raw / 1000.0
                    return f"{converted:.2f}℃"
                return f"{raw:.2f}℃"

            line = number_pattern.sub(repl, line)

        out.append(line)

    return "\n".join(out)

def rewrite_cisco_hardware_notification_text(text: str, request_id: Optional[str] = None) -> str:
    original = _safe(text)
    if not _is_cisco_hardware_text(original):
        return original

    prom_text, text_without_prom = _parse_prom_block(original)
    head, analysis_text, rec_text = _extract_analysis_and_recommendations(text_without_prom)

    if not analysis_text:
        return original

    command_line = ""
    for raw_line in analysis_text.splitlines():
        line = _safe(raw_line)
        if "已完成MCP只读取证" in line or "命令执行概况" in line:
            command_line = line
            break

    command_overview, success_cmds, failed_cmds, partial_cmds = _parse_summary_line(command_line)
    if not command_overview:
        command_overview, success_cmds, failed_cmds, partial_cmds = _parse_per_command_lines(analysis_text)

    if not command_overview:
        command_overview = (
            "3. 命令执行概况：本次硬件部件故障只读取证已执行，"
            "但通知文本未能解析出完整成功/失败命令清单，请结合 execution 记录复核。"
        )
        success_cmds = []
        failed_cmds = []

    sections = [
        _extract_initial(analysis_text),
        _build_alarm_meaning(),
        command_overview,
        _build_command_analysis(original, success_cmds, failed_cmds),
        _normalize_prometheus_section(prom_text),
        _build_overall(original, prom_text, failed_cmds),
    ]

    result = head.rstrip() + "\n\n分析过程：\n" + "\n".join(sections)
    rec = _clean_recommendations(rec_text)
    if rec:
        result += "\n\n建议：\n" + rec

    return _normalize_cisco_temperature_display(result.strip())
