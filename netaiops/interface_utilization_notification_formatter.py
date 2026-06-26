#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cisco interface/link utilization high notification formatter v9.5.

核心要求：
- 利用率高不是流量突增/突降。
- 支持多接口聚合口径，尤其 WG88互联网线路_电信_100M = Te1/0/1 + Te2/0/1。
- Prometheus 证据需要展示总 bps、总利用率、当前值、5分钟前对比值。
- 命令清单逐行展示。
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


BASE_DIR = Path("/opt/netaiops-webhook")
DATA_DIR = BASE_DIR / "data"


def _safe(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _walk(obj: Any, limit: int = 30000) -> str:
    parts: List[str] = []

    def rec(x: Any):
        if len(" ".join(parts)) > limit:
            return
        if isinstance(x, dict):
            for k, v in x.items():
                parts.append(str(k))
                rec(v)
        elif isinstance(x, list):
            for v in x:
                rec(v)
        elif x is not None:
            parts.append(str(x))

    rec(obj)
    return " ".join(parts)[:limit]


def _is_utilization(payload: Optional[Dict[str, Any]], text: str) -> bool:
    blob = text + " " + (_walk(payload) if isinstance(payload, dict) else "")
    return bool(re.search(
        r"interface_or_link_utilization_high|cisco_interface_utilization_high|接口.?链路.?利用率|接口.?利用率|链路.?利用率|利用率超过|利用率高|WG88互联网线路_电信_100M_利用率|in_util_percent|out_util_percent",
        blob,
        flags=re.I,
    ))


def _target_scope(payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    ts = payload.get("target_scope")
    if isinstance(ts, dict):
        return ts
    target = payload.get("target")
    if isinstance(target, dict) and isinstance(target.get("target_scope"), dict):
        return target.get("target_scope")
    return {}


def _request_id(payload: Optional[Dict[str, Any]], request_id: Optional[str]) -> str:
    return _safe(request_id or ((payload or {}).get("request_id") if isinstance(payload, dict) else ""))


def _find_latest(patterns: List[str]) -> Optional[Path]:
    files: List[Path] = []
    for pattern in patterns:
        files.extend(DATA_DIR.glob(pattern))
    files = [p for p in files if p.is_file()]
    if not files:
        return None
    return sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)[0]


def _load_json(path: Optional[Path]) -> Dict[str, Any]:
    if not path:
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _load_execution(request_id: str) -> Dict[str, Any]:
    if not request_id:
        return {}
    return _load_json(_find_latest([
        f"execution/*_{request_id}.execution.json",
        f"execution/*{request_id}*.json",
    ]))


def _load_prom(request_id: str) -> Dict[str, Any]:
    if not request_id:
        return {}
    return _load_json(_find_latest([
        f"prometheus_evidence/*_{request_id}.prometheus_evidence.json",
        f"prometheus_evidence/*{request_id}*.json",
        f"*/*{request_id}*prometheus*.json",
    ]))


def _command_results(payload: Optional[Dict[str, Any]], request_id: str) -> List[Dict[str, Any]]:
    if isinstance(payload, dict):
        cr = payload.get("command_results")
        if isinstance(cr, list) and cr:
            return cr
        ed = payload.get("execution_data")
        if isinstance(ed, dict) and isinstance(ed.get("command_results"), list):
            return ed.get("command_results")
    ed = _load_execution(request_id)
    cr = ed.get("command_results")
    return cr if isinstance(cr, list) else []


_HARD_ERROR_RE = re.compile(
    r"%\s*Invalid command|%\s*Invalid input detected|%\s*Ambiguous command|%\s*Incomplete command|Invalid interface format|Unknown command|syntax error|not supported",
    re.I,
)


def _cmd(item: Dict[str, Any]) -> str:
    return _safe(item.get("command") or item.get("cmd") or item.get("raw_command"))


def _status(item: Dict[str, Any]) -> str:
    text = _safe(item.get("output")) + "\n" + _safe(item.get("error"))
    judge = item.get("judge") if isinstance(item.get("judge"), dict) else {}
    if judge.get("hard_error") is True or _HARD_ERROR_RE.search(text):
        return "failed"
    status = _safe(item.get("dispatch_status") or item.get("status") or judge.get("final_status")).lower()
    if status in ("completed", "success", "succeeded", "ok"):
        return "completed"
    if status in ("failed", "failure", "error", "timeout"):
        return "failed"
    return "partial"


def _unique(values: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for v in values:
        v = _safe(v)
        if not v or v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def _format_command_overview(results: List[Dict[str, Any]]) -> Tuple[str, List[str], List[str], List[str]]:
    completed: List[str] = []
    failed: List[str] = []
    partial: List[str] = []
    for item in results:
        cmd = _cmd(item)
        if not cmd:
            continue
        s = _status(item)
        if s == "completed":
            completed.append(cmd)
        elif s == "failed":
            failed.append(cmd)
        else:
            partial.append(cmd)

    completed = _unique(completed)
    failed = _unique(failed)
    partial = _unique(partial)
    total = len(completed) + len(failed) + len(partial)

    if total == 0:
        return "3. 命令执行概况：本次未获取到结构化命令结果，请检查 execution.json / callback payload。", completed, failed, partial

    lines = [f"3. 命令执行概况：本次共执行 {total} 条只读命令，成功 {len(completed)} 条，具体如下："]
    lines.extend(completed if completed else ["无"])
    if failed:
        lines.append(f"失败 {len(failed)} 条，具体如下：")
        lines.extend(failed)
    else:
        lines.append("失败 0 条。失败命令：无。")
    if partial:
        lines.append(f"部分完成 {len(partial)} 条，具体如下：")
        lines.extend(partial)
    else:
        lines.append("部分完成 0 条。部分完成命令：无。")
    return "\n".join(lines), completed, failed, partial


def _prom_text(payload: Optional[Dict[str, Any]], request_id: str) -> str:
    if isinstance(payload, dict):
        nv = payload.get("notify_view")
        if isinstance(nv, dict) and _safe(nv.get("prometheus_evidence_text")):
            return _safe(nv.get("prometheus_evidence_text"))
        pe = payload.get("prometheus_evidence")
        if isinstance(pe, dict) and _safe(pe.get("summary_text")):
            return _safe(pe.get("summary_text"))
    prom = _load_prom(request_id)
    return _safe(prom.get("summary_text") or prom.get("text"))


def _normalize_prom_section(text: str) -> str:
    value = _safe(text)
    if not value:
        return (
            "5. Prometheus窗口证据：\n"
            "- 状态：未找到 Prometheus evidence 文件或通知 payload 未携带 prometheus_evidence_text。\n"
            "- 说明：这表示通知链路未拿到历史指标摘要，不代表 Prometheus 后端无数据。"
        )
    if value.startswith("5. Prometheus窗口证据："):
        return value
    if value.startswith("Prometheus窗口证据："):
        return "5. " + value
    return "5. Prometheus窗口证据：\n" + value


def _head(text: str) -> str:
    marker = "\n分析过程："
    if marker in text:
        return text.split(marker, 1)[0].rstrip()
    return text.rstrip()


def _interfaces(scope: Dict[str, Any], blob: str) -> List[str]:
    value = scope.get("interfaces")
    if isinstance(value, list):
        items = [str(x).strip() for x in value if str(x).strip()]
        if items:
            return items
    value = _safe(scope.get("interface_regex") or scope.get("interface") or scope.get("ifName") or scope.get("if_name"))
    if value:
        return [x.strip() for x in re.split(r"[|,]", value) if x.strip()]
    if "WG88互联网线路_电信_100M" in blob:
        return ["Te1/0/1", "Te2/0/1"]
    return []


def _direction(scope: Dict[str, Any], blob: str) -> str:
    value = _safe(scope.get("direction") or scope.get("traffic_direction")).lower()
    if value in ("out", "output", "outbound"):
        return "出向"
    if value in ("in", "input", "inbound"):
        return "入向"
    if re.search(r"出向|出口|outbound|output|out_bps|out_util", blob, flags=re.I):
        return "出向"
    if re.search(r"入向|入口|inbound|input|in_bps|in_util", blob, flags=re.I):
        return "入向"
    return "未知"


def _capacity(scope: Dict[str, Any], blob: str) -> Tuple[str, str]:
    value = _safe(scope.get("capacity_bps") or scope.get("link_capacity_bps"))
    if value:
        try:
            bps = float(value)
            if bps >= 1000 * 1000 * 1000:
                return str(int(bps)), f"{bps/1000/1000/1000:.0f}G"
            if bps >= 1000 * 1000:
                return str(int(bps)), f"{bps/1000/1000:.0f}M"
            if bps >= 1000:
                return str(int(bps)), f"{bps/1000:.0f}K"
            return str(int(bps)), f"{bps:.0f}bps"
        except Exception:
            return value, value
    if "WG88互联网线路_电信_100M" in blob:
        return "100000000", "100M"
    m = re.search(r"(\d+(?:\.\d+)?)\s*([KMG])", blob, flags=re.I)
    if m:
        num = float(m.group(1))
        unit = m.group(2).upper()
        factor = {"K": 1000, "M": 1000 * 1000, "G": 1000 * 1000 * 1000}[unit]
        return str(int(num * factor)), f"{num:g}{unit}"
    return "", "未知"


def _failed_detail(results: List[Dict[str, Any]], failed: List[str]) -> str:
    if not failed:
        return ""
    details = []
    failed_set = set(failed)
    for item in results:
        cmd = _cmd(item)
        if cmd not in failed_set:
            continue
        err = _safe(item.get("error"))
        out = _safe(item.get("output"))
        matched = _HARD_ERROR_RE.search(out + "\n" + err)
        reason = err or (matched.group(0) if matched else "")
        details.append(f"{cmd}：{reason}" if reason else cmd)
    return "；".join(_unique(details))


def _prom_failed_count(prom_text: str) -> Optional[int]:
    m = re.search(r"失败/无数据\s*(\d+)\s*项", prom_text)
    if m:
        return int(m.group(1))
    if re.search(r"不可用|no_data|query_failed|timeout", prom_text, flags=re.I):
        return 1
    return None


def _build_sections(payload: Optional[Dict[str, Any]], original: str, results: List[Dict[str, Any]], prom: str) -> List[str]:
    scope = _target_scope(payload)
    blob = original + " " + _walk(payload) + " " + prom
    interfaces = _interfaces(scope, blob)
    direction = _direction(scope, blob)
    _, cap_display = _capacity(scope, blob)
    link_name = _safe(scope.get("link_name") or scope.get("object_name")) or (" + ".join(interfaces) if interfaces else "目标链路")
    aggregate = len(interfaces) > 1 or bool(scope.get("aggregate_circuit"))
    aggregate_text = f"，该告警为多接口聚合口径，成员接口为 {' + '.join(interfaces)}，逻辑容量为 {cap_display}" if aggregate else ""

    overview, completed, failed, partial = _format_command_overview(results)

    prom_section = _normalize_prom_section(prom)
    prom_failed = _prom_failed_count(prom)
    if prom_failed is None:
        prom_state = "Prometheus 窗口证据已返回，但无法从摘要中直接判断失败项数量"
    elif prom_failed == 0:
        prom_state = "Prometheus 窗口证据已成功返回，未见失败/无数据项"
    else:
        prom_state = f"Prometheus 窗口证据存在 {prom_failed} 项失败/无数据"

    failed_detail = _failed_detail(results, failed)
    cli_state = "CLI 侧未发现命令执行硬错误" if not failed else f"CLI 侧存在失败命令：{failed_detail}"

    return [
        (
            f"1. 根据告警内容初步判断：Cisco 设备 {link_name} 触发接口/链路利用率高告警，"
            f"告警方向为{direction}{aggregate_text}。需要先确认高利用率是否真实、是否持续、"
            "是否已经恢复，并排除监控口径、采样周期、接口计数器清零、聚合统计口径错误等因素。"
        ),
        (
            "2. 告警含义分析：接口/链路利用率高不一定代表链路故障。"
            "如果利用率高但无 drop/error，可能只是正常业务高峰、容量压力、链路切流、备份同步；"
            "如果伴随 output drops/discards 或 QoS drop，才更偏向出口拥塞或策略限速；"
            "如果伴随 CRC/FCS/input error，则优先考虑物理链路质量问题。"
            "多接口逻辑链路必须用成员接口流量总和除以告警逻辑容量计算利用率。"
        ),
        overview,
        (
            "4. 命令分析：本次已围绕接口状态、当前速率、错误包、drop、QoS、聚合/LACP、"
            "trunk/VLAN、STP、MAC、storm-control、光模块等维度完成接口/链路利用率高第一轮只读取证。"
            + cli_state + "。"
        ),
        prom_section,
        (
            "6. 综合执行结果判断："
            f"{prom_state}；{cli_state}。"
            f"本次告警方向为{direction}。"
            "如果 Prometheus 聚合利用率与 CLI 当前速率一致，则高利用率可信；"
            "如果两者不一致，应优先核查监控口径、SNMP ifIndex、采样周期、接口映射、"
            "是否重复统计 Port-channel 与成员口，以及告警逻辑容量是否正确。"
        ),
    ]


def _recommendations(original: str, payload: Optional[Dict[str, Any]]) -> str:
    scope = _target_scope(payload)
    blob = original + " " + _walk(payload)
    interfaces = _interfaces(scope, blob)
    aggregate = len(interfaces) > 1 or bool(scope.get("aggregate_circuit"))

    recs = []
    if aggregate:
        recs.append(f"按告警口径继续以 {' + '.join(interfaces)} 的总流量计算利用率，不要只看单个物理接口。")
    recs.extend([
        "先对比 Prometheus 聚合利用率窗口和设备 CLI 当前速率，确认高利用率是否仍在持续。",
        "如果当前利用率已低于阈值，优先结合告警触发窗口判断是否为瞬时峰值或业务高峰。",
        "如果 output drops/discards、policy-map drop 或 police exceeded 增长，优先排查出口拥塞、QoS 队列和限速策略。",
        "如果 CRC/FCS/input error 增长，优先排查光模块、光纤、ODF、对端端口和物理链路质量。",
        "如果接口无错误但长期高，建议进入容量评估、业务源定位、NetFlow/ACL 计数、路由路径和对端设备排查。",
    ])
    return "\n".join(f"{i}. {x}" for i, x in enumerate(recs[:6], 1))


def rewrite_interface_utilization_notification_text(
    text: str,
    payload: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None,
) -> str:
    original = _safe(text)
    if not _is_utilization(payload, original):
        return original

    rid = _request_id(payload, request_id)
    results = _command_results(payload, rid)
    prom = _prom_text(payload, rid)

    head = _head(original)
    if not head:
        head = "告警内容：\n接口/链路利用率高"

    sections = _build_sections(payload, original, results, prom)
    return head.rstrip() + "\n\n分析过程：\n" + "\n".join(sections) + "\n\n建议：\n" + _recommendations(original, payload)
