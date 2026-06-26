#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cisco interface traffic spike/drop notification formatter v9.4.

修复目标：
1. 不再依赖最终文本正则解析命令清单。
2. 优先从 execution.json / payload.command_results 读取结构化命令结果。
3. 优先从 payload.notify_view.prometheus_evidence_text / prometheus_evidence.json 读取 Prometheus窗口证据。
4. 彻底覆盖旧 formatter 中“未展示”“硬件历史趋势”“模块/板卡/主控”等串场内容。
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


def _lower(value: Any) -> str:
    return _safe(value).lower()


def _get(d: Dict[str, Any], *keys: str) -> Any:
    if not isinstance(d, dict):
        return ""
    for k in keys:
        v = d.get(k)
        if v not in (None, "", [], {}):
            return v
    return ""


def _walk_strings(obj: Any, limit: int = 20000) -> str:
    parts: List[str] = []

    def walk(x: Any) -> None:
        if len(" ".join(parts)) > limit:
            return
        if isinstance(x, dict):
            for k, v in x.items():
                parts.append(str(k))
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
        elif x is not None:
            parts.append(str(x))

    walk(obj)
    return " ".join(parts)[:limit]


def _is_interface_traffic(payload: Optional[Dict[str, Any]], text: str) -> bool:
    blob = text + " " + (_walk_strings(payload) if isinstance(payload, dict) else "")
    return bool(re.search(
        r"interface_traffic_anomaly|cisco_interface_traffic_anomaly|cisco_interface_or_link_traffic_drop|"
        r"接口.?链路.?流量|骨干网.*流量|互联网.*流量|流量突增|流量突降|"
        r"in_bps|out_bps|ifHCInOctets|ifHCOutOctets",
        blob,
        flags=re.I,
    ))


def _request_id_from_payload(payload: Optional[Dict[str, Any]], request_id: Optional[str]) -> str:
    if request_id:
        return request_id
    if isinstance(payload, dict):
        return _safe(payload.get("request_id"))
    return ""


def _load_json_file(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _find_latest_file(patterns: List[str]) -> Optional[Path]:
    files: List[Path] = []
    for pattern in patterns:
        files.extend(DATA_DIR.glob(pattern))
    files = [p for p in files if p.is_file()]
    if not files:
        return None
    return sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)[0]


def _load_execution_by_request_id(request_id: str) -> Dict[str, Any]:
    if not request_id:
        return {}
    path = _find_latest_file([
        f"execution/*_{request_id}.execution.json",
        f"execution/*{request_id}*.json",
    ])
    return _load_json_file(path) if path else {}


def _load_prometheus_by_request_id(request_id: str) -> Dict[str, Any]:
    if not request_id:
        return {}
    path = _find_latest_file([
        f"prometheus_evidence/*_{request_id}.prometheus_evidence.json",
        f"prometheus_evidence/*{request_id}*.json",
        f"*/*{request_id}*prometheus*.json",
    ])
    return _load_json_file(path) if path else {}


def _extract_command_results(payload: Optional[Dict[str, Any]], request_id: str) -> List[Dict[str, Any]]:
    if isinstance(payload, dict):
        cr = payload.get("command_results")
        if isinstance(cr, list) and cr:
            return cr

        execution_data = payload.get("execution_data")
        if isinstance(execution_data, dict):
            cr = execution_data.get("command_results")
            if isinstance(cr, list) and cr:
                return cr

    execution_data = _load_execution_by_request_id(request_id)
    cr = execution_data.get("command_results")
    if isinstance(cr, list):
        return cr
    return []


_HARD_ERROR_RE = re.compile(
    r"%\s*Invalid command|%\s*Invalid input detected|%\s*Ambiguous command|%\s*Incomplete command|"
    r"Invalid interface format|Invalid range|Unknown command|command not found|syntax error|not supported on this platform",
    re.I,
)


def _status_of_command(item: Dict[str, Any]) -> str:
    status = _lower(
        item.get("dispatch_status")
        or item.get("status")
        or item.get("final_status")
        or ((item.get("judge") or {}) if isinstance(item.get("judge"), dict) else {}).get("final_status")
    )

    output = _safe(item.get("output"))
    error = _safe(item.get("error"))
    judge = item.get("judge") if isinstance(item.get("judge"), dict) else {}

    if judge.get("hard_error") is True or _HARD_ERROR_RE.search(output + "\n" + error):
        return "failed"

    if status in ("completed", "success", "succeeded", "ok"):
        return "completed"
    if status in ("failed", "failure", "error", "timeout"):
        return "failed"
    if status in ("partial", "partially_completed", "partial_completed"):
        return "partial"
    return "partial"


def _command_of(item: Dict[str, Any]) -> str:
    return _safe(item.get("command") or item.get("cmd") or item.get("raw_command"))


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


def _format_command_overview(command_results: List[Dict[str, Any]]) -> Tuple[str, List[str], List[str], List[str]]:
    completed: List[str] = []
    failed: List[str] = []
    partial: List[str] = []

    for item in command_results or []:
        cmd = _command_of(item)
        if not cmd:
            continue
        status = _status_of_command(item)
        if status == "completed":
            completed.append(cmd)
        elif status == "failed":
            failed.append(cmd)
        else:
            partial.append(cmd)

    completed = _unique(completed)
    failed = _unique(failed)
    partial = _unique(partial)

    total = len(completed) + len(failed) + len(partial)

    if total == 0:
        return (
            "3. 命令执行概况：本次未获取到结构化命令结果，请检查 execution.json / callback payload 是否生成。",
            completed,
            failed,
            partial,
        )

    lines = [
        f"3. 命令执行概况：本次共执行 {total} 条只读命令，成功 {len(completed)} 条，具体如下："
    ]

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


def _extract_head(text: str) -> str:
    marker = "\n分析过程："
    if marker in text:
        return text.split(marker, 1)[0].rstrip()
    return text.rstrip()


def _target_scope(payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    ts = payload.get("target_scope")
    if isinstance(ts, dict):
        return ts
    return {}


def _alarm_content_from_text(head: str) -> str:
    marker = "告警内容："
    if marker not in head:
        return ""
    return head.split(marker, 1)[1].strip()


def _device_from_payload_or_head(payload: Optional[Dict[str, Any]], head: str) -> str:
    notify_view = payload.get("notify_view") if isinstance(payload, dict) else {}
    if isinstance(notify_view, dict) and _safe(notify_view.get("device")):
        return _safe(notify_view.get("device"))

    m = re.search(r"设备[:：]\s*(.+)", head)
    if m:
        return m.group(1).strip()

    ts = _target_scope(payload)
    hostname = _safe(_get(ts, "hostname", "sysName", "device"))
    ip = _safe(_get(ts, "device_ip", "ip", "instance"))
    if hostname and ip:
        return f"{hostname}（{ip}）"
    return hostname or ip or "无"


def _infer_change_type(payload: Optional[Dict[str, Any]], text: str) -> str:
    ts = _target_scope(payload)
    value = _safe(_get(ts, "traffic_change_type"))
    if value.lower() == "spike":
        return "突增"
    if value.lower() == "drop":
        return "突降"

    blob = text + " " + _walk_strings(payload)
    if re.search(r"突增|升高|超过|高于|spike|increase|high", blob, flags=re.I):
        return "突增"
    if re.search(r"突降|下降|降低|归零|drop|decrease|low", blob, flags=re.I):
        return "突降"
    return "异常"


def _infer_direction(payload: Optional[Dict[str, Any]], text: str) -> str:
    ts = _target_scope(payload)
    value = _safe(_get(ts, "direction", "traffic_direction"))
    if value.lower() in ("in", "inbound", "input"):
        return "入向"
    if value.lower() in ("out", "outbound", "output"):
        return "出向"

    blob = text + " " + _walk_strings(payload)
    if re.search(r"入向|入口|inbound|input|in_bps|ifHCInOctets", blob, flags=re.I):
        return "入向"
    if re.search(r"出向|出口|outbound|output|out_bps|ifHCOutOctets", blob, flags=re.I):
        return "出向"
    return "未知"


def _prometheus_text_from_payload_or_file(payload: Optional[Dict[str, Any]], request_id: str) -> str:
    if isinstance(payload, dict):
        notify_view = payload.get("notify_view")
        if isinstance(notify_view, dict):
            value = _safe(notify_view.get("prometheus_evidence_text"))
            if value:
                return value

        prom = payload.get("prometheus_evidence")
        if isinstance(prom, dict):
            value = _safe(prom.get("summary_text") or prom.get("text"))
            if value:
                return value

    prom = _load_prometheus_by_request_id(request_id)
    value = _safe(prom.get("summary_text") or prom.get("text"))
    if value:
        return value

    return ""


def _normalize_prometheus_section(prom_text: str) -> str:
    value = _safe(prom_text)
    if not value:
        return (
            "5. Prometheus窗口证据：\n"
            "- 状态：未找到 Prometheus evidence 文件或 payload 中未携带 prometheus_evidence_text。\n"
            "- 说明：这表示通知链路未拿到历史指标摘要，不代表 Prometheus 后端无数据。"
        )
    value = value.replace("硬件历史趋势判断存在边界", "接口流量历史趋势判断存在边界")
    value = value.replace("模块/板卡/主控", "接口/链路")
    if value.startswith("5. Prometheus窗口证据："):
        return value
    if value.startswith("Prometheus窗口证据："):
        return "5. " + value
    return "5. Prometheus窗口证据：\n" + value


def _failed_detail(command_results: List[Dict[str, Any]], failed_commands: List[str]) -> str:
    if not failed_commands:
        return ""

    details = []
    failed_set = set(failed_commands)
    for item in command_results:
        cmd = _command_of(item)
        if cmd not in failed_set:
            continue
        err = _safe(item.get("error"))
        out = _safe(item.get("output"))
        matched = _HARD_ERROR_RE.search(out + "\n" + err)
        reason = err or (matched.group(0) if matched else "")
        if reason:
            details.append(f"{cmd}：{reason}")
        else:
            details.append(cmd)
    return "；".join(_unique(details))


def _build_initial(payload: Optional[Dict[str, Any]], text: str) -> str:
    ts = _target_scope(payload)
    iface = _safe(_get(ts, "interface", "ifName", "if_name", "object_name")) or "目标接口"
    change = _infer_change_type(payload, text)
    direction = _infer_direction(payload, text)
    return (
        f"1. 根据告警内容初步判断：Cisco 设备 {iface} 触发接口/链路流量{change}告警，"
        f"告警方向为{direction}。需要先确认流量变化是否真实发生，再排除监控口径、采样周期、"
        "接口重启、计数器清零、聚合负载变化等表象原因。"
    )


def _build_meaning() -> str:
    return (
        "2. 告警含义分析：接口/链路流量突增或突降不等同于链路故障，也不一定等同于业务异常。"
        "该类告警需要结合 Prometheus 历史窗口中的 in_bps/out_bps 当前值和5分钟前对比值，"
        "再对照 CLI 当前速率、接口状态、错误包、drop、QoS、Port-channel/LACP、VLAN/STP、光模块等证据综合判断。"
    )


def _build_command_analysis(payload: Optional[Dict[str, Any]], command_results: List[Dict[str, Any]], completed: List[str], failed: List[str], partial: List[str]) -> str:
    change = _infer_change_type(payload, _walk_strings(payload))
    direction = _infer_direction(payload, _walk_strings(payload))

    dimensions = []
    for cmd in completed + failed + partial:
        low = cmd.lower()
        if "interface status" in low:
            dimensions.append("接口状态")
        if re.search(r"show interfaces? .+", low) and "counters" not in low and "transceiver" not in low:
            dimensions.append("当前速率/接口详情")
        if "counters errors" in low or "counters" in low:
            dimensions.append("错误包/计数器")
        if "policy-map interface" in low:
            dimensions.append("QoS/policy-map")
        if "transceiver" in low:
            dimensions.append("光模块/收发光")
        if "port-channel" in low or "etherchannel" in low or "lacp" in low:
            dimensions.append("聚合/LACP")
        if "trunk" in low:
            dimensions.append("trunk")
        if "spanning-tree" in low:
            dimensions.append("STP")
        if "vlan brief" in low:
            dimensions.append("VLAN")
        if "logging" in low:
            dimensions.append("日志时间线")

    dimensions = _unique(dimensions) or ["接口状态", "当前速率", "错误包/丢弃", "QoS", "聚合/LACP", "二层路径", "光模块"]

    failed_text = _failed_detail(command_results, failed)
    if failed_text:
        suffix = f"失败命令及原因：{failed_text}。"
    else:
        suffix = "未发现命令执行硬错误。"

    return (
        "4. 命令分析：本次已围绕 "
        + "、".join(dimensions)
        + f" 等维度完成接口/链路流量{change}第一轮只读取证，告警方向识别为{direction}。"
        + suffix
    )


def _prometheus_brief(prom_text: str) -> str:
    value = _safe(prom_text)
    if not value:
        return "Prometheus 窗口证据未进入通知文本，需要检查 evidence 注入链路"
    if re.search(r"失败|无数据|timeout|no_data|query_failed", value, flags=re.I):
        return "Prometheus 窗口证据存在失败或无数据项，历史趋势判断存在边界"
    if "in_bps" in value or "out_bps" in value:
        return "Prometheus 已返回 in_bps/out_bps 历史窗口证据，可用于确认当前值、5分钟前对比值、变化量和变化比例"
    return "Prometheus 窗口证据已返回"


def _build_overall(payload: Optional[Dict[str, Any]], prom_text: str, command_results: List[Dict[str, Any]], failed: List[str]) -> str:
    change = _infer_change_type(payload, prom_text)
    direction = _infer_direction(payload, prom_text)
    prom = _prometheus_brief(prom_text)

    failed_detail = _failed_detail(command_results, failed)
    if failed_detail:
        cli_state = f"CLI 侧仍有失败命令：{failed_detail}"
    else:
        cli_state = "CLI 侧未发现命令执行硬错误"

    return (
        "6. 综合执行结果判断："
        f"{prom}；{cli_state}。"
        f"本次告警方向为{direction}，变化类型为流量{change}。"
        "如果 Prometheus 当前值和 CLI 当前速率一致，则流量变化可信；"
        "如果两者不一致，应优先排查监控口径、采样周期、SNMP index、接口名称映射和计数器清零。"
    )


def _extract_recommendations(text: str) -> List[str]:
    rec = ""
    marker = "\n建议："
    if marker in text:
        rec = text.split(marker, 1)[1]
    lines = []
    for raw in rec.splitlines():
        item = raw.strip()
        if not item:
            continue
        item = re.sub(r"^\s*\d+[\.、]\s*", "", item).strip()
        if not item:
            continue
        if "capability" in item.lower() or "平台命令映射" in item or "设备平台类型识别" in item:
            continue
        if "模块/板卡/主控" in item:
            continue
        lines.append(item)
    return _unique(lines)


def _build_recommendations(text: str) -> str:
    lines = _extract_recommendations(text)
    if not lines:
        lines = [
            "先对比 Prometheus 历史窗口和 CLI 当前 input/output rate，确认流量突增/突降是否真实发生。",
            "如果 CLI 与 Prometheus 不一致，优先核查监控采样周期、SNMP index、接口名称映射、计数器清零和聚合口/成员口重复统计。",
            "如果存在 flap、CRC/FCS、光功率异常，优先查光模块、光纤、ODF、对端端口和链路物理层。",
            "如果存在 output drops、discards、policy-map drop 或 police exceeded，优先查 QoS、队列拥塞和业务峰值。",
            "如果目标接口属于 Port-channel，优先查成员状态、LACP 邻居和是否发生哈希重分担。",
            "如果第一轮状态均正常，再进入路由路径、业务源、NetFlow、ACL计数和对端设备排查。",
        ]

    return "\n".join(f"{idx}. {item}" for idx, item in enumerate(lines[:6], 1))


def rewrite_interface_traffic_notification_text(
    text: str,
    payload: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None,
) -> str:
    original = _safe(text)
    if not _is_interface_traffic(payload, original):
        return original

    rid = _request_id_from_payload(payload, request_id)
    command_results = _extract_command_results(payload, rid)
    prom_text = _prometheus_text_from_payload_or_file(payload, rid)

    head = _extract_head(original)

    # 如果原始 head 为空，兜底重建设备/告警内容。
    if not head:
        device = _device_from_payload_or_head(payload, "")
        alarm_content = ""
        if isinstance(payload, dict):
            notify_view = payload.get("notify_view") if isinstance(payload.get("notify_view"), dict) else {}
            alarm_content = _safe(notify_view.get("alarm_content"))
        head = f"设备：{device}\n\n告警内容：\n{alarm_content or '接口/链路流量突增突降告警'}"

    command_overview, completed, failed, partial = _format_command_overview(command_results)

    sections = [
        _build_initial(payload, original),
        _build_meaning(),
        command_overview,
        _build_command_analysis(payload, command_results, completed, failed, partial),
        _normalize_prometheus_section(prom_text),
        _build_overall(payload, prom_text, command_results, failed),
    ]

    return head.rstrip() + "\n\n分析过程：\n" + "\n".join(sections) + "\n\n建议：\n" + _build_recommendations(original)
