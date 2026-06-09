#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple


ROOT = Path("/opt/netaiops-webhook")

MEMORY_FAMILY_CANONICAL = "device_memory_utilization_high"
MEMORY_FAMILY_ALIASES = {
    "device_memory_high",
    "device_memory_utilization_high",
    "cisco_device_memory_utilization_high",
    "memory_high",
    "cisco_memory_high",
    "device_memory",
}


def _safe_text(value: Any) -> str:
    return "" if value is None else str(value)


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return {}


def _is_memory_text(text: str) -> bool:
    t = _safe_text(text)
    low = t.lower()
    return (
        any(x in low for x in MEMORY_FAMILY_ALIASES)
        or "memory high" in low
        or "memory utilization" in low
        or "内存利用率" in t
        or "内存使用率" in t
        or "设备内存" in t
    )


def _is_memory_obj(obj: Any) -> bool:
    try:
        text = json.dumps(obj, ensure_ascii=False, default=str)
    except Exception:
        text = _safe_text(obj)
    return _is_memory_text(text)


def normalize_memory_family_in_obj(obj: Any) -> Any:
    if not isinstance(obj, dict):
        return obj

    def fix_dict(d: Dict[str, Any]) -> None:
        fam = _safe_text(d.get("family")).strip()
        skill = _safe_text(d.get("skill_name")).strip()
        playbook_id = _safe_text(d.get("playbook_id")).strip()
        alarm_type = _safe_text(d.get("alarm_type")).strip()

        if (
            fam in MEMORY_FAMILY_ALIASES
            or skill in MEMORY_FAMILY_ALIASES
            or playbook_id == "cisco_device_memory_utilization_high"
            or _is_memory_text(alarm_type)
        ):
            d["family"] = MEMORY_FAMILY_CANONICAL
            d["skill_name"] = "device_memory_utilization_high"

        for v in d.values():
            if isinstance(v, dict):
                fix_dict(v)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        fix_dict(item)

    fix_dict(obj)
    return obj


def _alert_content(request_id: str) -> str:
    raw = _load_json(ROOT / f"data/raw/alertmanager_{request_id}.json")
    norm = _load_json(ROOT / f"data/normalized/alertmanager_{request_id}.json")

    parts: List[str] = []

    def add(v: Any) -> None:
        s = _safe_text(v).strip()
        if s and s not in parts:
            parts.append(s)

    # Alertmanager 原始结构
    alerts = raw.get("alerts") if isinstance(raw.get("alerts"), list) else []
    if alerts:
        a0 = alerts[0] if isinstance(alerts[0], dict) else {}
        labels = a0.get("labels") or {}
        annotations = a0.get("annotations") or {}
        add(labels.get("alertname"))
        add(annotations.get("summary"))
        add(annotations.get("description"))

    common_labels = raw.get("commonLabels") or {}
    common_annotations = raw.get("commonAnnotations") or {}
    add(common_labels.get("alertname"))
    add(common_annotations.get("summary"))
    add(common_annotations.get("description"))

    # normalized 兜底
    add(norm.get("alertname"))
    add(norm.get("summary"))
    add(norm.get("description"))

    text = " ".join([p for p in parts if p])
    return text.strip() or "Cisco Memory High 设备内存利用率异常。"


def _find_first_dict(*objs: Any) -> Dict[str, Any]:
    for obj in objs:
        if isinstance(obj, dict):
            return obj
    return {}


def _get_target(review: Dict[str, Any], plan: Dict[str, Any], execution: Dict[str, Any]) -> Dict[str, Any]:
    eb = review.get("evidence_bundle") if isinstance(review.get("evidence_bundle"), dict) else {}
    target = _find_first_dict(
        review.get("target_scope"),
        eb.get("target_scope"),
        plan.get("target_scope"),
        execution.get("target_scope"),
    )

    device_ip = (
        target.get("device_ip")
        or target.get("ip")
        or target.get("instance")
        or target.get("hostname")
        or ""
    )
    hostname = target.get("hostname") or target.get("sysName") or device_ip or "unknown"
    if hostname == device_ip:
        # 尽量从 raw/plan 里找 sysName/hostname
        for obj in [plan, execution, review]:
            text = json.dumps(obj, ensure_ascii=False, default=str)
            m = re.search(r'"sysName"\s*:\s*"([^"]+)"', text)
            if m and m.group(1) and m.group(1) != device_ip:
                hostname = m.group(1)
                break

    return {
        "hostname": hostname or "unknown",
        "device_ip": device_ip or "",
        "platform": target.get("platform") or "nxos",
        "vendor": target.get("vendor") or "cisco",
    }


def _extract_commands(review: Dict[str, Any], execution: Dict[str, Any]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            if isinstance(obj.get("command"), str) and obj.get("order") is not None:
                results.append(obj)
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(execution)

    if not results:
        eb = review.get("evidence_bundle") if isinstance(review.get("evidence_bundle"), dict) else {}
        device_outputs = eb.get("device_outputs") if isinstance(eb.get("device_outputs"), list) else []
        for item in device_outputs:
            if isinstance(item, dict) and item.get("command"):
                results.append(item)

    seen = set()
    dedup: List[Dict[str, Any]] = []
    for item in results:
        key = (item.get("order"), item.get("command"))
        if key in seen:
            continue
        seen.add(key)
        dedup.append(item)

    return sorted(dedup, key=lambda x: x.get("order") or 9999)


def _cmd_status(item: Dict[str, Any]) -> Tuple[str, bool]:
    judge = item.get("judge") if isinstance(item.get("judge"), dict) else {}
    status = (
        item.get("dispatch_status")
        or item.get("status")
        or item.get("final_status")
        or judge.get("final_status")
        or ""
    )
    status_s = _safe_text(status).lower()
    hard_error = judge.get("hard_error") is True
    failed = status_s == "failed" or hard_error
    return status_s or "unknown", failed


def _extract_output(item: Dict[str, Any]) -> str:
    for key in ["output", "stdout", "result", "output_preview"]:
        if item.get(key) is not None:
            return _safe_text(item.get(key))
    return ""


def _parse_system_resources(commands: List[Dict[str, Any]]) -> Dict[str, Any]:
    out = ""
    for item in commands:
        if item.get("command") == "show system resources":
            out = _extract_output(item)
            break

    result: Dict[str, Any] = {}
    if not out:
        return result

    m = re.search(
        r"Memory usage:\s*([0-9]+)K\s+total,\s*([0-9]+)K\s+used,\s*([0-9]+)K\s+free",
        out,
        re.I,
    )
    if m:
        total = int(m.group(1))
        used = int(m.group(2))
        free = int(m.group(3))
        pct = used * 100.0 / total if total else 0
        result.update(
            {
                "total_k": total,
                "used_k": used,
                "free_k": free,
                "used_percent": pct,
                "line": m.group(0),
            }
        )

    m_cpu = re.search(r"CPU states\s*:\s*([^\n]+)", out, re.I)
    if m_cpu:
        result["cpu_line"] = m_cpu.group(0).strip()

    return result


def _prom_summary(request_id: str) -> str:
    prom = _load_json(ROOT / f"data/prometheus_evidence/alertmanager_{request_id}.prometheus_evidence.json")
    if not prom:
        return "Prometheus 内存历史窗口证据未生成，本次以内存 CLI 只读取证为主。"

    summary = _safe_text(prom.get("summary_text")).strip()
    if summary:
        return summary

    status = prom.get("status")
    profile = prom.get("profile")
    return f"Prometheus 内存历史窗口状态：{status or 'unknown'}，profile={profile or 'unknown'}。"


def _format_success_failed(commands: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    success: List[str] = []
    failed: List[str] = []

    for item in commands:
        cmd = _safe_text(item.get("command")).strip()
        if not cmd:
            continue
        status, is_failed = _cmd_status(item)
        if is_failed:
            failed.append(f"{cmd}（{status or 'failed'}）")
        else:
            success.append(cmd)

    return success, failed


def _clean_target_scope_in_review(review: Dict[str, Any]) -> None:
    """
    Memory 类告警不应把 alertname 塞进 interface / ifName 字段。
    这里只清理 review/evidence_bundle 内的通知展示上下文，不改原始 raw。
    """
    for obj in [review, review.get("evidence_bundle") if isinstance(review.get("evidence_bundle"), dict) else {}]:
        target = obj.get("target_scope") if isinstance(obj, dict) and isinstance(obj.get("target_scope"), dict) else None
        if not target:
            continue
        for k in ["interface", "if_name", "ifName", "interface_name", "object_name"]:
            v = _safe_text(target.get(k))
            if _is_memory_text(v):
                target[k] = ""


def build_memory_notification_text(request_id: str, review: Dict[str, Any] | None = None) -> str:
    review = review or _load_json(ROOT / f"data/reviews/alertmanager_{request_id}.review.json")
    plan = _load_json(ROOT / f"data/plans/alertmanager_{request_id}.plan.json")
    execution = _load_json(ROOT / f"data/execution/alertmanager_{request_id}.execution.json")

    target = _get_target(review, plan, execution)
    hostname = target.get("hostname") or "unknown"
    device_ip = target.get("device_ip") or ""

    alert_content = _alert_content(request_id)

    # Memory 类告警的 target_scope 里 hostname 有时会退化成管理 IP。
    # 优先从原始告警正文里的 "主机名(IP)"、"目标设备 主机名(IP)" 或 "主机名 设备内存" 模式恢复真实主机名。
    if device_ip and hostname == device_ip:
        hostname_patterns = [
            r"([A-Za-z0-9][A-Za-z0-9_.-]{2,})\s*[（(]\s*" + re.escape(device_ip) + r"\s*[）)]",
            r"目标设备\s*([A-Za-z0-9][A-Za-z0-9_.-]{2,})\s*[（(]\s*" + re.escape(device_ip) + r"\s*[）)]",
            r"([A-Za-z0-9][A-Za-z0-9_.-]{2,})\s+设备内存",
            r"([A-Za-z0-9][A-Za-z0-9_.-]{2,})\s+设备内存利用率异常",
        ]
        for pattern in hostname_patterns:
            m = re.search(pattern, alert_content)
            if m and m.group(1) and m.group(1) != device_ip:
                hostname = m.group(1)
                break

    device_display = f"{hostname}（{device_ip}）" if device_ip else hostname
    commands = _extract_commands(review, execution)
    success_cmds, failed_cmds = _format_success_failed(commands)
    stats_total = len(commands)
    stats_success = len(success_cmds)
    stats_failed = len(failed_cmds)

    sysres = _parse_system_resources(commands)
    prom_text = _prom_summary(request_id)

    now = datetime.now().strftime("%Y%m%d-%H%M")

    memory_fact = ""
    if sysres.get("used_percent") is not None:
        memory_fact = (
            f"设备 CLI 当前 show system resources 显示内存约 {sysres['used_percent']:.2f}% "
            f"used（total={sysres['total_k']}K，used={sysres['used_k']}K，free={sysres['free_k']}K）。"
        )

    if not memory_fact:
        memory_fact = "设备 CLI 已完成当前内存与进程维度取证，需结合完整输出判断 used/cache/available 关系。"

    failed_line = "无" if not failed_cmds else "；".join(failed_cmds)

    success_lines = "\n".join(success_cmds) if success_cmds else "无"

    # 保持与前面已确认的咚咚模板一致：标题/设备/告警内容/分析过程/建议。
    text = f"""NetAIOps分析结果-{now}
设备：{device_display}

告警内容：
{alert_content}

分析过程：
1. 根据告警内容初步判断：Cisco NX-OS 设备 {hostname} 的内存利用率触发异常告警，需要判断是监控口径、缓存占用、真实低可用内存、进程内存增长、表项规模增长，还是低内存故障事件。
2. 告警含义分析：设备内存持续偏高可能影响控制平面稳定性、协议进程、管理访问、日志写入、core 生成和异常情况下的故障取证；NX-OS 场景下还需要区分 used memory 与 available/cache，避免把 page cache 误判为真实故障。
3. 命令执行概况：本次共执行 {stats_total} 条只读命令，成功 {stats_success} 条，具体如下：
{success_lines}
失败 {stats_failed} 条。失败命令：{failed_line}。
4. 命令分析：本次已从 Prometheus 内存历史窗口、系统资源与当前内存、进程内存/RSS、kernel meminfo、kernel memory global、memory-alerts-log、近期日志、core/crash、process log、路由/ARP/MAC 表项规模以及 SNMP 管理面压力等维度完成自动取证。{memory_fact} {prom_text} 本 playbook 第一轮不默认展开 BGP/OSPF/ISIS 等协议专项命令；只有当进程、日志或表项规模证据指向具体协议或功能时，才进入后续专项取证。
5. 综合执行结果判断：本次内存类只读命令已完成，当前证据可用于支撑第一轮内存利用率异常判断。若 Prometheus 内存历史窗口无数据，则历史趋势判断存在边界，需要以 CLI 当前证据为主，并继续完善 memory 指标名和标签映射。当前判断范围聚焦于当前内存水位、available/cache、进程内存、kernel/RAM FS、内存告警、core/crash/restart、路由/ARP/MAC 表项规模以及 SNMP/管理面压力；如发现单进程持续增长、MALLOCFAIL/OOM/core/restart 或表项异常增长，应进入对应专项排查。

建议：
1. 优先结合 show system resources、kernel meminfo 和进程内存输出，确认是缓存/口径问题还是真实可用内存不足。
2. 检查是否存在内存告警、MALLOCFAIL、OOM、core、进程重启或 sysmgr/watchdog 相关日志。
3. 关注高内存进程、SNMP 管理面压力、路由/ARP/MAC 表项规模是否异常增长。
4. 若内存持续增长或反复触发，建议结合 Prometheus 历史趋势、设备运行时长、版本缺陷和近期变更继续复核。
"""
    return text.strip() + "\n"


def apply_memory_format_to_review(review: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(review, dict):
        return review

    if not _is_memory_obj(review):
        return review

    request_id = _safe_text(review.get("request_id")).strip()
    if not request_id:
        return review

    normalize_memory_family_in_obj(review)
    _clean_target_scope_in_review(review)

    text = build_memory_notification_text(request_id, review)
    review["notification_text"] = text
    review["message"] = text
    review["summary_text"] = text
    review["family"] = MEMORY_FAMILY_CANONICAL
    review["skill_name"] = "device_memory_utilization_high"
    review["memory_notification_formatter"] = {
        "enabled": True,
        "family_aliases": sorted(MEMORY_FAMILY_ALIASES),
        "canonical_family": MEMORY_FAMILY_CANONICAL,
    }

    eb = review.get("evidence_bundle")
    if isinstance(eb, dict):
        eb["family"] = MEMORY_FAMILY_CANONICAL
        eb["skill_name"] = "device_memory_utilization_high"
        _clean_target_scope_in_review(review)

    return review


def apply_memory_format_to_review_file(request_id: str) -> Dict[str, Any]:
    path = ROOT / f"data/reviews/alertmanager_{request_id}.review.json"
    review = _load_json(path)
    if not review:
        return {}
    review = apply_memory_format_to_review(review)
    path.write_text(json.dumps(review, ensure_ascii=False, indent=2), encoding="utf-8")
    return review


def rewrite_memory_notification_text(text: str, request_id: str | None = None) -> str:
    """
    notification_payload 层兜底：如果已有 request_id，就用标准 formatter 重建；
    没有 request_id 时，只在明显是 memory 文本时返回原文，避免误伤。
    """
    if request_id and _is_memory_text(text):
        try:
            return build_memory_notification_text(request_id)
        except Exception:
            return text
    return text


def apply_memory_format_to_payload(payload: Dict[str, Any], request_id: str | None = None) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return payload

    rid = request_id or _safe_text(payload.get("request_id")).strip()
    if not rid and _is_memory_obj(payload):
        # 没有 request_id 无法加载 execution/review 文件，只做 family alias。
        normalize_memory_family_in_obj(payload)
        return payload

    if rid:
        try:
            text = build_memory_notification_text(rid)
        except Exception:
            text = ""

        if text:
            for key in ["text", "content", "message", "notification_text", "summary_text"]:
                if key in payload:
                    payload[key] = text

            # 常见结构兜底
            if isinstance(payload.get("markdown"), dict):
                payload["markdown"]["text"] = text
            if isinstance(payload.get("body"), dict):
                for key in ["text", "content", "message"]:
                    if key in payload["body"]:
                        payload["body"][key] = text

    normalize_memory_family_in_obj(payload)
    return payload
