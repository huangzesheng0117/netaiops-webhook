#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetAIOps webhook v8 Prometheus notification hooks.

职责：
- 从 plan_data.prometheus_evidence_runtime 读取 Prometheus runtime sidecar 摘要。
- 将 Prometheus窗口证据 注入 notification payload。
- 将 Prometheus窗口证据 追加到最终咚咚通知文本。
- 不主动查询 Prometheus，不修改 plan/review/execution 文件。

安全策略：
- runtime_disabled 不展示，避免开关关闭时污染所有通知。
- 没有 runtime 证据不展示。
- 已经包含 Prometheus窗口证据 时不重复追加。
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Optional


HIDDEN_STATUSES = {
    "",
    "runtime_disabled",
    "not_configured",
}


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def should_show_prometheus_runtime(runtime: Optional[Dict[str, Any]]) -> bool:
    if not isinstance(runtime, dict) or not runtime:
        return False

    status = safe_text(runtime.get("status"))
    if status in HIDDEN_STATUSES:
        return False

    text = safe_text(runtime.get("summary_text"))
    if not text:
        return False

    if "Prometheus窗口证据" not in text:
        return False

    return True


def build_prometheus_runtime_payload(plan_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    plan_data = plan_data or {}
    runtime = plan_data.get("prometheus_evidence_runtime") or {}

    if not should_show_prometheus_runtime(runtime):
        return {
            "available": False,
            "visible": False,
            "status": safe_text(runtime.get("status")) if isinstance(runtime, dict) else "",
            "text": "",
        }

    return {
        "available": bool(runtime.get("ok")),
        "visible": True,
        "status": safe_text(runtime.get("status")),
        "profile": safe_text(runtime.get("profile")),
        "query_names": runtime.get("query_names") or [],
        "total_count": runtime.get("total_count"),
        "ok_count": runtime.get("ok_count"),
        "failed_count": runtime.get("failed_count"),
        "evidence_file": safe_text(runtime.get("evidence_file")),
        "created_at": safe_text(runtime.get("created_at")),
        "elapsed_ms": runtime.get("elapsed_ms"),
        "text": safe_text(runtime.get("summary_text")),
    }


def attach_prometheus_runtime_to_payload(
    payload: Optional[Dict[str, Any]],
    plan_data: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    result = deepcopy(payload or {})
    prom = build_prometheus_runtime_payload(plan_data)
    result["prometheus_evidence"] = prom

    if not prom.get("visible"):
        return result

    notify_view = result.get("notify_view")
    if not isinstance(notify_view, dict):
        notify_view = {}

    notify_view["prometheus_evidence_text"] = prom.get("text") or ""

    # 给后续模板留结构化字段；不直接拼进 analysis_process，避免和 build_notification_text 双重追加。
    result["notify_view"] = notify_view
    return result


def append_prometheus_runtime_to_text(text: str, payload: Optional[Dict[str, Any]]) -> str:
    base = safe_text(text)
    payload = payload or {}
    prom = payload.get("prometheus_evidence") or {}

    if not isinstance(prom, dict) or not prom.get("visible"):
        return base

    prom_text = safe_text(prom.get("text"))
    if not prom_text:
        return base

    if "Prometheus窗口证据" in base:
        return base

    # 优先插入到“建议：”之前；如果模板结构变化，则追加到末尾。
    marker = "\n建议："
    if marker in base:
        return base.replace(marker, "\n\n" + prom_text + marker, 1)

    return base.rstrip() + "\n\n" + prom_text


def summarize_payload_prometheus(payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    prom = ((payload or {}).get("prometheus_evidence") or {})
    if not isinstance(prom, dict):
        return {
            "visible": False,
            "status": "",
        }

    return {
        "visible": bool(prom.get("visible")),
        "available": bool(prom.get("available")),
        "status": prom.get("status"),
        "profile": prom.get("profile"),
        "query_names": prom.get("query_names") or [],
        "ok_count": prom.get("ok_count"),
        "failed_count": prom.get("failed_count"),
        "has_text": bool(safe_text(prom.get("text"))),
    }

# ===== v8 prometheus notification spacing override begin =====
# Batch24：控制 Prometheus窗口证据插入位置的空行。
def append_prometheus_runtime_to_text(text: str, payload: Optional[Dict[str, Any]]) -> str:
    base = safe_text(text)
    payload = payload or {}
    prom = payload.get("prometheus_evidence") or {}

    if not isinstance(prom, dict) or not prom.get("visible"):
        return base

    prom_text = safe_text(prom.get("text"))
    if not prom_text:
        return base

    if "Prometheus窗口证据" in base:
        return base

    marker = "\n建议："
    if marker in base:
        # 原始正文通常是“分析过程...\n\n建议：”，marker 匹配第二个换行。
        # 这里补一个换行，形成：
        # 分析过程...
        #
        # Prometheus窗口证据...
        #
        # 建议：
        return base.replace(marker, "\n" + prom_text.rstrip() + "\n" + marker, 1)

    return base.rstrip() + "\n\n" + prom_text.rstrip()
# ===== v8 prometheus notification spacing override end =====
