#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetAIOps webhook v8 Prometheus review hooks.

职责：
- 从 plan_data.prometheus_evidence_runtime 读取 Prometheus runtime sidecar 摘要。
- 将 Prometheus窗口证据 附加到 review dict。
- 不主动查询 Prometheus，不修改设备，不发送通知。
- runtime_disabled 不展示，避免配置开关关闭时污染 review。
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Optional

from netaiops.prometheus_notification_hooks import build_prometheus_runtime_payload


def attach_prometheus_runtime_to_review(
    review: Optional[Dict[str, Any]],
    plan_data: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    result = deepcopy(review or {})
    prom = build_prometheus_runtime_payload(plan_data or {})

    result["prometheus_evidence"] = prom

    if not prom.get("visible"):
        return result

    prom_text = str(prom.get("text") or "").strip()
    if not prom_text:
        return result

    # 结构化 facts，便于后续复盘/查询。
    facts = result.get("evidence_facts")
    if not isinstance(facts, list):
        facts = []

    facts.append({
        "type": "prometheus_window_evidence",
        "source": "prometheus_mcp",
        "status": prom.get("status"),
        "available": prom.get("available"),
        "profile": prom.get("profile"),
        "query_names": prom.get("query_names") or [],
        "ok_count": prom.get("ok_count"),
        "failed_count": prom.get("failed_count"),
        "evidence_file": prom.get("evidence_file"),
        "elapsed_ms": prom.get("elapsed_ms"),
    })
    result["evidence_facts"] = facts

    # sections 结构，适配可能存在的 review 结构。
    sections = result.get("sections")
    if not isinstance(sections, list):
        sections = []

    if not any(isinstance(x, dict) and x.get("type") == "prometheus_evidence" for x in sections):
        sections.append({
            "title": "Prometheus窗口证据",
            "type": "prometheus_evidence",
            "available": prom.get("available"),
            "text": prom_text,
        })
    result["sections"] = sections

    # 文本字段，尽量非侵入追加。
    for key in ["summary_text", "review_text", "text", "content"]:
        value = result.get(key)
        if isinstance(value, str) and value.strip():
            if "Prometheus窗口证据" not in value:
                result[key] = value.rstrip() + "\n\n" + prom_text
            break
    else:
        result["summary_text"] = prom_text

    return result


def summarize_review_prometheus(review: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    prom = ((review or {}).get("prometheus_evidence") or {})
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
        "has_text": bool(str(prom.get("text") or "").strip()),
    }
