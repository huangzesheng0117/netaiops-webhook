#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetAIOps webhook v8 Prometheus Evidence Formatter / Review Adapter.

职责：
- 将 prometheus_evidence_v8 输出转换为 review / 咚咚通知可直接引用的结构。
- 提供纯函数，不主动调用 Prometheus，不修改现有 review_builder / notifier 主链路。
- 后续正式接入时，可由 review_builder 或 notification_payload 调用这里的函数。
"""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any, Dict, List, Optional

from netaiops.prometheus_window_analyzer import format_number


def get_first_analysis(evidence: Dict[str, Any]) -> Dict[str, Any]:
    analysis = evidence.get("analysis") or {}
    analyses = analysis.get("analyses") or []
    if analyses and isinstance(analyses[0], dict):
        return analyses[0]
    return {}


def build_prometheus_evidence_section(evidence: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    输出统一 section，供 review_builder / notification_payload 复用。
    """
    if not evidence:
        return {
            "title": "Prometheus窗口证据",
            "available": False,
            "status": "missing",
            "text": "Prometheus窗口证据：\n- 状态：不可用\n- 原因：未传入 Prometheus evidence",
            "facts": [],
            "raw": {},
        }

    if evidence.get("summary_text"):
        text = str(evidence.get("summary_text"))
    else:
        text = render_prometheus_evidence_text(evidence)

    return {
        "title": "Prometheus窗口证据",
        "available": bool(evidence.get("ok")),
        "status": evidence.get("status") or ("success" if evidence.get("ok") else "unknown"),
        "source": evidence.get("source"),
        "fallback_used": evidence.get("fallback_used"),
        "profile": evidence.get("profile"),
        "query_name": evidence.get("query_name"),
        "selected_query": evidence.get("selected_query"),
        "text": text,
        "facts": build_prometheus_evidence_facts(evidence),
        "raw": evidence,
    }


def build_prometheus_evidence_facts(evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    将窗口统计转成结构化 facts，后续可进入 family_evidence / review_builder。
    """
    facts: List[Dict[str, Any]] = []

    if not evidence.get("ok"):
        facts.append({
            "type": "prometheus_evidence_unavailable",
            "severity": "warning",
            "status": evidence.get("status"),
            "reason": evidence.get("error") or evidence.get("status"),
            "profile": evidence.get("profile"),
            "query_name": evidence.get("query_name"),
        })
        return facts

    first = get_first_analysis(evidence)
    unit = evidence.get("unit") or ""
    window = evidence.get("query_window") or {}
    target = evidence.get("target") or {}

    facts.append({
        "type": "prometheus_window_evidence",
        "severity": "info",
        "source": evidence.get("source"),
        "fallback_used": evidence.get("fallback_used"),
        "profile": evidence.get("profile"),
        "query_name": evidence.get("query_name"),
        "direction": evidence.get("direction"),
        "unit": unit,
        "target": target,
        "lookback_minutes": window.get("lookback_minutes"),
        "compare_offset_minutes": window.get("compare_offset_minutes"),
        "step": window.get("step"),
        "current": first.get("current"),
        "offset": first.get("offset"),
        "delta": first.get("delta"),
        "change_ratio": first.get("change_ratio"),
        "window_max": first.get("window_max"),
        "window_min": first.get("window_min"),
        "window_avg": first.get("window_avg"),
        "trend_verdict": first.get("trend_verdict"),
        "selected_query": evidence.get("selected_query"),
    })

    return facts


def render_prometheus_evidence_text(evidence: Dict[str, Any]) -> str:
    """
    在 evidence 没有 summary_text 时兜底渲染。
    """
    lines: List[str] = ["Prometheus窗口证据："]

    if not evidence.get("ok"):
        lines.append("- 状态：不可用")
        lines.append(f"- Profile：{evidence.get('profile') or '-'} / {evidence.get('query_name') or '-'}")
        lines.append(f"- 原因：{evidence.get('error') or evidence.get('status') or 'unknown'}")

        candidates = evidence.get("candidates") or []
        if candidates:
            missing_items = []
            for c in candidates[:3]:
                missing = c.get("missing_variables") or []
                if missing:
                    missing_items.append("/".join(str(x) for x in missing))
            if missing_items:
                lines.append(f"- 缺少变量：{'; '.join(missing_items)}")
        return "\n".join(lines)

    first = get_first_analysis(evidence)
    unit = evidence.get("unit") or ""
    window = evidence.get("query_window") or {}
    target = evidence.get("target") or {}

    target_desc = " ".join(
        str(x) for x in [
            target.get("hostname"),
            target.get("device_ip"),
            target.get("if_name") or target.get("interface"),
        ] if x
    ) or "-"

    lines.append(f"- 数据源：{evidence.get('source') or 'prometheus'}")
    lines.append(f"- 查询对象：{target_desc}")
    lines.append(f"- 查询窗口：过去{window.get('lookback_minutes')}分钟，step={window.get('step')}")
    lines.append(f"- 当前值：{format_number(first.get('current'), unit)}")
    lines.append(f"- 对比值：{format_number(first.get('offset'), unit)}")
    lines.append(f"- 变化量：{format_number(first.get('delta'), unit)}")

    ratio = first.get("change_ratio")
    lines.append("- 变化比例：-" if ratio is None else f"- 变化比例：{ratio * 100:.2f}%")
    lines.append(f"- 窗口最大值：{format_number(first.get('window_max'), unit)}")
    lines.append(f"- 窗口最小值：{format_number(first.get('window_min'), unit)}")
    lines.append(f"- 窗口平均值：{format_number(first.get('window_avg'), unit)}")
    lines.append(f"- 趋势判断：{first.get('trend_verdict') or '-'}")
    return "\n".join(lines)


def attach_prometheus_evidence_to_review(
    review: Optional[Dict[str, Any]],
    evidence: Dict[str, Any],
) -> Dict[str, Any]:
    """
    以非侵入方式把 Prometheus evidence 附加到 review dict。

    不假设现有 review_builder 的固定结构：
    - 总是新增/覆盖 prometheus_evidence 字段。
    - 如果存在 evidence_facts，则追加 facts。
    - 如果存在 sections，则追加一个 Prometheus section。
    - 如果存在 summary_text/review_text，则追加可读文本。
    """
    result = deepcopy(review or {})
    section = build_prometheus_evidence_section(evidence)

    result["prometheus_evidence"] = {
        "available": section["available"],
        "status": section["status"],
        "source": section.get("source"),
        "fallback_used": section.get("fallback_used"),
        "profile": section.get("profile"),
        "query_name": section.get("query_name"),
        "selected_query": section.get("selected_query"),
        "text": section.get("text"),
    }

    existing_facts = result.get("evidence_facts")
    if isinstance(existing_facts, list):
        existing_facts.extend(section["facts"])
    else:
        result["evidence_facts"] = section["facts"]

    existing_sections = result.get("sections")
    section_item = {
        "title": section["title"],
        "type": "prometheus_evidence",
        "available": section["available"],
        "text": section["text"],
    }
    if isinstance(existing_sections, list):
        existing_sections.append(section_item)
    else:
        result["sections"] = [section_item]

    for text_key in ["summary_text", "review_text"]:
        if isinstance(result.get(text_key), str) and result[text_key].strip():
            if "Prometheus窗口证据" not in result[text_key]:
                result[text_key] = result[text_key].rstrip() + "\n\n" + section["text"]
            break
    else:
        result["summary_text"] = section["text"]

    return result


def attach_prometheus_evidence_to_notification_payload(
    payload: Optional[Dict[str, Any]],
    evidence: Dict[str, Any],
) -> Dict[str, Any]:
    """
    以非侵入方式把 Prometheus evidence 附加到通知 payload。
    后续可在 notification_payload.py 中调用。
    """
    result = deepcopy(payload or {})
    section = build_prometheus_evidence_section(evidence)

    result["prometheus_evidence"] = {
        "available": section["available"],
        "status": section["status"],
        "source": section.get("source"),
        "fallback_used": section.get("fallback_used"),
        "profile": section.get("profile"),
        "query_name": section.get("query_name"),
        "selected_query": section.get("selected_query"),
    }

    for key in ["markdown", "text", "content", "message", "body"]:
        if isinstance(result.get(key), str) and result[key].strip():
            if "Prometheus窗口证据" not in result[key]:
                result[key] = result[key].rstrip() + "\n\n" + section["text"]
            break
    else:
        result["text"] = section["text"]

    return result


if __name__ == "__main__":
    demo = {
        "ok": False,
        "status": "demo",
        "profile": "demo",
        "query_name": "demo",
        "error": "demo error",
    }
    print(json.dumps(build_prometheus_evidence_section(demo), ensure_ascii=False, indent=2))
