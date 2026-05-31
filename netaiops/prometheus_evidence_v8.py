#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetAIOps webhook v8 Prometheus Evidence 统一入口。

职责：
- 根据 profile/query_name/target 从 config/prometheus_metrics.yaml 渲染 PromQL。
- 优先通过 Prometheus MCP 执行 query_range。
- 调用 prometheus_window_analyzer 生成窗口统计。
- 输出统一结构，后续可接入 review_builder / notification_payload。

注意：
- 本模块只做只读指标查询。
- 不修改 Prometheus/Victoria/Grafana/设备配置。
- v8 初期先作为旁路 POC，不直接接入生产主链路。
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from agent_runner.mcp_bridge_prometheus import PrometheusBridge
from netaiops.prometheus_metric_mapping import PrometheusMetricMapping, normalize_context
from netaiops.prometheus_window_analyzer import analyze_window, format_number


def ts_to_iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except Exception:
        return None


def build_query_window(
    lookback_minutes: int,
    end_ts: Optional[float] = None,
) -> Dict[str, Any]:
    end = float(end_ts or int(time.time()))
    start = end - int(lookback_minutes) * 60
    return {
        "start": start,
        "end": end,
        "start_iso_utc": ts_to_iso(start),
        "end_iso_utc": ts_to_iso(end),
    }


def collect_prometheus_evidence(
    profile: str,
    query_name: str,
    target: Optional[Dict[str, Any]] = None,
    *,
    mapping_path: str = "config/prometheus_metrics.yaml",
    config_path: str = "config.yaml",
    lookback_minutes: Optional[int] = None,
    compare_offset_minutes: Optional[int] = None,
    step: Optional[str] = None,
    end_ts: Optional[float] = None,
    max_candidates_per_query: Optional[int] = None,
) -> Dict[str, Any]:
    """
    统一 Prometheus Evidence 查询入口。

    返回结构重点字段：
    - ok: 是否成功拿到并解析出窗口证据
    - status: success / no_usable_query / no_data / query_failed
    - selected_query: 实际采用的 PromQL
    - analysis: window_analyzer 输出
    - attempts: 所有候选 PromQL 尝试记录
    """
    started = time.time()
    target_ctx = normalize_context(target or {})

    mapping = PrometheusMetricMapping(mapping_path)
    defaults = mapping.defaults or {}

    lookback = int(lookback_minutes or defaults.get("lookback_minutes") or 15)
    compare_offset = int(compare_offset_minutes or defaults.get("compare_offset_minutes") or 5)
    step_value = str(step or f"{int(defaults.get('step_seconds') or 60)}s")
    max_candidates = int(max_candidates_per_query or defaults.get("max_candidates_per_query") or 0)

    window = build_query_window(lookback_minutes=lookback, end_ts=end_ts)

    try:
        candidates = mapping.render_candidates(profile, query_name, target_ctx)
    except Exception as e:
        return {
            "ok": False,
            "status": "mapping_error",
            "profile": profile,
            "query_name": query_name,
            "target": target_ctx,
            "error": f"{type(e).__name__}: {e}",
            "elapsed_ms": int((time.time() - started) * 1000),
        }

    usable = [c for c in candidates if not c.get("missing_variables")]
    if max_candidates > 0:
        usable = usable[:max_candidates]
    if not usable:
        evidence = {
            "ok": False,
            "status": "no_usable_query",
            "profile": profile,
            "query_name": query_name,
            "target": target_ctx,
            "query_window": {
                **window,
                "lookback_minutes": lookback,
                "compare_offset_minutes": compare_offset,
                "step": step_value,
            },
            "candidates": candidates,
            "attempts": [],
            "error": "all candidate PromQL templates have missing variables",
            "elapsed_ms": int((time.time() - started) * 1000),
        }
        evidence["summary_text"] = format_prometheus_evidence_text(evidence)
        return evidence

    bridge = PrometheusBridge.from_config(config_path)
    attempts: List[Dict[str, Any]] = []

    for candidate in usable:
        promql = candidate["promql"]

        bridge_result = bridge.execute_range_query(
            query=promql,
            start=window["start"],
            end=window["end"],
            step=step_value,
        )

        analysis = analyze_window(
            bridge_result,
            compare_offset_minutes=compare_offset,
        )

        attempt = {
            "candidate_index": candidate.get("index"),
            "query_name": candidate.get("query_name"),
            "promql": promql,
            "unit": candidate.get("unit"),
            "direction": candidate.get("direction"),
            "bridge_ok": bridge_result.get("ok"),
            "bridge_source": bridge_result.get("source"),
            "fallback_used": bridge_result.get("fallback_used"),
            "bridge_error": bridge_result.get("error"),
            "mcp_error": bridge_result.get("mcp_error"),
            "analysis_ok": analysis.get("ok"),
            "series_count": analysis.get("series_count"),
            "analysis": analysis,
        }
        attempts.append(attempt)

        if bridge_result.get("ok") and analysis.get("ok"):
            evidence = {
                "ok": True,
                "status": "success",
                "source": bridge_result.get("source"),
                "backend": bridge_result.get("backend"),
                "fallback_used": bridge_result.get("fallback_used"),
                "profile": profile,
                "query_name": query_name,
                "unit": candidate.get("unit"),
                "direction": candidate.get("direction"),
                "target": target_ctx,
                "query_window": {
                    **window,
                    "lookback_minutes": lookback,
                    "compare_offset_minutes": compare_offset,
                    "step": step_value,
                },
                "selected_query": promql,
                "selected_candidate_index": candidate.get("index"),
                "analysis": analysis,
                "attempts": attempts,
                "elapsed_ms": int((time.time() - started) * 1000),
            }
            evidence["summary_text"] = format_prometheus_evidence_text(evidence)
            return evidence

    evidence = {
        "ok": False,
        "status": "no_data_or_query_failed",
        "profile": profile,
        "query_name": query_name,
        "target": target_ctx,
        "query_window": {
            **window,
            "lookback_minutes": lookback,
            "compare_offset_minutes": compare_offset,
            "step": step_value,
        },
        "candidates": candidates,
        "attempts": attempts,
        "error": "all usable PromQL candidates failed or returned no analyzable series",
        "elapsed_ms": int((time.time() - started) * 1000),
    }
    evidence["summary_text"] = format_prometheus_evidence_text(evidence)
    return evidence


def format_prometheus_evidence_text(evidence: Dict[str, Any]) -> str:
    """
    生成可放入 review / 咚咚通知的简短文本。
    这里只做通用格式，后续 notification_payload 可按告警类型再做美化。
    """
    lines: List[str] = []
    lines.append("Prometheus窗口证据：")

    if not evidence.get("ok"):
        lines.append("- 状态：不可用")
        lines.append(f"- 原因：{evidence.get('status') or evidence.get('error') or 'unknown'}")
        attempts = evidence.get("attempts") or []
        if attempts:
            last = attempts[-1]
            if last.get("bridge_error"):
                lines.append(f"- 查询错误：{last.get('bridge_error')}")
            if last.get("mcp_error"):
                lines.append(f"- MCP错误：{last.get('mcp_error')}")
        return "\n".join(lines)

    target = evidence.get("target") or {}
    window = evidence.get("query_window") or {}
    analysis = evidence.get("analysis") or {}
    analyses = analysis.get("analyses") or []
    first = analyses[0] if analyses else {}

    unit = evidence.get("unit") or ""
    source = evidence.get("source") or "prometheus"
    fallback = evidence.get("fallback_used")

    target_desc = " ".join(
        str(x) for x in [
            target.get("hostname"),
            target.get("device_ip"),
            target.get("if_name") or target.get("interface"),
        ] if x
    ) or "-"

    lines.append(f"- 数据源：{source}" + ("，HTTP fallback" if fallback else ""))
    lines.append(f"- 查询对象：{target_desc}")
    lines.append(
        f"- 查询窗口：过去{window.get('lookback_minutes')}分钟，"
        f"step={window.get('step')}，对比偏移={window.get('compare_offset_minutes')}分钟"
    )
    lines.append(f"- 当前值：{format_number(first.get('current'), unit)}")
    lines.append(f"- 对比值：{format_number(first.get('offset'), unit)}")
    lines.append(f"- 变化量：{format_number(first.get('delta'), unit)}")

    ratio = first.get("change_ratio")
    if ratio is None:
        lines.append("- 变化比例：-")
    else:
        lines.append(f"- 变化比例：{ratio * 100:.2f}%")

    lines.append(f"- 窗口最大值：{format_number(first.get('window_max'), unit)}")
    lines.append(f"- 窗口最小值：{format_number(first.get('window_min'), unit)}")
    lines.append(f"- 窗口平均值：{format_number(first.get('window_avg'), unit)}")
    lines.append(f"- 趋势判断：{first.get('trend_verdict') or '-'}")

    return "\n".join(lines)


if __name__ == "__main__":
    result = collect_prometheus_evidence(
        profile="poc_count_up",
        query_name="current",
        target={},
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
