#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetAIOps v8 Prometheus window analyzer.

职责：
- 解析 Prometheus MCP / HTTP API 的 instant 或 range 返回。
- 对 query_range 的 matrix values 做窗口统计。
- 输出 current、offset、delta、change_ratio、max/min/avg、trend_verdict。
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from statistics import mean
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class SamplePoint:
    ts: float
    value: float


def extract_structured_payload(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    支持两类输入：
    1. PrometheusBridge 返回的 source=prometheus_mcp，数据在 mcp_result.structuredContent。
    2. PrometheusBridge fallback HTTP 返回的 source=prometheus_http_api，数据在 data.data。
    """
    if not isinstance(result, dict):
        return {}

    if result.get("source") == "prometheus_mcp":
        mcp = result.get("mcp_result") or result.get("result") or {}
        if isinstance(mcp, dict) and isinstance(mcp.get("structuredContent"), dict):
            return mcp["structuredContent"]

        # 兼容只有 content.text 的 MCP 返回。
        content = mcp.get("content") if isinstance(mcp, dict) else None
        if content and isinstance(content, list):
            first = content[0]
            if isinstance(first, dict) and first.get("text"):
                try:
                    return json.loads(first["text"])
                except Exception:
                    return {}

    data = result.get("data")
    if isinstance(data, dict):
        inner = data.get("data")
        if isinstance(inner, dict):
            return inner

    return {}


def extract_series(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    payload = extract_structured_payload(result)
    raw_result = payload.get("result") or []

    series_list: List[Dict[str, Any]] = []
    for item in raw_result:
        metric = item.get("metric") or {}

        if "values" in item:
            points = []
            for pair in item.get("values") or []:
                p = parse_point(pair)
                if p is not None:
                    points.append(p)
            series_list.append({
                "metric": metric,
                "points": points,
                "type": "matrix",
            })

        elif "value" in item:
            p = parse_point(item.get("value"))
            series_list.append({
                "metric": metric,
                "points": [p] if p is not None else [],
                "type": "vector",
            })

    return series_list


def parse_point(pair: Any) -> Optional[SamplePoint]:
    if not isinstance(pair, (list, tuple)) or len(pair) < 2:
        return None
    try:
        ts = float(pair[0])
        val = float(pair[1])
        if math.isnan(val) or math.isinf(val):
            return None
        return SamplePoint(ts=ts, value=val)
    except Exception:
        return None


def analyze_window(
    result: Dict[str, Any],
    compare_offset_minutes: int = 5,
    high_change_ratio: float = 0.5,
    low_change_ratio: float = -0.5,
) -> Dict[str, Any]:
    series_list = extract_series(result)

    analyses: List[Dict[str, Any]] = []
    for series in series_list:
        points: List[SamplePoint] = sorted(series.get("points") or [], key=lambda x: x.ts)
        metric = series.get("metric") or {}

        if not points:
            analyses.append({
                "metric": metric,
                "ok": False,
                "error": "no_points",
            })
            continue

        current = points[-1]
        offset_target_ts = current.ts - compare_offset_minutes * 60
        offset = nearest_point(points, offset_target_ts)

        values = [p.value for p in points]
        delta = current.value - offset.value if offset else None
        change_ratio = safe_ratio(delta, offset.value) if offset and delta is not None else None

        verdict = build_trend_verdict(
            point_count=len(points),
            current=current.value,
            offset=offset.value if offset else None,
            change_ratio=change_ratio,
            high_change_ratio=high_change_ratio,
            low_change_ratio=low_change_ratio,
        )

        analyses.append({
            "metric": metric,
            "ok": True,
            "point_count": len(points),
            "start_ts": points[0].ts,
            "end_ts": current.ts,
            "current": current.value,
            "current_ts": current.ts,
            "offset_minutes": compare_offset_minutes,
            "offset": offset.value if offset else None,
            "offset_ts": offset.ts if offset else None,
            "delta": delta,
            "change_ratio": change_ratio,
            "window_max": max(values),
            "window_min": min(values),
            "window_avg": mean(values),
            "trend_verdict": verdict,
        })

    return {
        "ok": bool(analyses) and any(a.get("ok") for a in analyses),
        "series_count": len(series_list),
        "analyses": analyses,
    }


def nearest_point(points: List[SamplePoint], target_ts: float) -> Optional[SamplePoint]:
    if not points:
        return None
    return min(points, key=lambda p: abs(p.ts - target_ts))


def safe_ratio(delta: Optional[float], base: Optional[float]) -> Optional[float]:
    if delta is None or base is None:
        return None
    if abs(base) < 1e-12:
        return None
    return delta / base


def build_trend_verdict(
    point_count: int,
    current: float,
    offset: Optional[float],
    change_ratio: Optional[float],
    high_change_ratio: float,
    low_change_ratio: float,
) -> str:
    if point_count < 2:
        return "数据点不足"
    if offset is None or change_ratio is None:
        return "可统计但缺少有效对比基线"

    if change_ratio >= high_change_ratio:
        return "明显上升"
    if change_ratio <= low_change_ratio:
        return "明显下降"
    if current == offset:
        return "基本持平"
    return "小幅波动"


def format_number(value: Optional[float], unit: str = "") -> str:
    if value is None:
        return "-"
    if unit == "bps":
        abs_v = abs(value)
        if abs_v >= 1_000_000_000:
            return f"{value / 1_000_000_000:.2f} Gbps"
        if abs_v >= 1_000_000:
            return f"{value / 1_000_000:.2f} Mbps"
        if abs_v >= 1_000:
            return f"{value / 1_000:.2f} Kbps"
        return f"{value:.2f} bps"
    if unit:
        return f"{value:.2f} {unit}"
    return f"{value:.2f}"


if __name__ == "__main__":
    print("prometheus_window_analyzer module loaded")
