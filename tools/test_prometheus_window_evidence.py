#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetAIOps v8 Prometheus window evidence POC.

默认动作：
- 读取 config/prometheus_metrics.yaml 的 poc_count_up/current。
- 通过 Prometheus MCP 执行 query_range。
- 使用 prometheus_window_analyzer 做窗口统计。
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent_runner.mcp_bridge_prometheus import PrometheusBridge
from netaiops.prometheus_metric_mapping import PrometheusMetricMapping, normalize_context
from netaiops.prometheus_window_analyzer import analyze_window


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default="poc_count_up")
    parser.add_argument("--query-name", default="current")
    parser.add_argument("--device-ip", default="")
    parser.add_argument("--if-name", default="")
    parser.add_argument("--lookback-minutes", type=int, default=15)
    parser.add_argument("--compare-offset-minutes", type=int, default=5)
    parser.add_argument("--step", default="60s")
    parser.add_argument("--out-dir", default="data/v8_prometheus_mcp_poc")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    ctx = normalize_context({
        "device_ip": args.device_ip,
        "if_name": args.if_name,
    })

    mapping = PrometheusMetricMapping("config/prometheus_metrics.yaml")
    candidates = mapping.render_candidates(args.profile, args.query_name, ctx)

    print("========== Mapping ==========")
    print("profiles =", mapping.list_profiles())
    print("profile =", args.profile)
    print("query_name =", args.query_name)
    print("context =", json.dumps(ctx, ensure_ascii=False))
    print("candidates =", json.dumps(candidates, ensure_ascii=False, indent=2))

    usable = [c for c in candidates if not c.get("missing_variables")]
    if not usable:
        print("[ERROR] 没有可执行 PromQL，缺少变量：")
        for c in candidates:
            print(c.get("promql"), "missing=", c.get("missing_variables"))
        return 2

    query = usable[0]["promql"]
    unit = usable[0].get("unit") or ""

    end = int(time.time())
    start = end - args.lookback_minutes * 60

    print("\n========== Query ==========")
    print("query =", query)
    print("start =", start)
    print("end =", end)
    print("step =", args.step)

    bridge = PrometheusBridge.from_config("config.yaml")
    result = bridge.execute_range_query(query=query, start=start, end=end, step=args.step)

    print("\n========== Bridge Result ==========")
    print("ok =", result.get("ok"))
    print("source =", result.get("source"))
    print("fallback_used =", result.get("fallback_used"))
    print("error =", result.get("error"))
    if result.get("mcp_error"):
        print("mcp_error =", result.get("mcp_error"))

    analysis = analyze_window(
        result,
        compare_offset_minutes=args.compare_offset_minutes,
    )

    print("\n========== Window Analysis ==========")
    print(json.dumps(analysis, ensure_ascii=False, indent=2))

    ts = time.strftime("%Y%m%d_%H%M%S")
    out_file = out_dir / f"prometheus_window_evidence_{args.profile}_{args.query_name}_{ts}.json"
    out_file.write_text(json.dumps({
        "profile": args.profile,
        "query_name": args.query_name,
        "context": ctx,
        "query": query,
        "unit": unit,
        "bridge_result": result,
        "analysis": analysis,
    }, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    print("\n========== 输出文件 ==========")
    print(out_file)

    if result.get("ok") and analysis.get("ok"):
        print("\n[OK] Prometheus 窗口证据 POC 成功。")
        return 0

    print("\n[WARN] Prometheus 窗口证据 POC 未完全成功。")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
