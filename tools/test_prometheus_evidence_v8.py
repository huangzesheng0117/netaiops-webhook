#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetAIOps webhook v8 Prometheus Evidence 统一入口测试工具。
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netaiops.prometheus_evidence_v8 import collect_prometheus_evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default="poc_count_up")
    parser.add_argument("--query-name", default="current")
    parser.add_argument("--device-ip", default="")
    parser.add_argument("--hostname", default="")
    parser.add_argument("--if-name", default="")
    parser.add_argument("--lookback-minutes", type=int, default=15)
    parser.add_argument("--compare-offset-minutes", type=int, default=5)
    parser.add_argument("--step", default="60s")
    parser.add_argument("--out-dir", default="data/v8_prometheus_mcp_poc")
    args = parser.parse_args()

    target = {
        "device_ip": args.device_ip,
        "hostname": args.hostname,
        "if_name": args.if_name,
    }

    evidence = collect_prometheus_evidence(
        profile=args.profile,
        query_name=args.query_name,
        target=target,
        lookback_minutes=args.lookback_minutes,
        compare_offset_minutes=args.compare_offset_minutes,
        step=args.step,
    )

    print("========== Evidence Result ==========")
    print("ok =", evidence.get("ok"))
    print("status =", evidence.get("status"))
    print("source =", evidence.get("source"))
    print("fallback_used =", evidence.get("fallback_used"))
    print("profile =", evidence.get("profile"))
    print("query_name =", evidence.get("query_name"))
    print("selected_query =", evidence.get("selected_query"))
    print("elapsed_ms =", evidence.get("elapsed_ms"))
    print("error =", evidence.get("error"))

    print("\n========== Summary Text ==========")
    print(evidence.get("summary_text") or "")

    print("\n========== Attempts 摘要 ==========")
    for idx, item in enumerate(evidence.get("attempts") or [], 1):
        print(f"--- attempt {idx} ---")
        print("promql =", item.get("promql"))
        print("bridge_ok =", item.get("bridge_ok"))
        print("bridge_source =", item.get("bridge_source"))
        print("fallback_used =", item.get("fallback_used"))
        print("bridge_error =", item.get("bridge_error"))
        print("mcp_error =", item.get("mcp_error"))
        print("analysis_ok =", item.get("analysis_ok"))
        print("series_count =", item.get("series_count"))

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_file = out_dir / f"prometheus_evidence_v8_{args.profile}_{args.query_name}_{ts}.json"
    out_file.write_text(json.dumps(evidence, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    print("\n========== 输出文件 ==========")
    print(out_file)

    if evidence.get("ok"):
        print("\n[OK] Prometheus Evidence v8 POC 成功。")
        return 0

    print("\n[WARN] Prometheus Evidence v8 POC 未成功，请查看 status/error/attempts。")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
