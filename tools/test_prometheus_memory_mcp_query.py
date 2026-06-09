#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import argparse
import json
import re
from typing import Any, Dict, List

import yaml

from agent_runner.mcp_bridge_prometheus import PrometheusBridge
from netaiops.prometheus_metric_mapping import PrometheusMetricMapping


def compact(obj: Any, limit: int = 2600) -> str:
    text = json.dumps(obj, ensure_ascii=False, indent=2, default=str)
    if len(text) > limit:
        return text[:limit] + "\n...<truncated>"
    return text


def result_series_count(result: Dict[str, Any]) -> int:
    text = json.dumps(result, ensure_ascii=False, default=str)

    # 常见 Prometheus API 结构
    try:
        data = result.get("result", {}).get("data", {}).get("result", [])
        if isinstance(data, list):
            return len(data)
    except Exception:
        pass

    try:
        data = result.get("data", {}).get("result", [])
        if isinstance(data, list):
            return len(data)
    except Exception:
        pass

    # MCP 文本返回兜底：只要里面有 resultType/result/value，一般说明有实际返回。
    if '"resultType"' in text and '"result"' in text and '"value"' in text:
        if re.search(r'"result"\s*:\s*\[\s*\]', text):
            return 0
        return 1

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Test device_memory_usage Prometheus candidates through existing PrometheusBridge.")
    parser.add_argument("--device-ip", default="10.187.251.107")
    parser.add_argument("--hostname", default="SH16-G03-DCI-BN-ACC-SW01")
    parser.add_argument("--max-candidates", type=int, default=20)
    args = parser.parse_args()

    print("========== Prometheus Memory MCP Query Test ==========")
    print("device_ip =", args.device_ip)
    print("hostname  =", args.hostname)

    mapping = PrometheusMetricMapping("config/prometheus_metrics.yaml")
    ctx = {
        "device_ip": args.device_ip,
        "ip": args.device_ip,
        "instance": args.device_ip,
        "hostname": args.hostname,
        "sysName": args.hostname,
    }

    candidates = mapping.render_candidates("device_memory_usage", "memory_usage_percent", ctx)
    print("candidate_count =", len(candidates))

    for i, c in enumerate(candidates[: args.max_candidates], 1):
        print(f"\n--- candidate {i} ---")
        print("promql =", c.get("promql"))
        print("missing_variables =", c.get("missing_variables"))

    bridge = PrometheusBridge.from_config()
    print("\nbridge_summary =")
    print(compact(bridge.summary(), 2000))

    print("\n========== Basic query ==========")
    for q in [
        "count(up)",
        f'count(up{{ip="{args.device_ip}"}})',
        f'count(up{{instance="{args.device_ip}"}})',
        f'count(up{{instance=~"{args.device_ip}(:.*)?"}})',
        f'count(cseSysMemoryUtilization)',
        f'count(cseSysMemoryUtilization{{ip="{args.device_ip}"}})',
        f'count(cpmCPUMemoryUsed{{ip="{args.device_ip}"}})',
        f'count(cpmCPUMemoryFree{{ip="{args.device_ip}"}})',
    ]:
        print(f"\nquery = {q}")
        r = bridge.execute_query(q)
        print(compact(r, 1800))

    print("\n========== Candidate query test ==========")
    success = []
    failed = []

    for i, c in enumerate(candidates[: args.max_candidates], 1):
        q = c.get("promql")
        if not q or c.get("missing_variables"):
            failed.append((i, q, "missing_variables"))
            continue

        print(f"\n--- candidate {i} query ---")
        print(q)
        try:
            r = bridge.execute_query(q)
            cnt = result_series_count(r)
            print("series_count =", cnt)
            print(compact(r, 2200))
            if cnt > 0:
                success.append((i, q, cnt))
            else:
                failed.append((i, q, "no_series"))
        except Exception as e:
            print("ERROR =", repr(e))
            failed.append((i, q, repr(e)))

    print("\n========== Summary ==========")
    print("success_count =", len(success))
    for i, q, cnt in success:
        print(f"[OK] candidate {i} series_count={cnt} promql={q}")

    print("failed_count =", len(failed))
    for i, q, reason in failed[:10]:
        print(f"[MISS] candidate {i} reason={reason} promql={q}")

    if not success:
        print("[ERROR] No memory candidate returned data.")
        return 2

    print("[OK] At least one memory candidate returned data.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
