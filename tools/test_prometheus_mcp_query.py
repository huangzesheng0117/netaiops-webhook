#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetAIOps v8 Prometheus MCP Bridge POC 测试工具。

默认测试：
- 读取 config.yaml 中 prometheus_mcp 配置。
- MCP tools/list。
- execute_query: count(up)。
- execute_range_query: count(up)，过去 15 分钟。
- 保存完整 JSON 到 data/v8_prometheus_mcp_poc/。
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent_runner.mcp_bridge_prometheus import PrometheusBridge


def compact(obj: Any, limit: int = 2500) -> str:
    s = json.dumps(obj, ensure_ascii=False, indent=2, default=str)
    if len(s) > limit:
        return s[:limit] + "\n... <truncated> ..."
    return s


def summarize_result(name: str, result: Dict[str, Any]) -> None:
    print(f"\n========== {name} ==========")
    print("ok =", result.get("ok"))
    print("source =", result.get("source"))
    print("query_type =", result.get("query_type"))
    print("fallback_used =", result.get("fallback_used"))
    print("error =", result.get("error"))
    if result.get("mcp_error"):
        print("mcp_error =", result.get("mcp_error"))

    if result.get("source") == "prometheus_http_api":
        print("status_code =", result.get("status_code"))
        print("result_count =", result.get("result_count"))
        data = result.get("data") or {}
        prom_result = ((data.get("data") or {}).get("result")) or []
        if prom_result:
            print("first_result =", compact(prom_result[0], 1200))
    else:
        print("mcp_result =", compact(result.get("mcp_result") or result.get("result"), 2000))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--query", default="count(up)", help="instant query PromQL")
    parser.add_argument("--range-query", default="count(up)", help="range query PromQL")
    parser.add_argument("--lookback-minutes", type=int, default=15)
    parser.add_argument("--step", default="60s")
    parser.add_argument("--out-dir", default="data/v8_prometheus_mcp_poc")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    ts = time.strftime("%Y%m%d_%H%M%S")
    out_file = out_dir / f"prometheus_mcp_bridge_test_{ts}.json"

    bridge = PrometheusBridge.from_config("config.yaml")

    print("========== Prometheus MCP Bridge 配置摘要 ==========")
    print(compact(bridge.summary(), 3000))

    print("\n========== MCP tools/list ==========")
    tools_result = bridge.list_tools()
    print(compact(tools_result, 4000))

    end = int(time.time())
    start = end - args.lookback_minutes * 60

    instant = bridge.execute_query(args.query)
    range_result = bridge.execute_range_query(
        query=args.range_query,
        start=start,
        end=end,
        step=args.step,
    )

    summarize_result("Instant Query", instant)
    summarize_result("Range Query", range_result)

    output = {
        "time": ts,
        "summary": bridge.summary(),
        "tools_list": tools_result,
        "instant": instant,
        "range": range_result,
    }
    out_file.write_text(json.dumps(output, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    print("\n========== 输出文件 ==========")
    print(out_file)

    # 只要 MCP 或 fallback 有一个成功，就认为 POC 查询链路可继续推进。
    if instant.get("ok") and range_result.get("ok"):
        print("\n[OK] instant 与 range 查询均成功。")
        return 0

    print("\n[WARN] instant 或 range 查询未完全成功，请查看 error / mcp_error。")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
