#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试 Prometheus Evidence Formatter / Review Adapter。
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
from netaiops.prometheus_evidence_formatter import (
    attach_prometheus_evidence_to_notification_payload,
    attach_prometheus_evidence_to_review,
    build_prometheus_evidence_section,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default="poc_count_up")
    parser.add_argument("--query-name", default="current")
    parser.add_argument("--lookback-minutes", type=int, default=15)
    parser.add_argument("--compare-offset-minutes", type=int, default=5)
    parser.add_argument("--step", default="60s")
    parser.add_argument("--out-dir", default="data/v8_prometheus_mcp_poc")
    args = parser.parse_args()

    evidence = collect_prometheus_evidence(
        profile=args.profile,
        query_name=args.query_name,
        target={},
        lookback_minutes=args.lookback_minutes,
        compare_offset_minutes=args.compare_offset_minutes,
        step=args.step,
    )

    section = build_prometheus_evidence_section(evidence)

    fake_review = {
        "request_id": "demo-request",
        "summary_text": "原始复核结论：这里是已有 CLI 取证与 LLM 分析。",
        "evidence_facts": [
            {
                "type": "cli_fact",
                "severity": "info",
                "message": "示例 CLI 事实",
            }
        ],
        "sections": [
            {
                "title": "设备侧取证",
                "text": "这里是设备 show 命令取证摘要。",
            }
        ],
    }

    fake_notification = {
        "title": "NetAIOps分析结果-demo",
        "text": "原始咚咚通知正文。",
    }

    merged_review = attach_prometheus_evidence_to_review(fake_review, evidence)
    merged_notification = attach_prometheus_evidence_to_notification_payload(fake_notification, evidence)

    print("========== Evidence Section ==========")
    print(json.dumps({
        "available": section.get("available"),
        "status": section.get("status"),
        "source": section.get("source"),
        "fallback_used": section.get("fallback_used"),
        "profile": section.get("profile"),
        "query_name": section.get("query_name"),
        "selected_query": section.get("selected_query"),
        "facts_count": len(section.get("facts") or []),
        "text": section.get("text"),
    }, ensure_ascii=False, indent=2))

    print("\n========== Merged Review 摘要 ==========")
    print("prometheus_evidence =", json.dumps(merged_review.get("prometheus_evidence"), ensure_ascii=False, indent=2))
    print("evidence_facts_count =", len(merged_review.get("evidence_facts") or []))
    print("sections_count =", len(merged_review.get("sections") or []))
    print("summary_text =")
    print(merged_review.get("summary_text"))

    print("\n========== Merged Notification 摘要 ==========")
    print("prometheus_evidence =", json.dumps(merged_notification.get("prometheus_evidence"), ensure_ascii=False, indent=2))
    print("text =")
    print(merged_notification.get("text"))

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_file = out_dir / f"prometheus_evidence_formatter_{args.profile}_{args.query_name}_{ts}.json"
    out_file.write_text(json.dumps({
        "evidence": evidence,
        "section": section,
        "merged_review": merged_review,
        "merged_notification": merged_notification,
    }, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    print("\n========== 输出文件 ==========")
    print(out_file)

    if section.get("text") and "Prometheus窗口证据" in section.get("text"):
        print("\n[OK] Formatter / Review Adapter POC 成功。")
        return 0

    print("\n[WARN] Formatter / Review Adapter POC 未成功。")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
