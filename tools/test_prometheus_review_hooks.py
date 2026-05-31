#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netaiops.prometheus_review_hooks import (
    attach_prometheus_runtime_to_review,
    summarize_review_prometheus,
)


def main() -> int:
    fake_review = {
        "request_id": "demo",
        "summary_text": "原始 Review：CLI 取证完成。",
        "evidence_facts": [
            {
                "type": "cli_fact",
                "message": "接口 up/up",
            }
        ],
    }

    plan_data_success = {
        "prometheus_evidence_runtime": {
            "ok": True,
            "status": "success",
            "profile": "interface_traffic",
            "query_names": ["in_bps", "out_bps", "oper_status"],
            "total_count": 3,
            "ok_count": 2,
            "failed_count": 1,
            "evidence_file": "/opt/netaiops-webhook/data/prometheus_evidence/demo.prometheus_evidence.json",
            "summary_text": (
                "Prometheus窗口证据：\n"
                "- 状态：成功 2 项，失败/无数据 1 项\n"
                "- Profile：interface_traffic\n"
                "- 查询项：in_bps, out_bps, oper_status\n"
                "- in_bps：当前值 1.20 Gbps，对比值 900.00 Mbps，趋势判断：明显上升"
            ),
            "elapsed_ms": 15000,
        }
    }

    plan_data_disabled = {
        "prometheus_evidence_runtime": {
            "ok": False,
            "status": "runtime_disabled",
            "summary_text": (
                "Prometheus窗口证据：\n"
                "- 状态：未执行\n"
                "- 原因：runtime sidecar 当前由配置开关关闭"
            ),
        }
    }

    merged_success = attach_prometheus_runtime_to_review(fake_review, plan_data_success)
    merged_disabled = attach_prometheus_runtime_to_review(fake_review, plan_data_disabled)

    print("========== success review ==========")
    print(json.dumps(summarize_review_prometheus(merged_success), ensure_ascii=False, indent=2))
    print("evidence_facts_count =", len(merged_success.get("evidence_facts") or []))
    print("sections_count =", len(merged_success.get("sections") or []))
    print("summary_text =")
    print(merged_success.get("summary_text"))

    print("\n========== disabled review ==========")
    print(json.dumps(summarize_review_prometheus(merged_disabled), ensure_ascii=False, indent=2))
    print("contains_prometheus =", "Prometheus窗口证据" in str(merged_disabled.get("summary_text") or ""))

    out_dir = ROOT / "data" / "v8_prometheus_mcp_poc"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"prometheus_review_hooks_test_{time.strftime('%Y%m%d_%H%M%S')}.json"
    out_file.write_text(json.dumps({
        "merged_success": merged_success,
        "merged_disabled": merged_disabled,
    }, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    print("\n========== 输出文件 ==========")
    print(out_file)

    ok_success = (
        summarize_review_prometheus(merged_success).get("visible") is True
        and "Prometheus窗口证据" in str(merged_success.get("summary_text") or "")
        and len(merged_success.get("evidence_facts") or []) >= 2
    )

    ok_disabled = (
        summarize_review_prometheus(merged_disabled).get("visible") is False
        and "Prometheus窗口证据" not in str(merged_disabled.get("summary_text") or "")
    )

    if ok_success and ok_disabled:
        print("\n[OK] Prometheus review hooks POC 成功。")
        return 0

    print("\n[WARN] Prometheus review hooks POC 未完全成功。")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
