#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试 Prometheus notification hooks。

不会发送咚咚。
不会触发真实 pipeline。
只测试 payload/text 适配逻辑。
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netaiops.prometheus_notification_hooks import (
    append_prometheus_runtime_to_text,
    attach_prometheus_runtime_to_payload,
    build_prometheus_runtime_payload,
    summarize_payload_prometheus,
)


def main() -> int:
    fake_payload = {
        "request_id": "demo",
        "title": "NetAIOps分析结果-demo",
        "notify_view": {
            "device": "DEMO-SW01",
            "alarm_content": "接口流量突降",
            "analysis_process": "1. 原始分析过程",
            "recommendations_text": "1. 原始建议",
        },
        "target": {
            "family": "interface_or_link_traffic_drop",
        },
    }

    success_plan_data = {
        "prometheus_evidence_runtime": {
            "enabled": True,
            "executed": True,
            "runtime_stage": "pipeline_sidecar",
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
            "created_at": "2026-05-31T00:00:00+00:00",
            "elapsed_ms": 15000,
        }
    }

    disabled_plan_data = {
        "prometheus_evidence_runtime": {
            "enabled": True,
            "executed": True,
            "runtime_stage": "pipeline_sidecar",
            "ok": False,
            "status": "runtime_disabled",
            "summary_text": (
                "Prometheus窗口证据：\n"
                "- 状态：未执行\n"
                "- 原因：runtime sidecar 当前由配置开关关闭"
            ),
        }
    }

    base_text = (
        "设备：DEMO-SW01\n\n"
        "告警内容：\n接口流量突降\n\n"
        "分析过程：\n1. 原始分析过程\n\n"
        "建议：\n1. 原始建议"
    )

    print("========== success runtime payload ==========")
    prom = build_prometheus_runtime_payload(success_plan_data)
    print(json.dumps(prom, ensure_ascii=False, indent=2))

    merged_payload = attach_prometheus_runtime_to_payload(fake_payload, success_plan_data)
    merged_text = append_prometheus_runtime_to_text(base_text, merged_payload)

    print("\n========== merged payload summary ==========")
    print(json.dumps(summarize_payload_prometheus(merged_payload), ensure_ascii=False, indent=2))

    print("\n========== merged text ==========")
    print(merged_text)

    print("\n========== runtime disabled should be hidden ==========")
    disabled_payload = attach_prometheus_runtime_to_payload(fake_payload, disabled_plan_data)
    disabled_text = append_prometheus_runtime_to_text(base_text, disabled_payload)
    print(json.dumps(summarize_payload_prometheus(disabled_payload), ensure_ascii=False, indent=2))
    print("contains_prometheus =", "Prometheus窗口证据" in disabled_text)

    out_dir = ROOT / "data" / "v8_prometheus_mcp_poc"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"prometheus_notification_hooks_test_{time.strftime('%Y%m%d_%H%M%S')}.json"
    out_file.write_text(json.dumps({
        "success_prometheus": prom,
        "merged_payload": merged_payload,
        "merged_text": merged_text,
        "disabled_payload": disabled_payload,
        "disabled_text": disabled_text,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n========== 输出文件 ==========")
    print(out_file)

    ok_success = (
        summarize_payload_prometheus(merged_payload).get("visible") is True
        and "Prometheus窗口证据" in merged_text
        and merged_text.index("Prometheus窗口证据") < merged_text.index("建议：")
    )

    ok_disabled = (
        summarize_payload_prometheus(disabled_payload).get("visible") is False
        and "Prometheus窗口证据" not in disabled_text
    )

    if ok_success and ok_disabled:
        print("\n[OK] Prometheus notification hooks POC 成功。")
        return 0

    print("\n[WARN] Prometheus notification hooks POC 未完全成功。")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
