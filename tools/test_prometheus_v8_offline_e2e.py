#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Prometheus v8 离线端到端验证。

验证链路：
fake plan metadata
-> runtime sidecar force=True
-> evidence 落盘
-> review hook 合并
-> notification hook 合并
-> 最终文本包含 Prometheus窗口证据

不会重启服务，不发送咚咚，不触发真实 pipeline。
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netaiops.prometheus_runtime_sidecar import run_prometheus_evidence_sidecar_for_plan_result
from netaiops.prometheus_review_hooks import attach_prometheus_runtime_to_review, summarize_review_prometheus
from netaiops.prometheus_notification_hooks import (
    append_prometheus_runtime_to_text,
    attach_prometheus_runtime_to_payload,
    summarize_payload_prometheus,
)


POC_DIR = ROOT / "data" / "v8_prometheus_mcp_poc"


def safe_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


def build_fake_plan_result(request_id: str) -> dict:
    plan_file = POC_DIR / f"{request_id}.offline.plan.json"
    plan_data = {
        "request_id": request_id,
        "plan_id": f"offline-plan-{request_id}",
        "source": "offline_e2e",
        "target_scope": {},
        "prometheus_evidence_first": {
            "enabled": True,
            "status": "metadata_ready",
            "runtime_stage": "plan_metadata_only",
            "source": "offline_e2e",
            "backend_preference": "prometheus_mcp",
            "fallback": "http_api",
            "evidence_profile": "poc_count_up",
            "query_names": ["current"],
            "lookback_minutes": 15,
            "compare_offset_minutes": 5,
            "step_seconds": 60,
            "step": "60s",
            "max_candidates_per_query": 1,
            "sidecar_overall_timeout_seconds": 30,
            "sidecar_parallel_workers": 1,
            "required_labels": [],
            "missing_required_labels": [],
            "target_context": {},
            "stop_device_cli_if_not_confirmed": False,
            "unavailable_policy": "continue_cli_evidence",
        },
    }
    safe_write_json(plan_file, plan_data)
    return {
        "plan_file": str(plan_file),
        "plan_data": plan_data,
    }


def main() -> int:
    POC_DIR.mkdir(parents=True, exist_ok=True)
    request_id = f"offline_e2e_{time.strftime('%Y%m%d_%H%M%S')}"

    print("========== 1. runtime sidecar force=True ==========")
    plan_result = build_fake_plan_result(request_id)
    sidecar = run_prometheus_evidence_sidecar_for_plan_result(
        request_id=request_id,
        plan_result=plan_result,
        write_record=True,
        update_plan=True,
        force=True,
    )
    print("sidecar.ok =", sidecar.get("ok"))
    print("sidecar.skipped =", sidecar.get("skipped"))
    print("evidence_file =", sidecar.get("evidence_file"))

    plan_data = ((sidecar.get("plan_result") or {}).get("plan_data") or {})
    runtime = plan_data.get("prometheus_evidence_runtime") or {}
    print("runtime.status =", runtime.get("status"))
    print("runtime.ok_count =", runtime.get("ok_count"))

    print("\n========== 2. review hook ==========")
    review = {
        "request_id": request_id,
        "summary_text": "离线 Review：CLI 取证摘要。",
        "evidence_facts": [],
    }
    merged_review = attach_prometheus_runtime_to_review(review, plan_data)
    print(json.dumps(summarize_review_prometheus(merged_review), ensure_ascii=False, indent=2))

    print("\n========== 3. notification hook ==========")
    payload = {
        "request_id": request_id,
        "title": "离线通知测试",
        "text": "设备：offline-demo\n\n分析过程：\n离线通知测试\n\n建议：\n继续观察",
    }
    merged_payload = attach_prometheus_runtime_to_payload(payload, plan_data)
    final_text = append_prometheus_runtime_to_text(payload["text"], merged_payload)
    print(json.dumps(summarize_payload_prometheus(merged_payload), ensure_ascii=False, indent=2))
    print("\nfinal_text =")
    print(final_text)

    out_file = POC_DIR / f"prometheus_v8_offline_e2e_{request_id}.json"
    safe_write_json(out_file, {
        "request_id": request_id,
        "sidecar": sidecar,
        "merged_review": merged_review,
        "merged_payload": merged_payload,
        "final_text": final_text,
    })

    print("\n========== 输出文件 ==========")
    print(out_file)

    ok = (
        sidecar.get("ok") is True
        and summarize_review_prometheus(merged_review).get("visible") is True
        and summarize_payload_prometheus(merged_payload).get("visible") is True
        and "Prometheus窗口证据" in final_text
        and final_text.index("Prometheus窗口证据") < final_text.index("建议：")
    )

    if ok:
        print("\n[OK] Prometheus v8 offline E2E POC 成功。")
        return 0

    print("\n[WARN] Prometheus v8 offline E2E POC 未完全成功。")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
