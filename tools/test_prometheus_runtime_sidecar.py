#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试 Prometheus runtime sidecar。

测试内容：
1. POC profile=poc_count_up：应通过 Prometheus MCP 成功取证并落盘。
2. interface_traffic fake target：可能无数据，但不得 Traceback，必须可解释失败。
3. pipeline.py import：确认不影响模块加载。

不会触发真实告警 pipeline，不会 dispatch，不会发咚咚。
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netaiops.prometheus_runtime_sidecar import run_prometheus_evidence_sidecar_for_plan_result


POC_DIR = ROOT / "data" / "v8_prometheus_mcp_poc"


def safe_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


def build_fake_plan_result(
    request_id: str,
    profile: str,
    query_names: list[str],
    target_context: dict,
    status: str = "metadata_ready",
) -> dict:
    plan_path = POC_DIR / f"{request_id}.fake.plan.json"

    plan_data = {
        "request_id": request_id,
        "plan_id": f"fake-plan-{request_id}",
        "source": "poc",
        "plan_status": "generated",
        "target_scope": target_context,
        "prometheus_evidence_first": {
            "enabled": True,
            "status": status,
            "runtime_stage": "plan_metadata_only",
            "source": "test",
            "backend_preference": "prometheus_mcp",
            "fallback": "http_api",
            "evidence_profile": profile,
            "query_names": query_names,
            "lookback_minutes": 15,
            "compare_offset_minutes": 5,
            "step_seconds": 60,
            "step": "60s",
            "max_candidates_per_query": 1,
            "sidecar_overall_timeout_seconds": 30,
            "sidecar_parallel_workers": 3,
            "required_labels": [],
            "missing_required_labels": [],
            "target_context": target_context,
            "stop_device_cli_if_not_confirmed": False,
            "unavailable_policy": "continue_cli_evidence",
        },
        "v8_features": {
            "prometheus_evidence_first": {
                "enabled": True,
                "status": status,
                "runtime_stage": "plan_metadata_only",
                "profile": profile,
                "query_names": query_names,
                "missing_required_labels": [],
            }
        },
    }

    safe_write_json(plan_path, plan_data)

    return {
        "plan_file": str(plan_path),
        "plan_data": plan_data,
    }


def print_result(name: str, result: dict) -> None:
    print(f"\n========== {name} ==========")
    print("ok =", result.get("ok"))
    print("skipped =", result.get("skipped"))
    print("error =", result.get("error"))
    print("evidence_file =", result.get("evidence_file"))

    record = result.get("record") or {}
    print("record_status =", record.get("status"))
    print("record_ok =", record.get("ok"))
    print("profile =", record.get("profile"))
    print("query_names =", record.get("query_names"))
    print("elapsed_ms =", record.get("elapsed_ms"))
    print("summary_text =")
    print(record.get("summary_text") or "")

    pr = result.get("plan_result") or {}
    pd = pr.get("plan_data") or {}
    runtime = pd.get("prometheus_evidence_runtime") or {}
    print("plan.prometheus_evidence_runtime =")
    print(json.dumps(runtime, ensure_ascii=False, indent=2, default=str))


def main() -> int:
    POC_DIR.mkdir(parents=True, exist_ok=True)

    ts = time.strftime("%Y%m%d_%H%M%S")

    # 1. 成功路径：poc_count_up/current，无需 target label。
    request_id1 = f"poc_sidecar_count_up_{ts}"
    plan_result1 = build_fake_plan_result(
        request_id=request_id1,
        profile="poc_count_up",
        query_names=["current"],
        target_context={},
    )
    result1 = run_prometheus_evidence_sidecar_for_plan_result(
        request_id=request_id1,
        plan_result=plan_result1,
        write_record=True,
        update_plan=True,
        force=True,
    )
    print_result("POC count(up) sidecar", result1)

    # 2. 失败但可解释路径：fake interface target，大概率无数据，但不得阻断。
    request_id2 = f"poc_sidecar_interface_fake_{ts}"
    plan_result2 = build_fake_plan_result(
        request_id=request_id2,
        profile="interface_traffic",
        query_names=["in_bps", "out_bps", "oper_status"],
        target_context={
            "device_ip": "10.255.255.254",
            "ip": "10.255.255.254",
            "instance": "10.255.255.254",
            "if_name": "Ethernet999/999",
            "ifName": "Ethernet999/999",
            "interface": "Ethernet999/999",
        },
    )
    result2 = run_prometheus_evidence_sidecar_for_plan_result(
        request_id=request_id2,
        plan_result=plan_result2,
        write_record=True,
        update_plan=True,
        force=True,
    )
    print_result("Fake interface sidecar", result2)


    # 4. runtime disabled guard：不传 force，应被 config.yaml 全局开关拦截，不执行 Prometheus 查询。
    request_id3 = f"poc_sidecar_runtime_disabled_{ts}"
    plan_result3 = build_fake_plan_result(
        request_id=request_id3,
        profile="poc_count_up",
        query_names=["current"],
        target_context={},
    )
    result3 = run_prometheus_evidence_sidecar_for_plan_result(
        request_id=request_id3,
        plan_result=plan_result3,
        write_record=True,
        update_plan=True,
        force=False,
    )
    print_result("runtime disabled guard test", result3)

    # 3. import pipeline，确认 patch 不影响模块加载。
    from netaiops import pipeline
    print("\n========== pipeline import ==========")
    print("[OK] netaiops.pipeline import success")
    print("run_pipeline_for_request_id =", pipeline.run_pipeline_for_request_id)

    ok1 = bool(result1.get("ok")) and not bool(result1.get("skipped"))
    no_crash2 = result2.get("record") is not None and result2.get("error") is None
    guard_ok3 = bool(result3.get("skipped")) and ((result3.get("record") or {}).get("status") == "runtime_disabled")

    elapsed2 = ((result2.get("record") or {}).get("elapsed_ms") or 0)
    print("\n========== performance check ==========")
    print("fake_interface_elapsed_ms =", elapsed2)
    print("expected_under_ms =", 40000)

    out_file = POC_DIR / f"prometheus_runtime_sidecar_test_{ts}.json"
    safe_write_json(out_file, {
        "result1": result1,
        "result2": result2,
    })

    print("\n========== 输出文件 ==========")
    print(out_file)

    if ok1 and no_crash2 and guard_ok3:
        print("\n[OK] Prometheus runtime sidecar POC 成功。")
        return 0

    print("\n[WARN] Prometheus runtime sidecar POC 未完全成功，请查看上方输出。")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
