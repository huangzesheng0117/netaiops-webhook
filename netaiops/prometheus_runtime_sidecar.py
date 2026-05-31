#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetAIOps webhook v8 Prometheus Evidence runtime sidecar.

职责：
- 在 pipeline 生成 plan 后，根据 plan.prometheus_evidence_first 判断是否需要 Prometheus 取证。
- 调用 collect_prometheus_evidence() 执行 Prometheus MCP query_range。
- 将证据落盘到 data/prometheus_evidence/。
- 将证据摘要和 evidence_file 回写到 plan metadata。
- 不阻断原有 CLI 取证、dispatch、callback、review、notifier。

安全原则：
- 只读查询。
- 失败只标记 unavailable，不抛出到主链路。
- 不直接修改咚咚通知格式。
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
import json
import time
import yaml
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from netaiops.prometheus_evidence_v8 import collect_prometheus_evidence
from netaiops.prometheus_evidence_formatter import build_prometheus_evidence_section


BASE_DIR = Path("/opt/netaiops-webhook")
DATA_DIR = BASE_DIR / "data"
PROM_EVIDENCE_DIR = DATA_DIR / "prometheus_evidence"

def load_runtime_sidecar_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """
    读取 config.yaml 中 prometheus_mcp.runtime_sidecar。
    默认 enabled=False，避免服务重启后未经确认直接执行生产 Prometheus 查询。
    """
    try:
        cfg_path = Path(config_path)
        if not cfg_path.exists():
            return {"enabled": False, "reason": "config.yaml not found"}
        cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
        pm = cfg.get("prometheus_mcp") or {}
        runtime = pm.get("runtime_sidecar") or {}
        if not isinstance(runtime, dict):
            runtime = {}
        return {
            "enabled": bool(runtime.get("enabled", False)),
            "mode": runtime.get("mode", "guarded"),
            "max_queries_per_alert": int(runtime.get("max_queries_per_alert") or 4),
            "overall_timeout_seconds": int(runtime.get("overall_timeout_seconds") or 30),
            "max_candidates_per_query": int(runtime.get("max_candidates_per_query") or 1),
            "parallel_workers": int(runtime.get("parallel_workers") or 3),
            "failure_policy": runtime.get("failure_policy", "continue_cli_evidence"),
            "write_record": bool(runtime.get("write_record", True)),
            "update_plan": bool(runtime.get("update_plan", True)),
        }
    except Exception as exc:
        return {
            "enabled": False,
            "reason": f"{type(exc).__name__}: {exc}",
        }


def build_runtime_disabled_record(
    request_id: str,
    plan_data: Dict[str, Any],
    runtime_cfg: Dict[str, Any],
) -> Dict[str, Any]:
    meta = plan_data.get("prometheus_evidence_first") or {}
    reason = "runtime sidecar disabled by config.yaml prometheus_mcp.runtime_sidecar.enabled=false"
    if runtime_cfg.get("reason"):
        reason = str(runtime_cfg.get("reason"))

    return {
        "ok": False,
        "request_id": request_id,
        "status": "runtime_disabled",
        "reason": reason,
        "created_at": now_utc_str(),
        "plan_id": plan_data.get("plan_id", ""),
        "profile": meta.get("evidence_profile"),
        "query_names": meta.get("query_names") or [],
        "target_context": meta.get("target_context") or {},
        "metadata": meta,
        "runtime_config": runtime_cfg,
        "evidences": [],
        "summary_text": (
            "Prometheus窗口证据：\n"
            "- 状态：未执行\n"
            "- 原因：runtime sidecar 当前由配置开关关闭"
        ),
    }



def now_utc_str() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)


def read_json_file(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def first_non_empty(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def build_unavailable_record(
    request_id: str,
    plan_data: Dict[str, Any],
    reason: str,
    status: str = "unavailable",
) -> Dict[str, Any]:
    meta = plan_data.get("prometheus_evidence_first") or {}
    record = {
        "ok": False,
        "request_id": request_id,
        "status": status,
        "reason": reason,
        "created_at": now_utc_str(),
        "plan_id": plan_data.get("plan_id", ""),
        "profile": meta.get("evidence_profile"),
        "query_names": meta.get("query_names") or [],
        "target_context": meta.get("target_context") or {},
        "metadata": meta,
        "evidences": [],
        "summary_text": (
            "Prometheus窗口证据：\n"
            "- 状态：不可用\n"
            f"- 原因：{reason}"
        ),
    }
    return record


def build_aggregate_summary(record: Dict[str, Any]) -> str:
    evidences = record.get("evidences") or []

    if not evidences:
        reason = record.get("reason") or record.get("status") or "unknown"
        return "Prometheus窗口证据：\n- 状态：不可用\n- 原因：" + str(reason)

    ok_items = [x for x in evidences if x.get("ok")]
    failed_items = [x for x in evidences if not x.get("ok")]

    lines: List[str] = []
    lines.append("Prometheus窗口证据：")
    lines.append(f"- 状态：成功 {len(ok_items)} 项，失败/无数据 {len(failed_items)} 项")
    lines.append(f"- Profile：{record.get('profile') or '-'}")
    lines.append(f"- 查询项：{', '.join(record.get('query_names') or []) or '-'}")
    lines.append(f"- 证据文件：{record.get('evidence_file') or '-'}")

    for item in ok_items[:3]:
        query_name = item.get("query_name") or "-"
        section = build_prometheus_evidence_section(item)
        text = section.get("text") or ""
        compact = "；".join([line.strip("- ").strip() for line in text.splitlines() if line.strip() and "Prometheus窗口证据" not in line])
        if compact:
            lines.append(f"- {query_name}：{compact[:500]}")

    for item in failed_items[:3]:
        lines.append(
            f"- {item.get('query_name') or '-'}：不可用，"
            f"原因={item.get('status') or item.get('error') or 'unknown'}"
        )

    return "\n".join(lines)


def build_plan_prometheus_summary(record: Dict[str, Any]) -> Dict[str, Any]:
    evidences = record.get("evidences") or []
    ok_count = sum(1 for x in evidences if x.get("ok"))

    return {
        "enabled": True,
        "executed": True,
        "runtime_stage": "pipeline_sidecar",
        "ok": bool(record.get("ok")),
        "status": record.get("status"),
        "profile": record.get("profile"),
        "query_names": record.get("query_names") or [],
        "total_count": len(evidences),
        "ok_count": ok_count,
        "failed_count": len(evidences) - ok_count,
        "evidence_file": record.get("evidence_file"),
        "summary_text": record.get("summary_text") or "",
        "created_at": record.get("created_at"),
        "elapsed_ms": record.get("elapsed_ms"),
    }


def update_plan_result_with_prometheus_record(
    plan_result: Dict[str, Any],
    record: Dict[str, Any],
) -> Dict[str, Any]:
    if not isinstance(plan_result, dict):
        return plan_result

    plan_data = plan_result.get("plan_data")
    plan_file = plan_result.get("plan_file")

    if not isinstance(plan_data, dict):
        return plan_result

    plan_data["prometheus_evidence_runtime"] = build_plan_prometheus_summary(record)

    features = plan_data.get("v8_features")
    if not isinstance(features, dict):
        features = {}

    features["prometheus_evidence_runtime"] = {
        "executed": True,
        "ok": bool(record.get("ok")),
        "status": record.get("status"),
        "profile": record.get("profile"),
        "ok_count": plan_data["prometheus_evidence_runtime"].get("ok_count"),
        "total_count": plan_data["prometheus_evidence_runtime"].get("total_count"),
        "evidence_file": record.get("evidence_file"),
    }
    plan_data["v8_features"] = features

    plan_result["plan_data"] = plan_data

    if plan_file:
        try:
            safe_write_json(Path(plan_file), plan_data)
        except Exception as exc:
            plan_result["prometheus_evidence_plan_write_error"] = f"{type(exc).__name__}: {exc}"

    return plan_result


def should_run_prometheus_sidecar(plan_data: Dict[str, Any]) -> tuple[bool, str]:
    meta = plan_data.get("prometheus_evidence_first") or {}

    if not isinstance(meta, dict) or not meta:
        return False, "prometheus_evidence_first metadata not found"

    if not bool(meta.get("enabled", False)):
        return False, f"prometheus_evidence_first disabled status={meta.get('status')}"

    status = str(meta.get("status") or "")
    if status not in ("metadata_ready", "metadata_ready_but_missing_required_labels"):
        return False, f"prometheus_evidence_first not ready status={status}"

    missing = meta.get("missing_required_labels") or []
    if missing:
        return False, "missing required labels: " + ",".join(str(x) for x in missing)

    profile = str(meta.get("evidence_profile") or "").strip()
    query_names = meta.get("query_names") or []
    if not profile or profile == "unknown":
        return False, "evidence_profile is empty or unknown"
    if not isinstance(query_names, list) or not query_names:
        return False, "query_names is empty"

    return True, "ready"


def run_prometheus_evidence_sidecar_for_plan_result(
    request_id: str,
    plan_result: Dict[str, Any],
    *,
    write_record: bool = True,
    update_plan: bool = True,
    force: bool = False,
) -> Dict[str, Any]:
    """
    pipeline 调用入口。

    返回：
    {
      ok,
      skipped,
      evidence_file,
      record,
      plan_result,
      error
    }
    """
    started = time.time()

    try:
        plan_data = (plan_result or {}).get("plan_data") or {}
        if not isinstance(plan_data, dict):
            record = {
                "ok": False,
                "request_id": request_id,
                "status": "invalid_plan",
                "reason": "plan_result.plan_data is not dict",
                "created_at": now_utc_str(),
                "evidences": [],
            }
            return {
                "ok": False,
                "skipped": True,
                "request_id": request_id,
                "record": record,
                "plan_result": plan_result,
                "error": record["reason"],
            }

        should_run, reason = should_run_prometheus_sidecar(plan_data)
        if not should_run:
            record = build_unavailable_record(
                request_id=request_id,
                plan_data=plan_data,
                reason=reason,
                status="skipped",
            )
            record["elapsed_ms"] = int((time.time() - started) * 1000)
            return {
                "ok": False,
                "skipped": True,
                "request_id": request_id,
                "record": record,
                "plan_result": plan_result,
                "error": None,
            }

        runtime_cfg = load_runtime_sidecar_config()
        if not force and not bool(runtime_cfg.get("enabled", False)):
            record = build_runtime_disabled_record(
                request_id=request_id,
                plan_data=plan_data,
                runtime_cfg=runtime_cfg,
            )
            record["elapsed_ms"] = int((time.time() - started) * 1000)

            # runtime disabled 也回写 plan metadata，便于后续 dry-run 观察，但不写正式证据文件。
            if update_plan:
                plan_result = update_plan_result_with_prometheus_record(plan_result, record)

            return {
                "ok": False,
                "skipped": True,
                "request_id": request_id,
                "record": record,
                "plan_result": plan_result,
                "error": None,
            }

        meta = plan_data.get("prometheus_evidence_first") or {}
        profile = str(meta.get("evidence_profile") or "").strip()
        query_names = meta.get("query_names") or []
        target_context = meta.get("target_context") or {}

        lookback_minutes = int(meta.get("lookback_minutes") or 15)
        compare_offset_minutes = int(meta.get("compare_offset_minutes") or 5)
        step = first_non_empty(meta.get("step"), f"{int(meta.get('step_seconds') or 60)}s")
        max_candidates_per_query = int(meta.get("max_candidates_per_query") or runtime_cfg.get("max_candidates_per_query") or 1)
        sidecar_overall_timeout_seconds = int(meta.get("sidecar_overall_timeout_seconds") or runtime_cfg.get("overall_timeout_seconds") or 30)
        sidecar_parallel_workers = int(meta.get("sidecar_parallel_workers") or runtime_cfg.get("parallel_workers") or 3)

        normalized_query_names = [str(x).strip() for x in query_names if str(x).strip()]
        sidecar_parallel_workers = max(1, min(sidecar_parallel_workers, len(normalized_query_names) or 1, 4))

        evidences: List[Dict[str, Any]] = []

        def _collect_one(qn: str) -> Dict[str, Any]:
            evidence = collect_prometheus_evidence(
                profile=profile,
                query_name=qn,
                target=target_context,
                lookback_minutes=lookback_minutes,
                compare_offset_minutes=compare_offset_minutes,
                step=step,
                max_candidates_per_query=max_candidates_per_query,
            )
            evidence["request_id"] = request_id
            evidence["query_name"] = qn
            return evidence

        if not normalized_query_names:
            evidences.append({
                "ok": False,
                "status": "query_names_empty",
                "query_name": "",
                "error": "query_names is empty",
                "profile": profile,
                "target": target_context,
            })
        else:
            executor = ThreadPoolExecutor(max_workers=sidecar_parallel_workers)
            futures = {}
            try:
                for qn in normalized_query_names:
                    futures[executor.submit(_collect_one, qn)] = qn

                remaining_timeout = max(1, sidecar_overall_timeout_seconds - int(time.time() - started))

                try:
                    for future in as_completed(futures, timeout=remaining_timeout):
                        qn = futures.get(future, "")
                        try:
                            evidences.append(future.result())
                        except Exception as exc:
                            evidences.append({
                                "ok": False,
                                "status": "sidecar_query_exception",
                                "query_name": qn,
                                "error": f"{type(exc).__name__}: {exc}",
                                "profile": profile,
                                "target": target_context,
                            })
                except FuturesTimeoutError:
                    pass

                completed_query_names = {str(x.get("query_name") or "") for x in evidences}
                for future, qn in futures.items():
                    if qn not in completed_query_names:
                        future.cancel()
                        evidences.append({
                            "ok": False,
                            "status": "sidecar_overall_timeout",
                            "query_name": qn,
                            "error": f"sidecar overall timeout reached: {sidecar_overall_timeout_seconds}s",
                            "profile": profile,
                            "target": target_context,
                        })
            finally:
                executor.shutdown(wait=False, cancel_futures=True)

        order = {name: idx for idx, name in enumerate(normalized_query_names)}
        evidences.sort(key=lambda x: order.get(str(x.get("query_name") or ""), 999))

        ok_count = sum(1 for x in evidences if x.get("ok"))

        record = {
            "ok": ok_count > 0,
            "request_id": request_id,
            "status": "success" if ok_count > 0 else "no_successful_evidence",
            "created_at": now_utc_str(),
            "plan_id": plan_data.get("plan_id", ""),
            "profile": profile,
            "query_names": query_names,
            "target_context": target_context,
            "metadata": meta,
            "evidences": evidences,
            "elapsed_ms": int((time.time() - started) * 1000),
        }

        evidence_file = ""
        if write_record:
            PROM_EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
            source = first_non_empty(plan_data.get("source"), "unknown")
            path = PROM_EVIDENCE_DIR / f"{source}_{request_id}.prometheus_evidence.json"
            record["evidence_file"] = str(path)
            record["summary_text"] = build_aggregate_summary(record)
            safe_write_json(path, record)
            evidence_file = str(path)
        else:
            record["summary_text"] = build_aggregate_summary(record)

        if update_plan:
            plan_result = update_plan_result_with_prometheus_record(plan_result, record)

        return {
            "ok": bool(record.get("ok")),
            "skipped": False,
            "request_id": request_id,
            "evidence_file": evidence_file,
            "record": record,
            "plan_result": plan_result,
            "error": None,
        }

    except Exception as exc:
        record = {
            "ok": False,
            "request_id": request_id,
            "status": "sidecar_exception",
            "reason": f"{type(exc).__name__}: {exc}",
            "created_at": now_utc_str(),
            "elapsed_ms": int((time.time() - started) * 1000),
            "evidences": [],
            "summary_text": (
                "Prometheus窗口证据：\n"
                "- 状态：不可用\n"
                f"- 原因：{type(exc).__name__}: {exc}"
            ),
        }

        try:
            PROM_EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
            path = PROM_EVIDENCE_DIR / f"unknown_{request_id}.prometheus_evidence.error.json"
            record["evidence_file"] = str(path)
            safe_write_json(path, record)
        except Exception:
            pass

        return {
            "ok": False,
            "skipped": False,
            "request_id": request_id,
            "record": record,
            "plan_result": plan_result,
            "error": record["reason"],
        }

# ===== v8 prometheus compact summary override begin =====
# 只覆盖 Prometheus窗口证据的展示格式，不改变查询逻辑。
def _v8_compact_fmt_number(value, unit=""):
    if value is None:
        return "-"
    try:
        v = float(value)
    except Exception:
        return str(value)

    if unit == "bps":
        av = abs(v)
        if av >= 1000000000:
            return f"{v / 1000000000:.2f} Gbps"
        if av >= 1000000:
            return f"{v / 1000000:.2f} Mbps"
        if av >= 1000:
            return f"{v / 1000:.2f} Kbps"
        return f"{v:.2f} bps"

    if unit:
        return f"{v:.2f} {unit}"
    return f"{v:.2f}"


def _v8_compact_fmt_ratio(value):
    if value is None:
        return "-"
    try:
        return f"{float(value) * 100:.2f}%"
    except Exception:
        return str(value)


def _v8_compact_first_analysis(item):
    analysis = item.get("analysis") or {}
    analyses = analysis.get("analyses") or []
    if analyses and isinstance(analyses[0], dict):
        return analyses[0]
    return {}


def _v8_compact_one_item(item):
    query_name = str(item.get("query_name") or "-")
    unit = str(item.get("unit") or "")
    window = item.get("query_window") or {}
    first = _v8_compact_first_analysis(item)

    lookback = window.get("lookback_minutes") or 15
    step = window.get("step") or "60s"
    offset = window.get("compare_offset_minutes") or 5

    lines = []
    lines.append(f"- {query_name}:")
    lines.append(f"查询窗口：过去{lookback}分钟，step={step}，对比偏移={offset}分钟；")
    lines.append(
        "当前值：{current}；对比值：{compare}；变化量：{delta}；变化比例：{ratio}；"
        "窗口最大值：{wmax}；窗口最小值：{wmin}；窗口平均值：{wavg}；趋势判断：{verdict}".format(
            current=_v8_compact_fmt_number(first.get("current"), unit),
            compare=_v8_compact_fmt_number(first.get("offset"), unit),
            delta=_v8_compact_fmt_number(first.get("delta"), unit),
            ratio=_v8_compact_fmt_ratio(first.get("change_ratio")),
            wmax=_v8_compact_fmt_number(first.get("window_max"), unit),
            wmin=_v8_compact_fmt_number(first.get("window_min"), unit),
            wavg=_v8_compact_fmt_number(first.get("window_avg"), unit),
            verdict=first.get("trend_verdict") or "-",
        )
    )
    return "\n".join(lines)


def build_aggregate_summary(record):
    evidences = record.get("evidences") or []
    if not evidences:
        reason = record.get("reason") or record.get("status") or "unknown"
        return "Prometheus窗口证据：\n- 状态：不可用\n- 原因：" + str(reason)

    ok_items = [x for x in evidences if x.get("ok")]
    failed_items = [x for x in evidences if not x.get("ok")]

    lines = []
    lines.append("Prometheus窗口证据：")
    lines.append(f"- 状态：成功 {len(ok_items)} 项，失败/无数据 {len(failed_items)} 项")

    for item in ok_items:
        lines.append("")
        lines.append(_v8_compact_one_item(item))

    for item in failed_items:
        query_name = item.get("query_name") or "-"
        reason = item.get("status") or item.get("error") or "unknown"
        lines.append("")
        lines.append(f"- {query_name}:")
        lines.append(f"状态：不可用；原因：{reason}")

    return "\n".join(lines)
# ===== v8 prometheus compact summary override end =====

# ===== v8 prometheus compact summary spacing override begin =====
# Batch24：只微调 Prometheus窗口证据的换行间距。
def build_aggregate_summary(record):
    evidences = record.get("evidences") or []

    if not evidences:
        reason = record.get("reason") or record.get("status") or "unknown"
        return "Prometheus窗口证据：\n- 状态：不可用\n- 原因：" + str(reason)

    ok_items = [x for x in evidences if x.get("ok")]
    failed_items = [x for x in evidences if not x.get("ok")]

    lines = []
    lines.append("Prometheus窗口证据：")
    lines.append(f"- 状态：成功 {len(ok_items)} 项，失败/无数据 {len(failed_items)} 项")

    for item in ok_items:
        lines.append(_v8_compact_one_item(item))

    for item in failed_items:
        query_name = item.get("query_name") or "-"
        reason = item.get("status") or item.get("error") or "unknown"
        lines.append(f"- {query_name}:")
        lines.append(f"状态：不可用；原因：{reason}")

    return "\n".join(lines)
# ===== v8 prometheus compact summary spacing override end =====
