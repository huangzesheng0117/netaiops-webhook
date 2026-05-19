from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STAGES = [
    "received",
    "normalized",
    "analyzed",
    "planned",
    "policy_checked",
    "dispatched",
    "executed",
    "judged",
    "reviewed",
    "notified",
]

STAGE_LABELS = {
    "received": "告警接入",
    "normalized": "事件标准化",
    "analyzed": "LLM 初步分析",
    "planned": "只读取证计划生成",
    "policy_checked": "安全策略校验",
    "dispatched": "执行请求生成",
    "executed": "MCP/Runner 执行",
    "judged": "执行结果判错",
    "reviewed": "证据复盘生成",
    "notified": "通知发送",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def safe_read_json(path: Path | None) -> dict[str, Any]:
    if not path or not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "_read_error": str(exc),
            "_path": str(path),
        }


def first_existing_file(base_dir: Path, patterns: list[str]) -> Path | None:
    for pattern in patterns:
        files = sorted(base_dir.glob(pattern), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
        if files:
            return files[0]
    return None


def find_request_files(base_dir: str | Path, request_id: str) -> dict[str, str]:
    base = Path(base_dir)

    mapping = {
        "raw": first_existing_file(base, [
            f"data/raw/*{request_id}*.json",
            f"data/raw/**/*{request_id}*.json",
        ]),
        "normalized": first_existing_file(base, [
            f"data/normalized/*{request_id}*.json",
            f"data/normalized/**/*{request_id}*.json",
        ]),
        "analysis": first_existing_file(base, [
            f"data/analysis/*{request_id}*.analysis.json",
            f"data/analysis/*{request_id}*.json",
            f"data/analysis/**/*{request_id}*.json",
        ]),
        "plan": first_existing_file(base, [
            f"data/plans/*{request_id}*.plan.json",
            f"data/plans/*{request_id}*.json",
            f"data/plans/**/*{request_id}*.json",
        ]),
        "dispatch": first_existing_file(base, [
            f"data/dispatch/*{request_id}*.dispatch.request.json",
            f"data/dispatch/*{request_id}*.json",
            f"data/dispatch/**/*{request_id}*.json",
        ]),
        "runner_result": first_existing_file(base, [
            f"data/callback/{request_id}.runner.result.json",
            f"data/callback/*{request_id}*.runner.result.json",
            f"data/callback/**/*{request_id}*.runner.result.json",
        ]),
        "callback_payload": first_existing_file(base, [
            f"data/callback/{request_id}.callback.payload.json",
            f"data/callback/*{request_id}*.callback.payload.json",
            f"data/callback/**/*{request_id}*.callback.payload.json",
        ]),
        "execution": first_existing_file(base, [
            f"data/execution/*{request_id}*.execution.json",
            f"data/execution/*{request_id}*.json",
            f"data/execution/**/*{request_id}*.json",
        ]),
        "review": first_existing_file(base, [
            f"data/reviews/*{request_id}*.review.json",
            f"data/reviews/*{request_id}*.json",
            f"data/reviews/**/*{request_id}*.json",
        ]),
    }

    return {k: str(v) for k, v in mapping.items() if v is not None}


def unwrap_execution(data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    if isinstance(data.get("execution_data"), dict):
        return data.get("execution_data") or {}
    if isinstance(data.get("callback_result"), dict):
        cr = data.get("callback_result") or {}
        if isinstance(cr.get("execution_data"), dict):
            return cr.get("execution_data") or {}
    return data


def unwrap_review(data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    if isinstance(data.get("review_data"), dict):
        return data.get("review_data") or {}
    if isinstance(data.get("review_result"), dict):
        rr = data.get("review_result") or {}
        if isinstance(rr.get("review_data"), dict):
            return rr.get("review_data") or {}
    return data


def get_nested(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    cur: Any = data
    for key in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
    return default if cur is None else cur


def stage_item(stage: str, status: str, file_key: str = "", file_path: str = "", details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "stage": stage,
        "label": STAGE_LABELS.get(stage, stage),
        "status": status,
        "file_key": file_key,
        "file": file_path,
        "details": details or {},
    }


def summarize_command_results(execution_data: dict[str, Any]) -> dict[str, Any]:
    stats = execution_data.get("stats")
    if isinstance(stats, dict):
        return {
            "execution_status": stats.get("execution_status") or execution_data.get("execution_status", ""),
            "total_commands": stats.get("total_commands", stats.get("command_total", 0)),
            "completed_commands": stats.get("completed_commands", stats.get("command_completed", 0)),
            "failed_commands": stats.get("failed_commands", stats.get("command_failed", 0)),
            "partial_commands": stats.get("partial_commands", stats.get("command_partial", 0)),
            "hard_error_count": stats.get("hard_error_count", 0),
        }

    command_results = execution_data.get("command_results") or []
    if not isinstance(command_results, list):
        command_results = []

    total = len(command_results)
    completed = 0
    failed = 0
    partial = 0
    hard_error = 0

    for item in command_results:
        if not isinstance(item, dict):
            continue
        status = safe_text(item.get("dispatch_status") or item.get("status"))
        judge = item.get("judge") if isinstance(item.get("judge"), dict) else {}
        final_status = safe_text(judge.get("final_status"))

        effective = final_status or status
        if effective == "completed":
            completed += 1
        elif effective == "partial":
            partial += 1
        elif effective == "failed":
            failed += 1

        if judge.get("hard_error") is True:
            hard_error += 1

    execution_status = execution_data.get("execution_status") or ("completed" if total and failed == 0 and partial == 0 else "partial" if total else "")

    return {
        "execution_status": execution_status,
        "total_commands": total,
        "completed_commands": completed,
        "failed_commands": failed,
        "partial_commands": partial,
        "hard_error_count": hard_error,
    }


def infer_session_status(timeline: list[dict[str, Any]]) -> str:
    if not timeline:
        return "empty"

    failed_stages = []
    for item in timeline:
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        status = safe_text(item.get("status"))

        if status in {"failed", "error"}:
            failed_stages.append(item.get("stage"))

        if item.get("stage") == "executed":
            if int(details.get("failed_commands") or 0) > 0:
                failed_stages.append("executed")
            if int(details.get("hard_error_count") or 0) > 0:
                failed_stages.append("judged")

    if failed_stages:
        return "needs_review"

    last = timeline[-1].get("stage")
    if last == "notified":
        return "completed"
    if last == "reviewed":
        return "reviewed"
    if last == "executed":
        return "executed"
    return "in_progress"


def build_investigation_session(request_id: str, base_dir: str | Path = ".") -> dict[str, Any]:
    base = Path(base_dir)
    files = find_request_files(base, request_id)

    raw_data = safe_read_json(Path(files["raw"])) if "raw" in files else {}
    normalized_data = safe_read_json(Path(files["normalized"])) if "normalized" in files else {}
    analysis_data = safe_read_json(Path(files["analysis"])) if "analysis" in files else {}
    plan_data = safe_read_json(Path(files["plan"])) if "plan" in files else {}
    dispatch_data = safe_read_json(Path(files["dispatch"])) if "dispatch" in files else {}
    runner_result_data = safe_read_json(Path(files["runner_result"])) if "runner_result" in files else {}
    callback_payload_data = safe_read_json(Path(files["callback_payload"])) if "callback_payload" in files else {}
    execution_data = unwrap_execution(safe_read_json(Path(files["execution"])) if "execution" in files else {})
    review_data = unwrap_review(safe_read_json(Path(files["review"])) if "review" in files else {})

    timeline: list[dict[str, Any]] = []

    if raw_data or "raw" in files:
        timeline.append(stage_item("received", "completed", "raw", files.get("raw", ""), {
            "source": raw_data.get("source") or get_nested(raw_data, "normalized_event", "source", default=""),
        }))

    if normalized_data or "normalized" in files:
        timeline.append(stage_item("normalized", "completed", "normalized", files.get("normalized", ""), {
            "source": normalized_data.get("source", ""),
            "hostname": normalized_data.get("hostname", ""),
            "alarm_type": normalized_data.get("alarm_type", ""),
            "object_name": normalized_data.get("object_name", ""),
        }))

    if analysis_data or "analysis" in files:
        analysis_status = safe_text(analysis_data.get("status")) or "completed"
        timeline.append(stage_item("analyzed", analysis_status, "analysis", files.get("analysis", ""), {
            "summary": analysis_data.get("summary", ""),
            "confidence": analysis_data.get("confidence", ""),
        }))

    if plan_data or "plan" in files:
        timeline.append(stage_item("planned", safe_text(plan_data.get("status")) or "completed", "plan", files.get("plan", ""), {
            "readonly_only": plan_data.get("readonly_only"),
            "execution_source": plan_data.get("execution_source", ""),
            "family": get_nested(plan_data, "family_result", "family", default=plan_data.get("family", "")),
            "capability_count": len(get_nested(plan_data, "capability_plan", "selected_capabilities", default=[]) or []),
        }))

        policy_result = plan_data.get("policy_result") if isinstance(plan_data.get("policy_result"), dict) else {}
        if policy_result:
            timeline.append(stage_item("policy_checked", safe_text(policy_result.get("policy_summary")) or "checked", "plan", files.get("plan", ""), {
                "auto_confirm_allowed": policy_result.get("auto_confirm_allowed"),
                "policy_summary": policy_result.get("policy_summary"),
                "reasons": policy_result.get("reasons") or [],
                "checked_items": policy_result.get("checked_items") or {},
            }))

    if dispatch_data or "dispatch" in files:
        guard_result = dispatch_data.get("guard_result") if isinstance(dispatch_data.get("guard_result"), dict) else {}
        timeline.append(stage_item("dispatched", "completed", "dispatch", files.get("dispatch", ""), {
            "all_readonly": guard_result.get("all_readonly"),
            "allowed_count": guard_result.get("allowed_count"),
            "blocked_count": guard_result.get("blocked_count"),
        }))

    if runner_result_data or execution_data or "runner_result" in files or "execution" in files:
        exec_source = execution_data if execution_data else runner_result_data
        stats = summarize_command_results(exec_source)
        timeline.append(stage_item("executed", safe_text(stats.get("execution_status")) or "completed", "execution", files.get("execution", files.get("runner_result", "")), stats))
        timeline.append(stage_item("judged", "completed" if int(stats.get("hard_error_count") or 0) == 0 else "needs_review", "execution", files.get("execution", files.get("runner_result", "")), {
            "hard_error_count": stats.get("hard_error_count", 0),
            "failed_commands": stats.get("failed_commands", 0),
        }))

    if review_data or "review" in files:
        timeline.append(stage_item("reviewed", safe_text(review_data.get("review_status")) or safe_text(review_data.get("status")) or "completed", "review", files.get("review", ""), {
            "family": review_data.get("family", ""),
            "confidence": get_nested(review_data, "evidence_bundle", "confidence", default=review_data.get("confidence", "")),
            "conclusion": review_data.get("conclusion", ""),
            "recommendation_count": len(review_data.get("recommendations") or []),
        }))

    notify_result = callback_payload_data.get("notify_result") if isinstance(callback_payload_data.get("notify_result"), dict) else {}
    if notify_result:
        timeline.append(stage_item("notified", "completed" if notify_result.get("sent") else "skipped", "callback_payload", files.get("callback_payload", ""), {
            "provider": notify_result.get("provider", ""),
            "sent": notify_result.get("sent"),
            "ok": notify_result.get("ok"),
            "status_code": notify_result.get("status_code"),
        }))

    target_scope = {}
    for source in [execution_data, plan_data, review_data, runner_result_data]:
        if isinstance(source.get("target_scope"), dict):
            target_scope = source.get("target_scope") or {}
            break

    classification = {}
    for source in [execution_data, plan_data, review_data, runner_result_data]:
        if isinstance(source.get("classification"), dict):
            classification = source.get("classification") or {}
            break

    session = {
        "schema_version": "v6.1.0",
        "request_id": request_id,
        "generated_at": utc_now_iso(),
        "source": "netaiops_webhook_v6_1_investigation_state",
        "session_status": infer_session_status(timeline),
        "v6_stage": "v6.1",
        "adaptive": {
            "enabled": False,
            "max_extra_rounds": 0,
            "max_extra_commands": 0,
            "reason": "v6.1 only records investigation timeline; adaptive investigation is disabled.",
        },
        "target_scope": target_scope,
        "classification": classification,
        "files": files,
        "timeline": timeline,
        "stage_order": STAGES,
    }

    return session


def persist_investigation_session(session: dict[str, Any], base_dir: str | Path = ".") -> Path:
    base = Path(base_dir)
    request_id = safe_text(session.get("request_id"))
    if not request_id:
        raise ValueError("session.request_id is required")

    out_dir = base / "data" / "investigation"
    out_dir.mkdir(parents=True, exist_ok=True)

    out_file = out_dir / f"{request_id}.investigation.session.json"
    out_file.write_text(json.dumps(session, ensure_ascii=False, indent=2), encoding="utf-8")
    return out_file


def build_and_persist_investigation_session(request_id: str, base_dir: str | Path = ".") -> tuple[dict[str, Any], Path]:
    session = build_investigation_session(request_id=request_id, base_dir=base_dir)
    path = persist_investigation_session(session=session, base_dir=base_dir)
    return session, path


def render_session_text(session: dict[str, Any]) -> str:
    lines = []
    lines.append(f"request_id: {session.get('request_id')}")
    lines.append(f"v6_stage: {session.get('v6_stage')}")
    lines.append(f"session_status: {session.get('session_status')}")
    lines.append(f"generated_at: {session.get('generated_at')}")
    lines.append("")

    target = session.get("target_scope") if isinstance(session.get("target_scope"), dict) else {}
    if target:
        lines.append("target_scope:")
        for key in ["hostname", "device_ip", "alarm_type", "interface", "interfaces"]:
            if key in target:
                lines.append(f"  {key}: {target.get(key)}")
        lines.append("")

    lines.append("timeline:")
    for item in session.get("timeline", []) or []:
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        short = ""
        if item.get("stage") == "executed":
            short = f" total={details.get('total_commands')} completed={details.get('completed_commands')} failed={details.get('failed_commands')} hard_error={details.get('hard_error_count')}"
        elif item.get("stage") == "reviewed":
            short = f" confidence={details.get('confidence')} conclusion={safe_text(details.get('conclusion'))[:80]}"
        elif item.get("stage") == "notified":
            short = f" sent={details.get('sent')} ok={details.get('ok')} status_code={details.get('status_code')}"
        elif item.get("stage") == "policy_checked":
            short = f" policy={details.get('policy_summary')} allowed={details.get('auto_confirm_allowed')}"

        lines.append(f"  - {item.get('stage')} [{item.get('status')}] {item.get('label')}{short}")
        if item.get("file"):
            lines.append(f"    file: {item.get('file')}")

    return "\n".join(lines)

# ===== v6.1 batch2 notified stage helper begin =====
def upsert_timeline_stage(session: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    session = dict(session or {})
    timeline = list(session.get("timeline") or [])
    stage = safe_text(item.get("stage"))

    if not stage:
        return session

    replaced = False
    new_timeline = []
    for old in timeline:
        if old.get("stage") == stage:
            if not replaced:
                new_timeline.append(item)
                replaced = True
            continue
        new_timeline.append(old)

    if not replaced:
        new_timeline.append(item)

    order = {name: idx for idx, name in enumerate(STAGES)}
    new_timeline.sort(key=lambda x: order.get(x.get("stage"), 999))

    session["timeline"] = new_timeline
    session["session_status"] = infer_session_status(new_timeline)
    session["generated_at"] = utc_now_iso()
    return session


def append_notified_stage(
    session: dict[str, Any],
    notify_result: dict[str, Any] | None,
    file_path: str = "",
) -> dict[str, Any]:
    notify_result = notify_result or {}

    sent = notify_result.get("sent")
    ok = notify_result.get("ok")
    status_code = notify_result.get("status_code")
    provider = notify_result.get("provider", "")

    if sent is True:
        status = "completed"
    elif sent is False:
        status = "skipped"
    else:
        status = "unknown"

    item = stage_item(
        "notified",
        status,
        "runtime_notify_result",
        file_path,
        {
            "provider": provider,
            "sent": sent,
            "ok": ok,
            "status_code": status_code,
            "request_id": notify_result.get("request_id", ""),
        },
    )

    return upsert_timeline_stage(session, item)


def build_persist_session_with_notify_result(
    request_id: str,
    notify_result: dict[str, Any] | None = None,
    base_dir: str | Path = ".",
) -> tuple[dict[str, Any], Path]:
    session = build_investigation_session(request_id=request_id, base_dir=base_dir)
    session = append_notified_stage(session, notify_result or {})
    path = persist_investigation_session(session=session, base_dir=base_dir)
    return session, path
# ===== v6.1 batch2 notified stage helper end =====

# ===== v6.1 batch2 repair preserve runtime stages begin =====
_v61_original_build_and_persist_investigation_session = build_and_persist_investigation_session


def load_existing_investigation_session(request_id: str, base_dir: str | Path = ".") -> dict[str, Any]:
    base = Path(base_dir)
    session_file = base / "data" / "investigation" / f"{request_id}.investigation.session.json"
    return safe_read_json(session_file)


def preserve_runtime_stages(new_session: dict[str, Any], old_session: dict[str, Any] | None) -> dict[str, Any]:
    old_session = old_session or {}
    old_timeline = old_session.get("timeline") if isinstance(old_session.get("timeline"), list) else []

    # v6.1 batch2 中，notified 可能来自 callback runtime，而不是历史 artifact 文件。
    # 手工 --build 重新扫描历史文件时，不应该把 runtime notified 阶段覆盖丢失。
    for old_item in old_timeline:
        if not isinstance(old_item, dict):
            continue
        if old_item.get("stage") in {"notified"}:
            new_session = upsert_timeline_stage(new_session, old_item)

    return new_session


def build_and_persist_investigation_session(request_id: str, base_dir: str | Path = ".") -> tuple[dict[str, Any], Path]:
    old_session = load_existing_investigation_session(request_id=request_id, base_dir=base_dir)
    session = build_investigation_session(request_id=request_id, base_dir=base_dir)
    session = preserve_runtime_stages(session, old_session)
    path = persist_investigation_session(session=session, base_dir=base_dir)
    return session, path
# ===== v6.1 batch2 repair preserve runtime stages end =====

# ===== v6.3 batch3 skill context bridge begin =====
try:
    _v63_original_build_investigation_session = build_investigation_session
except NameError:
    _v63_original_build_investigation_session = None


if _v63_original_build_investigation_session is not None:
    def build_investigation_session(request_id: str, base_dir: str | Path = ".") -> dict[str, Any]:
        session = _v63_original_build_investigation_session(request_id=request_id, base_dir=base_dir)
        try:
            from netaiops.skill_session_context import attach_skill_context_to_session
            return attach_skill_context_to_session(session, base_dir=base_dir)
        except Exception as exc:
            session["skill_context"] = {
                "enabled": True,
                "stage": "v6.3",
                "matched": False,
                "reason": "skill_context_error",
                "error": str(exc),
            }
            return session


try:
    _v63_original_render_session_text = render_session_text
except NameError:
    _v63_original_render_session_text = None


if _v63_original_render_session_text is not None:
    def render_session_text(session: dict[str, Any]) -> str:
        text = _v63_original_render_session_text(session)
        sc = session.get("skill_context") if isinstance(session.get("skill_context"), dict) else {}
        if not sc:
            return text

        lines = [
            "",
            "skill_context:",
            f"  matched: {sc.get('matched')}",
            f"  family: {sc.get('family')}",
            f"  skill_name: {sc.get('skill_name')}",
            f"  skill_version: {sc.get('skill_version')}",
            f"  risk_level: {sc.get('risk_level')}",
            f"  binding_verdict: {sc.get('binding_verdict')}",
            f"  allowed_tools: {', '.join(sc.get('allowed_tools') or [])}",
            f"  allowed_capabilities: {', '.join(sc.get('allowed_capabilities') or [])}",
            f"  parsers: {', '.join(sc.get('parsers') or [])}",
        ]

        warnings = sc.get("warnings") or []
        if warnings:
            lines.append("  warnings:")
            for item in warnings:
                lines.append(f"    - {item}")

        violations = sc.get("violations") or []
        if violations:
            lines.append("  violations:")
            for item in violations:
                lines.append(f"    - {item}")

        return text + "\n" + "\n".join(lines)
# ===== v6.3 batch3 skill context bridge end =====

# ===== v6.4 batch2 skill runtime context bridge begin =====
try:
    _v64_original_build_investigation_session = build_investigation_session
except NameError:
    _v64_original_build_investigation_session = None


if _v64_original_build_investigation_session is not None:
    def build_investigation_session(request_id: str, base_dir: str | Path = ".") -> dict[str, Any]:
        session = _v64_original_build_investigation_session(request_id=request_id, base_dir=base_dir)
        try:
            from netaiops.skill_runtime_session_context import attach_skill_runtime_context_to_session
            return attach_skill_runtime_context_to_session(
                session=session,
                base_dir=base_dir,
                levels=["metadata"],
            )
        except Exception as exc:
            session["skill_runtime_context"] = {
                "enabled": True,
                "stage": "v6.4",
                "matched": False,
                "reason": "skill_runtime_context_error",
                "error": str(exc),
            }
            return session


try:
    _v64_original_render_session_text = render_session_text
except NameError:
    _v64_original_render_session_text = None


if _v64_original_render_session_text is not None:
    def render_session_text(session: dict[str, Any]) -> str:
        text = _v64_original_render_session_text(session)
        rc = session.get("skill_runtime_context") if isinstance(session.get("skill_runtime_context"), dict) else {}
        if not rc:
            return text

        lines = [
            "",
            "skill_runtime_context:",
            f"  stage: {rc.get('stage')}",
            f"  runtime_version: {rc.get('runtime_version')}",
            f"  load_strategy: {rc.get('load_strategy')}",
            f"  matched: {rc.get('matched')}",
            f"  family: {rc.get('family')}",
            f"  skill_name: {rc.get('skill_name')}",
            f"  loaded_levels: {', '.join(rc.get('loaded_levels') or [])}",
            f"  content_embedded: {rc.get('content_embedded')}",
            f"  content_policy: {rc.get('content_policy')}",
        ]

        metadata = rc.get("metadata") if isinstance(rc.get("metadata"), dict) else {}
        if metadata:
            lines.extend([
                "  metadata:",
                f"    version: {metadata.get('version')}",
                f"    risk_level: {metadata.get('risk_level')}",
                f"    description: {metadata.get('description')}",
            ])

        return text + "\n" + "\n".join(lines)
# ===== v6.4 batch2 skill runtime context bridge end =====

# ===== v6.5 batch2 adaptive evidence context bridge begin =====
try:
    _v65_original_build_investigation_session = build_investigation_session
except NameError:
    _v65_original_build_investigation_session = None


if _v65_original_build_investigation_session is not None:
    def build_investigation_session(request_id: str, base_dir: str | Path = ".") -> dict[str, Any]:
        session = _v65_original_build_investigation_session(request_id=request_id, base_dir=base_dir)
        try:
            from netaiops.adaptive_session_context import attach_adaptive_evidence_context_to_session
            return attach_adaptive_evidence_context_to_session(
                session=session,
                base_dir=base_dir,
            )
        except Exception as exc:
            session["adaptive_evidence_context"] = {
                "enabled": True,
                "stage": "v6.5",
                "matched_skill": False,
                "dispatch_enabled": False,
                "reason": "adaptive_evidence_context_error",
                "error": str(exc),
            }
            return session


try:
    _v65_original_render_session_text = render_session_text
except NameError:
    _v65_original_render_session_text = None


if _v65_original_render_session_text is not None:
    def render_session_text(session: dict[str, Any]) -> str:
        text = _v65_original_render_session_text(session)
        ac = session.get("adaptive_evidence_context") if isinstance(session.get("adaptive_evidence_context"), dict) else {}
        if not ac:
            return text

        lines = [
            "",
            "adaptive_evidence_context:",
            f"  stage: {ac.get('stage')}",
            f"  mode: {ac.get('mode')}",
            f"  family: {ac.get('family')}",
            f"  skill_name: {ac.get('skill_name')}",
            f"  matched_skill: {ac.get('matched_skill')}",
            f"  dispatch_enabled: {ac.get('dispatch_enabled')}",
            f"  dispatch_reason: {ac.get('dispatch_reason')}",
            f"  adaptive_execution_enabled: {ac.get('adaptive_execution_enabled')}",
            f"  readonly_only: {ac.get('readonly_only')}",
            f"  candidate_count: {ac.get('candidate_count')}",
            f"  suppressed_candidate_count: {ac.get('suppressed_candidate_count')}",
            f"  policy_verdict: {ac.get('policy_verdict')}",
        ]

        gaps = ac.get("gaps") if isinstance(ac.get("gaps"), dict) else {}
        if gaps:
            lines.append(f"  required_missing: {', '.join(gaps.get('required_missing') or [])}")
            lines.append(f"  preferred_missing: {', '.join(gaps.get('preferred_missing') or [])}")

        candidates = ac.get("candidates") if isinstance(ac.get("candidates"), list) else []
        if candidates:
            lines.append("  candidates:")
            for item in candidates:
                if isinstance(item, dict):
                    lines.append(f"    - {item.get('command')} | {item.get('capability')} | {item.get('dispatch_status')}")

        violations = ac.get("policy_violations") or []
        if violations:
            lines.append("  policy_violations:")
            for item in violations:
                lines.append(f"    - {item}")

        warnings = ac.get("policy_warnings") or []
        if warnings:
            lines.append("  policy_warnings:")
            for item in warnings:
                lines.append(f"    - {item}")

        return text + "\n" + "\n".join(lines)
# ===== v6.5 batch2 adaptive evidence context bridge end =====

