from __future__ import annotations

from pathlib import Path
from typing import Any

from netaiops.investigation_state import STAGES, build_and_persist_investigation_session, safe_text


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _timeline(session: dict[str, Any]) -> list[dict[str, Any]]:
    value = session.get("timeline")
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _find_stage(session: dict[str, Any], stage: str) -> dict[str, Any] | None:
    for item in _timeline(session):
        if item.get("stage") == stage:
            return item
    return None


def validate_stage_order(session: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    order = {stage: idx for idx, stage in enumerate(STAGES)}

    last_idx = -1
    for item in _timeline(session):
        stage = safe_text(item.get("stage"))
        if not stage:
            violations.append("timeline contains item without stage")
            continue

        idx = order.get(stage)
        if idx is None:
            violations.append(f"unknown stage: {stage}")
            continue

        if idx < last_idx:
            violations.append(f"stage order violation: {stage}")
        last_idx = max(last_idx, idx)

    return violations


def evaluate_v6_1_boundary(session: dict[str, Any]) -> tuple[list[str], list[str]]:
    violations: list[str] = []
    warnings: list[str] = []

    if safe_text(session.get("v6_stage")) != "v6.1":
        violations.append(f"unexpected v6_stage: {session.get('v6_stage')}")

    adaptive = session.get("adaptive") if isinstance(session.get("adaptive"), dict) else {}
    if adaptive.get("enabled") is not False:
        violations.append("adaptive.enabled must be false in v6.1")

    if _as_int(adaptive.get("max_extra_rounds"), 0) != 0:
        violations.append("adaptive.max_extra_rounds must be 0 in v6.1")

    if _as_int(adaptive.get("max_extra_commands"), 0) != 0:
        violations.append("adaptive.max_extra_commands must be 0 in v6.1")

    if not _timeline(session):
        violations.append("timeline is empty")

    if _find_stage(session, "notified") is None:
        warnings.append("notified stage is missing; this may be normal for old sessions or non-notified flows")

    return violations, warnings


def evaluate_safety_policy_trace(session: dict[str, Any]) -> tuple[list[str], list[str]]:
    violations: list[str] = []
    warnings: list[str] = []

    policy_stage = _find_stage(session, "policy_checked")
    if not policy_stage:
        warnings.append("policy_checked stage is missing")
        return violations, warnings

    details = policy_stage.get("details") if isinstance(policy_stage.get("details"), dict) else {}
    checked = details.get("checked_items") if isinstance(details.get("checked_items"), dict) else {}

    readonly_only = checked.get("readonly_only")
    guard_all_readonly = checked.get("guard_all_readonly")
    command_count = _as_int(checked.get("command_count"), 0)
    max_commands = _as_int(checked.get("max_commands"), 0)

    if readonly_only is not True:
        violations.append("policy_checked.checked_items.readonly_only is not true")

    if guard_all_readonly is not True:
        violations.append("policy_checked.checked_items.guard_all_readonly is not true")

    if max_commands and command_count > max_commands:
        violations.append(f"command_count exceeds max_commands: {command_count} > {max_commands}")

    return violations, warnings


def evaluate_execution_trace(session: dict[str, Any]) -> tuple[list[str], list[str]]:
    violations: list[str] = []
    warnings: list[str] = []

    executed = _find_stage(session, "executed")
    judged = _find_stage(session, "judged")

    if executed and not judged:
        warnings.append("executed stage exists but judged stage is missing")

    if judged and not executed:
        warnings.append("judged stage exists but executed stage is missing")

    if executed:
        details = executed.get("details") if isinstance(executed.get("details"), dict) else {}
        total = _as_int(details.get("total_commands"), 0)
        completed = _as_int(details.get("completed_commands"), 0)
        failed = _as_int(details.get("failed_commands"), 0)
        partial = _as_int(details.get("partial_commands"), 0)

        if total and completed + failed + partial > total:
            violations.append("command result counters exceed total_commands")

    return violations, warnings


def evaluate_investigation_session(session: dict[str, Any]) -> dict[str, Any]:
    violations: list[str] = []
    warnings: list[str] = []

    if not isinstance(session, dict):
        return {
            "verdict": "fail",
            "violations": ["session is not a dict"],
            "warnings": [],
            "summary": {},
        }

    if not safe_text(session.get("request_id")):
        violations.append("request_id is missing")

    violations.extend(validate_stage_order(session))

    for fn in [
        evaluate_v6_1_boundary,
        evaluate_safety_policy_trace,
        evaluate_execution_trace,
    ]:
        v, w = fn(session)
        violations.extend(v)
        warnings.extend(w)

    timeline = _timeline(session)
    summary = {
        "request_id": session.get("request_id"),
        "session_status": session.get("session_status"),
        "v6_stage": session.get("v6_stage"),
        "timeline_count": len(timeline),
        "stages": [item.get("stage") for item in timeline],
        "adaptive_enabled": (session.get("adaptive") or {}).get("enabled") if isinstance(session.get("adaptive"), dict) else None,
    }

    return {
        "verdict": "fail" if violations else "pass",
        "violations": violations,
        "warnings": warnings,
        "summary": summary,
    }


def evaluate_request_id(request_id: str, base_dir: str | Path = ".") -> dict[str, Any]:
    session, path = build_and_persist_investigation_session(request_id=request_id, base_dir=base_dir)
    result = evaluate_investigation_session(session)
    result["session_file"] = str(path)
    return result
