from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from netaiops.adaptive_evidence_planner import build_adaptive_evidence_plan
from netaiops.investigation_state import find_request_files, safe_read_json, unwrap_execution, unwrap_review


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _read_execution_review_for_session(
    session: dict[str, Any],
    base_dir: str | Path = ".",
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
    base = Path(base_dir)
    request_id = _safe_text(session.get("request_id"))

    files = find_request_files(base, request_id) if request_id else {}

    execution_file = files.get("execution")
    review_file = files.get("review")

    execution_data = unwrap_execution(safe_read_json(Path(execution_file))) if execution_file else {}
    review_data = unwrap_review(safe_read_json(Path(review_file))) if review_file else {}

    return execution_data, review_data, {
        "execution_file": execution_file or "",
        "review_file": review_file or "",
    }


def compact_adaptive_plan(plan: dict[str, Any]) -> dict[str, Any]:
    policy = plan.get("policy_result") if isinstance(plan.get("policy_result"), dict) else {}
    limits = plan.get("limits") if isinstance(plan.get("limits"), dict) else {}

    return {
        "enabled": True,
        "stage": "v6.5",
        "mode": plan.get("mode", ""),
        "request_id": plan.get("request_id", ""),
        "family": plan.get("family", ""),
        "skill_name": plan.get("skill_name", ""),
        "matched_skill": plan.get("matched_skill", False),
        "extra_round": plan.get("extra_round", 0),
        "dispatch_enabled": plan.get("dispatch_enabled", False),
        "dispatch_reason": plan.get("dispatch_reason", ""),
        "adaptive_execution_enabled": limits.get("adaptive_execution_enabled", False),
        "readonly_only": limits.get("readonly_only", True),
        "max_extra_rounds": limits.get("max_extra_rounds"),
        "max_extra_commands": limits.get("max_extra_commands"),
        "candidate_count": plan.get("candidate_count", 0),
        "suppressed_candidate_count": plan.get("suppressed_candidate_count", 0),
        "gaps": plan.get("gaps", {}),
        "policy_verdict": policy.get("verdict", ""),
        "policy_violations": policy.get("violations", []),
        "policy_warnings": policy.get("warnings", []),
        "candidates": plan.get("candidates", []),
        "suppressed_candidates": plan.get("suppressed_candidates", []),
        "adaptive_plan_file": plan.get("adaptive_plan_file", ""),
        "session_file": plan.get("session_file", ""),
        "execution_file": plan.get("execution_file", ""),
        "review_file": plan.get("review_file", ""),
    }


def build_adaptive_evidence_context_for_session(
    session: dict[str, Any],
    base_dir: str | Path = ".",
    execution_data: dict[str, Any] | None = None,
    review_data: dict[str, Any] | None = None,
    write_plan_file: bool = False,
) -> dict[str, Any]:
    session = session or {}
    base = Path(base_dir)
    request_id = _safe_text(session.get("request_id"))

    file_info = {
        "execution_file": "",
        "review_file": "",
    }

    if execution_data is None or review_data is None:
        loaded_execution, loaded_review, file_info = _read_execution_review_for_session(session, base)
        execution_data = loaded_execution if execution_data is None else execution_data
        review_data = loaded_review if review_data is None else review_data

    plan = build_adaptive_evidence_plan(
        session=session,
        execution_data=execution_data or {},
        review_data=review_data or {},
        base_dir=base,
    )

    plan["session_file"] = str(base / "data" / "investigation" / f"{request_id}.investigation.session.json") if request_id else ""
    plan["execution_file"] = file_info.get("execution_file", "")
    plan["review_file"] = file_info.get("review_file", "")

    if write_plan_file and request_id:
        out_dir = base / "data" / "adaptive_plans"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{request_id}.adaptive.plan.json"
        out_file.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
        plan["adaptive_plan_file"] = str(out_file)

    return compact_adaptive_plan(plan)


def attach_adaptive_evidence_context_to_session(
    session: dict[str, Any],
    base_dir: str | Path = ".",
) -> dict[str, Any]:
    session = dict(session or {})
    session["adaptive_evidence_context"] = build_adaptive_evidence_context_for_session(
        session=session,
        base_dir=base_dir,
        write_plan_file=False,
    )
    return session
