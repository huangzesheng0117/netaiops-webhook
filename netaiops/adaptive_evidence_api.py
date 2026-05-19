from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from netaiops.adaptive_evidence_planner import (
    build_adaptive_evidence_plan,
    build_adaptive_evidence_plan_for_request,
)


EXPECTED_MISSING_FACTS_COMMANDS = {
    "show interfaces TenGigabitEthernet1/0/1",
    "show interfaces TenGigabitEthernet1/0/1 counters errors",
    "show etherchannel summary",
}


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _policy_verdict(plan: dict[str, Any]) -> str:
    policy = plan.get("policy_result") if isinstance(plan.get("policy_result"), dict) else {}
    return str(policy.get("verdict", ""))


def _policy_violations(plan: dict[str, Any]) -> list[str]:
    policy = plan.get("policy_result") if isinstance(plan.get("policy_result"), dict) else {}
    violations = policy.get("violations")
    return violations if isinstance(violations, list) else []


def _policy_warnings(plan: dict[str, Any]) -> list[str]:
    policy = plan.get("policy_result") if isinstance(plan.get("policy_result"), dict) else {}
    warnings = policy.get("warnings")
    return warnings if isinstance(warnings, list) else []


def compact_adaptive_plan_for_api(plan: dict[str, Any], include_candidates: bool = True) -> dict[str, Any]:
    candidates = plan.get("candidates") if isinstance(plan.get("candidates"), list) else []
    suppressed = plan.get("suppressed_candidates") if isinstance(plan.get("suppressed_candidates"), list) else []

    result: dict[str, Any] = {
        "stage": plan.get("stage"),
        "mode": plan.get("mode"),
        "request_id": plan.get("request_id"),
        "family": plan.get("family"),
        "skill_name": plan.get("skill_name"),
        "matched_skill": plan.get("matched_skill"),
        "extra_round": plan.get("extra_round"),
        "dispatch_enabled": plan.get("dispatch_enabled"),
        "dispatch_reason": plan.get("dispatch_reason"),
        "candidate_count": plan.get("candidate_count", len(candidates)),
        "suppressed_candidate_count": plan.get("suppressed_candidate_count", len(suppressed)),
        "gaps": plan.get("gaps", {}),
        "limits": plan.get("limits", {}),
        "policy_verdict": _policy_verdict(plan),
        "policy_violations": _policy_violations(plan),
        "policy_warnings": _policy_warnings(plan),
        "session_file": plan.get("session_file", ""),
        "execution_file": plan.get("execution_file", ""),
        "review_file": plan.get("review_file", ""),
        "adaptive_plan_file": plan.get("adaptive_plan_file", ""),
        "dry_run_only": True,
        "readonly_only": True,
        "api_note": "v6.5 adaptive evidence API only returns dry-run plans and never dispatches commands.",
    }

    if include_candidates:
        result["candidates"] = candidates
        result["suppressed_candidates"] = suppressed
        result["commands"] = [
            item.get("command")
            for item in candidates
            if isinstance(item, dict) and item.get("command")
        ]

    return result


def build_adaptive_plan_response(
    request_id: str,
    base_dir: str | Path = ".",
    include_candidates: bool = True,
) -> dict[str, Any]:
    plan = build_adaptive_evidence_plan_for_request(
        request_id=request_id,
        base_dir=base_dir,
        write=False,
    )

    compact = compact_adaptive_plan_for_api(plan, include_candidates=include_candidates)

    return {
        "status": "ok" if compact.get("policy_verdict") == "pass" else "fail",
        "stage": "v6.5_adaptive_plan",
        "request_id": request_id,
        "adaptive_plan": compact,
    }


def build_missing_facts_simulation_response(
    base_dir: str | Path = ".",
    include_candidates: bool = True,
    strict: bool = True,
) -> dict[str, Any]:
    base = Path(base_dir)
    fixture_dir = base / "tests" / "fixtures" / "adaptive_missing_facts"

    session = _load_json(fixture_dir / "session.missing_facts.json")
    execution_data = _load_json(fixture_dir / "execution.empty.json")
    review_data = _load_json(fixture_dir / "review.missing_facts.json")

    plan = build_adaptive_evidence_plan(
        session=session,
        execution_data=execution_data,
        review_data=review_data,
        base_dir=base,
    )

    compact = compact_adaptive_plan_for_api(plan, include_candidates=include_candidates)
    commands = set(compact.get("commands") or [])

    validation_errors = []

    if strict:
        missing = sorted(EXPECTED_MISSING_FACTS_COMMANDS - commands)
        if missing:
            validation_errors.append("expected commands missing: " + ",".join(missing))

        for item in compact.get("candidates", []) or []:
            if not isinstance(item, dict):
                continue
            if item.get("dispatch_status") != "not_dispatched_dry_run":
                validation_errors.append("candidate is not dry-run: " + str(item.get("command")))
            if item.get("readonly") is not True:
                validation_errors.append("candidate is not readonly: " + str(item.get("command")))

    if compact.get("policy_verdict") != "pass":
        validation_errors.append("policy_verdict is not pass")

    if compact.get("policy_violations"):
        validation_errors.append("policy_violations is not empty")

    if compact.get("dispatch_enabled") is not False:
        validation_errors.append("dispatch_enabled must be false")

    if compact.get("candidate_count", 0) <= 0:
        validation_errors.append("candidate_count should be greater than 0")

    return {
        "status": "ok" if not validation_errors else "fail",
        "stage": "v6.5_adaptive_missing_facts_simulation",
        "strict": strict,
        "validation_errors": validation_errors,
        "adaptive_plan": compact,
    }
