from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from netaiops.adaptive_evidence_policy import (
    ADAPTIVE_MODE,
    ADAPTIVE_STAGE,
    load_adaptive_skill_constraints,
    normalize_cli_command,
    validate_adaptive_plan,
)
from netaiops.investigation_state import (
    build_and_persist_investigation_session,
    find_request_files,
    safe_read_json,
    unwrap_execution,
    unwrap_review,
)


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [_safe_text(x) for x in value if _safe_text(x)]
    text = _safe_text(value)
    return [text] if text else []


def _facts_from_review(review_data: dict[str, Any]) -> dict[str, Any]:
    es = review_data.get("evidence_summary") if isinstance(review_data.get("evidence_summary"), dict) else {}
    facts = es.get("facts") if isinstance(es.get("facts"), dict) else {}
    return facts


def _fact_present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str) and not value.strip():
        return False
    return True


def _target_interfaces(session: dict[str, Any]) -> list[str]:
    target_scope = session.get("target_scope") if isinstance(session.get("target_scope"), dict) else {}
    result = []

    for value in _as_list(target_scope.get("interfaces")):
        result.append(value)

    for value in _as_list(target_scope.get("interface")):
        result.append(value)

    dedup = []
    seen = set()
    for item in result:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            dedup.append(item)

    return dedup


def _platform_from_session(session: dict[str, Any], constraints: dict[str, Any]) -> str:
    target_scope = session.get("target_scope") if isinstance(session.get("target_scope"), dict) else {}
    platform = _safe_text(target_scope.get("platform"))

    if platform:
        return platform

    platforms = list((constraints.get("platform_commands") or {}).keys())
    if "cisco_iosxe" in platforms:
        return "cisco_iosxe"

    return platforms[0] if platforms else ""


def _existing_commands(execution_data: dict[str, Any]) -> set[str]:
    result = set()

    for item in execution_data.get("command_results", []) or []:
        if not isinstance(item, dict):
            continue
        command = _safe_text(item.get("command"))
        if command:
            result.add(normalize_cli_command(command))

    return result


def _missing_required_facts(facts: dict[str, Any], constraints: dict[str, Any]) -> list[str]:
    missing = []

    for name in constraints.get("required_facts", []) or []:
        if not _fact_present(facts.get(name)):
            missing.append(name)

    return missing


def _missing_preferred_facts(facts: dict[str, Any], constraints: dict[str, Any]) -> list[str]:
    missing = []

    for name in constraints.get("preferred_facts", []) or []:
        if not _fact_present(facts.get(name)):
            missing.append(name)

    return missing


def _capabilities_for_gaps(required_missing: list[str], preferred_missing: list[str]) -> list[str]:
    result = []

    status_or_rate = {
        "interface",
        "admin_status",
        "oper_status",
        "bandwidth_bps",
        "input_rate_bps",
        "output_rate_bps",
        "input_utilization_percent_estimated",
        "output_utilization_percent_estimated",
    }

    counters = {
        "crc",
        "fcs_err",
        "input_errors",
        "rcv_err",
        "xmit_err",
        "out_discards",
        "output_discards",
        "output_errors",
        "output_drops",
        "runts",
    }

    aggregation = {
        "channel_group_count",
        "port_channel_count",
        "etherchannel_member_count",
        "etherchannel_bundled_member_count",
        "etherchannel_down_member_count",
    }

    gaps = set(required_missing) | set(preferred_missing)

    if gaps & status_or_rate:
        result.append("show_interface_detail")

    if gaps & counters:
        result.append("show_interface_error_counters")

    if gaps & aggregation:
        result.append("show_interface_aggregation")

    return result


def _render_candidate(
    capability: str,
    platform: str,
    interface: str,
    constraints: dict[str, Any],
    reason: str,
) -> dict[str, Any] | None:
    platform_commands = constraints.get("platform_commands") or {}
    cap_spec = (platform_commands.get(platform) or {}).get(capability)

    if not cap_spec:
        return None

    template = _safe_text(cap_spec.get("template"))
    if not template:
        return None

    if "{interface}" in template and not interface:
        return None

    command = template.replace("{interface}", interface)

    return {
        "stage": ADAPTIVE_STAGE,
        "tool_name": "mcp_netmiko_run_show",
        "capability": capability,
        "platform": platform,
        "interface": interface,
        "command": command,
        "parser": cap_spec.get("parser", ""),
        "readonly": cap_spec.get("readonly", True),
        "reason": reason,
        "dispatch_status": "not_dispatched_dry_run",
    }


def build_adaptive_evidence_plan(
    session: dict[str, Any],
    execution_data: dict[str, Any] | None = None,
    review_data: dict[str, Any] | None = None,
    base_dir: str | Path = ".",
) -> dict[str, Any]:
    execution_data = execution_data or {}
    review_data = review_data or {}

    skill_context = session.get("skill_context") if isinstance(session.get("skill_context"), dict) else {}
    skill_name = _safe_text(skill_context.get("skill_name"))
    family = _safe_text(skill_context.get("family"))

    plan: dict[str, Any] = {
        "stage": ADAPTIVE_STAGE,
        "mode": ADAPTIVE_MODE,
        "request_id": session.get("request_id", ""),
        "family": family,
        "skill_name": skill_name,
        "matched_skill": bool(skill_name),
        "extra_round": 1,
        "dispatch_enabled": False,
        "dispatch_reason": "v6.5_batch1_dry_run_only",
        "candidates": [],
        "gaps": {
            "required_missing": [],
            "preferred_missing": [],
        },
        "policy_result": {},
    }

    if not skill_name:
        plan["policy_result"] = {
            "verdict": "fail",
            "violations": ["skill_name missing from session.skill_context"],
            "warnings": [],
        }
        return plan

    constraints = load_adaptive_skill_constraints(skill_name, base_dir)
    facts = _facts_from_review(review_data)

    required_missing = _missing_required_facts(facts, constraints)
    preferred_missing = _missing_preferred_facts(facts, constraints)

    plan["gaps"] = {
        "required_missing": required_missing,
        "preferred_missing": preferred_missing,
    }

    platform = _platform_from_session(session, constraints)
    interfaces = _target_interfaces(session)
    if not interfaces:
        interfaces = [""]

    existing = _existing_commands(execution_data)
    wanted_capabilities = _capabilities_for_gaps(required_missing, preferred_missing)

    candidates = []
    seen_commands = set()

    for capability in wanted_capabilities:
        if capability == "show_interface_aggregation":
            item = _render_candidate(
                capability=capability,
                platform=platform,
                interface="",
                constraints=constraints,
                reason="missing_aggregation_facts",
            )
            items = [item] if item else []
        else:
            items = []
            for interface in interfaces:
                reason = "missing_required_facts" if required_missing else "missing_preferred_facts"
                item = _render_candidate(
                    capability=capability,
                    platform=platform,
                    interface=interface,
                    constraints=constraints,
                    reason=reason,
                )
                if item:
                    items.append(item)

        for item in items:
            command_key = normalize_cli_command(item["command"])
            if command_key in existing:
                continue
            if command_key in seen_commands:
                continue
            seen_commands.add(command_key)
            candidates.append(item)

    max_extra = constraints.get("limits", {}).get("max_extra_commands", 3)
    plan["candidates"] = candidates[:max_extra]
    plan["suppressed_candidates"] = candidates[max_extra:]
    plan["candidate_count"] = len(plan["candidates"])
    plan["suppressed_candidate_count"] = len(plan["suppressed_candidates"])
    plan["limits"] = constraints.get("limits", {})
    plan["policy_result"] = validate_adaptive_plan(plan, constraints)

    return plan


def build_adaptive_evidence_plan_for_request(
    request_id: str,
    base_dir: str | Path = ".",
    write: bool = False,
) -> dict[str, Any]:
    base_dir = Path(base_dir)

    session, session_file = build_and_persist_investigation_session(request_id, base_dir)
    files = find_request_files(base_dir, request_id)

    execution_file = files.get("execution")
    review_file = files.get("review")

    execution_data = unwrap_execution(safe_read_json(Path(execution_file))) if execution_file else {}
    review_data = unwrap_review(safe_read_json(Path(review_file))) if review_file else {}

    plan = build_adaptive_evidence_plan(
        session=session,
        execution_data=execution_data,
        review_data=review_data,
        base_dir=base_dir,
    )

    plan["session_file"] = str(session_file)
    plan["execution_file"] = execution_file
    plan["review_file"] = review_file

    if write:
        out_dir = base_dir / "data" / "adaptive_plans"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{request_id}.adaptive.plan.json"
        out_file.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
        plan["adaptive_plan_file"] = str(out_file)

    return plan
