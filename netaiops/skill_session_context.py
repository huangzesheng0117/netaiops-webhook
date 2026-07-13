from __future__ import annotations

from pathlib import Path
from typing import Any

from netaiops.skill_registry import get_skill_by_family
from netaiops.skill_binding_validator import load_skill_binding_graph, validate_skill_binding


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def infer_family_from_session(session: dict[str, Any]) -> str:
    candidates = []

    for key in ["classification", "family_result", "target_scope"]:
        value = session.get(key)
        if isinstance(value, dict):
            candidates.extend([
                value.get("family"),
                value.get("alert_family"),
                value.get("classification_family"),
            ])

    candidates.extend([
        session.get("family"),
        session.get("alert_family"),
    ])

    for item in session.get("timeline", []) or []:
        if not isinstance(item, dict):
            continue
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        candidates.extend([
            details.get("family"),
            details.get("alert_family"),
        ])

    for value in candidates:
        text = _safe_text(value)
        if text:
            return text

    return ""


def build_skill_context_for_session(session: dict[str, Any], base_dir: str | Path = ".") -> dict[str, Any]:
    family = infer_family_from_session(session)

    context: dict[str, Any] = {
        "enabled": True,
        "stage": "v6.3",
        "matched": False,
        "family": family,
        "skill_name": "",
        "skill_version": "",
        "risk_level": "",
        "binding_verdict": "",
        "allowed_tools": [],
        "allowed_capabilities": [],
        "parsers": [],
        "platforms": [],
        "warnings": [],
        "violations": [],
        "reason": "",
    }

    if not family:
        context["reason"] = "family_missing"
        return context

    skill = get_skill_by_family(family, base_dir)
    if not skill:
        context["reason"] = "no_skill_matched_for_family"
        return context

    skill_name = skill.get("name")
    graph = load_skill_binding_graph(skill_name, base_dir)
    validation = validate_skill_binding(skill_name, base_dir)

    context.update({
        "matched": True,
        "reason": "matched_by_family",
        "stage": skill.get("stage", ""),
        "schema_generation": skill.get("schema_generation", ""),
        "skill_name": skill_name,
        "skill_version": skill.get("version", ""),
        "risk_level": skill.get("risk_level", ""),
        "binding_verdict": validation.get("verdict", ""),
        "allowed_tools": graph.get("allowed_tools", []),
        "allowed_capabilities": graph.get("allowed_capabilities", []),
        "parsers": graph.get("parsers", []),
        "platforms": graph.get("platforms", []),
        "registered_tools": graph.get("registered_tools", []),
        "enabled_tools": graph.get("enabled_tools", []),
        "registered_parsers": graph.get("registered_parsers", []),
        "missing_tools": graph.get("missing_tools", []),
        "disabled_tools": graph.get("disabled_tools", []),
        "missing_parsers": graph.get("missing_parsers", []),
        "unknown_capabilities": graph.get("unknown_capabilities", []),
        "family_known": graph.get("family_known"),
        "warnings": validation.get("warnings", []),
        "violations": validation.get("violations", []),
    })

    return context


def attach_skill_context_to_session(session: dict[str, Any], base_dir: str | Path = ".") -> dict[str, Any]:
    session = dict(session or {})
    session["skill_context"] = build_skill_context_for_session(session, base_dir)
    return session


def compact_skill_context(context: dict[str, Any]) -> dict[str, Any]:
    return {
        "stage": context.get("stage"),
        "schema_generation": context.get("schema_generation"),
        "matched": context.get("matched"),
        "family": context.get("family"),
        "skill_name": context.get("skill_name"),
        "skill_version": context.get("skill_version"),
        "risk_level": context.get("risk_level"),
        "binding_verdict": context.get("binding_verdict"),
        "allowed_tools": context.get("allowed_tools", []),
        "allowed_capabilities": context.get("allowed_capabilities", []),
        "parsers": context.get("parsers", []),
        "warnings": context.get("warnings", []),
        "violations": context.get("violations", []),
        "reason": context.get("reason", ""),
    }
