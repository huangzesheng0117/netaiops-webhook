from __future__ import annotations

from pathlib import Path
from typing import Any

from netaiops.skill_runtime import build_runtime_context_for_family


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def infer_family_for_runtime(session: dict[str, Any]) -> str:
    skill_context = session.get("skill_context") if isinstance(session.get("skill_context"), dict) else {}
    family = _safe_text(skill_context.get("family"))
    if family:
        return family

    for key in ["classification", "family_result", "target_scope"]:
        value = session.get(key)
        if isinstance(value, dict):
            for subkey in ["family", "alert_family", "classification_family"]:
                family = _safe_text(value.get(subkey))
                if family:
                    return family

    for item in session.get("timeline", []) or []:
        if not isinstance(item, dict):
            continue
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        family = _safe_text(details.get("family") or details.get("alert_family"))
        if family:
            return family

    return ""


def compact_runtime_context(context: dict[str, Any]) -> dict[str, Any]:
    metadata = context.get("metadata") if isinstance(context.get("metadata"), dict) else {}

    compact: dict[str, Any] = {
        "enabled": True,
        "stage": "v6.4",
        "runtime_version": context.get("runtime_version", ""),
        "load_strategy": context.get("load_strategy", ""),
        "matched": context.get("matched", False),
        "family": context.get("family", ""),
        "skill_name": context.get("skill_name", ""),
        "reason": context.get("reason", ""),
        "loaded_levels": context.get("loaded_levels", []),
        "metadata": metadata,
        "content_embedded": False,
        "content_policy": "metadata_only_in_investigation_session",
        "loaded_files": {},
    }

    for section in ["instructions", "commands", "evidence", "schema"]:
        value = context.get(section)
        if isinstance(value, dict):
            compact["loaded_files"][section] = value.get("file", "")

    return compact


def build_skill_runtime_context_for_session(
    session: dict[str, Any],
    base_dir: str | Path = ".",
    levels: list[str] | None = None,
) -> dict[str, Any]:
    family = infer_family_for_runtime(session)

    if not family:
        return {
            "enabled": True,
            "stage": "v6.4",
            "runtime_version": "v6.4.0",
            "load_strategy": "progressive_loading",
            "matched": False,
            "family": "",
            "skill_name": "",
            "reason": "family_missing",
            "loaded_levels": [],
            "metadata": {},
            "content_embedded": False,
            "content_policy": "metadata_only_in_investigation_session",
            "loaded_files": {},
        }

    context = build_runtime_context_for_family(
        family=family,
        base_dir=base_dir,
        levels=levels or ["metadata"],
    )

    return compact_runtime_context(context)


def attach_skill_runtime_context_to_session(
    session: dict[str, Any],
    base_dir: str | Path = ".",
    levels: list[str] | None = None,
) -> dict[str, Any]:
    session = dict(session or {})
    session["skill_runtime_context"] = build_skill_runtime_context_for_session(
        session=session,
        base_dir=base_dir,
        levels=levels or ["metadata"],
    )
    return session
