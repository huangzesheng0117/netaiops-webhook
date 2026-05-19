from __future__ import annotations

from pathlib import Path
from typing import Any

from netaiops.skill_runtime import (
    LOAD_LEVELS,
    build_runtime_context_for_family,
    build_skill_index,
    load_skill_runtime_context,
    validate_skill_runtime,
)


def parse_runtime_levels(levels: str | list[str] | None) -> list[str]:
    if levels is None:
        return ["metadata"]

    if isinstance(levels, str):
        items = [x.strip() for x in levels.split(",") if x.strip()]
    else:
        items = [str(x).strip() for x in levels if str(x).strip()]

    if not items:
        items = ["metadata"]

    allowed = set(LOAD_LEVELS)
    unknown = sorted(set(items) - allowed)
    if unknown:
        raise ValueError(f"unknown skill runtime levels: {unknown}; allowed={LOAD_LEVELS}")

    result = []
    seen = set()
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)

    return result


def _content_embedded(context: dict[str, Any]) -> bool:
    for key in ["instructions", "commands", "evidence"]:
        value = context.get(key)
        if isinstance(value, dict) and value.get("content"):
            return True

    schema = context.get("schema")
    if isinstance(schema, dict) and schema.get("schema"):
        return True

    return False


def _loaded_files(context: dict[str, Any]) -> dict[str, str]:
    result = {}

    for key in ["instructions", "commands", "evidence", "schema"]:
        value = context.get(key)
        if isinstance(value, dict) and value.get("file"):
            result[key] = value.get("file")

    return result


def _with_runtime_api_metadata(context: dict[str, Any]) -> dict[str, Any]:
    context = dict(context or {})
    context["runtime_api"] = {
        "stage": "v6.4",
        "api_version": "v6.4.0",
        "load_strategy": "progressive_loading",
        "content_embedded": _content_embedded(context),
        "loaded_files": _loaded_files(context),
    }
    return context


def build_runtime_index_response(base_dir: str | Path = ".") -> dict[str, Any]:
    index = build_skill_index(base_dir)
    return {
        "status": "ok",
        "stage": "v6.4_skill_runtime_index",
        "runtime_version": index.get("runtime_version"),
        "load_strategy": index.get("load_strategy"),
        "skill_count": index.get("skill_count"),
        "levels": index.get("levels"),
        "skills": index.get("skills"),
        "by_family": index.get("by_family"),
    }


def build_runtime_validate_response(base_dir: str | Path = ".") -> dict[str, Any]:
    result = validate_skill_runtime(base_dir)
    return {
        "status": "ok" if result.get("verdict") == "pass" else "fail",
        "stage": "v6.4_skill_runtime_validate",
        "result": result,
    }


def build_runtime_family_response(
    family: str,
    base_dir: str | Path = ".",
    levels: str | list[str] | None = "metadata",
) -> dict[str, Any]:
    parsed_levels = parse_runtime_levels(levels)
    context = build_runtime_context_for_family(
        family=family,
        base_dir=base_dir,
        levels=parsed_levels,
    )

    return {
        "status": "ok" if context.get("matched") else "not_found",
        "stage": "v6.4_skill_runtime_family",
        "family": family,
        "levels": parsed_levels,
        "runtime_context": _with_runtime_api_metadata(context),
    }


def build_runtime_skill_response(
    skill_name: str,
    base_dir: str | Path = ".",
    levels: str | list[str] | None = "metadata",
) -> dict[str, Any]:
    parsed_levels = parse_runtime_levels(levels)
    context = load_skill_runtime_context(
        skill_name=skill_name,
        base_dir=base_dir,
        levels=parsed_levels,
    )

    return {
        "status": "ok",
        "stage": "v6.4_skill_runtime_skill",
        "skill_name": skill_name,
        "levels": parsed_levels,
        "runtime_context": _with_runtime_api_metadata(context),
    }
