from __future__ import annotations

import json
from pathlib import Path
from typing import Any


RUNTIME_VERSION = "v6.4.0"

LOAD_LEVELS = [
    "metadata",
    "instructions",
    "commands",
    "evidence",
    "schema",
]


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _parse_frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---"):
        return {}

    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}

    raw = parts[1]
    result: dict[str, str] = {}

    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue

        key, value = line.split(":", 1)
        result[key.strip()] = value.strip().strip('"').strip("'")

    return result


def _skill_root(base_dir: str | Path = ".") -> Path:
    return Path(base_dir) / "skills"


def _skill_dir(skill_name: str, base_dir: str | Path = ".") -> Path:
    return _skill_root(base_dir) / skill_name


def list_skill_metadata(base_dir: str | Path = ".") -> list[dict[str, Any]]:
    root = _skill_root(base_dir)
    if not root.exists():
        return []

    result: list[dict[str, Any]] = []

    for path in sorted(root.iterdir()):
        if not path.is_dir():
            continue

        skill_md = path / "SKILL.md"
        if not skill_md.exists():
            continue

        text = _read_text(skill_md)
        meta = _parse_frontmatter(text)

        result.append({
            "name": meta.get("name") or path.name,
            "version": meta.get("version", ""),
            "family": meta.get("family", ""),
            "description": meta.get("description", ""),
            "risk_level": meta.get("risk_level", ""),
            "stage": meta.get("stage", ""),
            "path": str(path),
            "load_level": "metadata",
            "runtime_version": RUNTIME_VERSION,
        })

    return result


def build_skill_index(base_dir: str | Path = ".") -> dict[str, Any]:
    skills = list_skill_metadata(base_dir)

    by_name = {}
    by_family = {}

    for item in skills:
        name = item.get("name")
        family = item.get("family")

        if name:
            by_name[name] = item

        if family:
            by_family[family] = item

    return {
        "runtime_version": RUNTIME_VERSION,
        "load_strategy": "progressive_loading",
        "levels": LOAD_LEVELS,
        "skill_count": len(skills),
        "skills": skills,
        "by_name": by_name,
        "by_family": by_family,
    }


def select_skill_metadata_by_family(family: str, base_dir: str | Path = ".") -> dict[str, Any] | None:
    family = _safe_text(family)
    if not family:
        return None

    index = build_skill_index(base_dir)
    item = index.get("by_family", {}).get(family)

    return item if isinstance(item, dict) else None


def load_skill_instructions(skill_name: str, base_dir: str | Path = ".") -> dict[str, Any]:
    path = _skill_dir(skill_name, base_dir)
    skill_md = path / "SKILL.md"

    if not skill_md.exists():
        raise FileNotFoundError(f"SKILL.md not found: {skill_md}")

    text = _read_text(skill_md)
    meta = _parse_frontmatter(text)

    return {
        "load_level": "instructions",
        "skill_name": meta.get("name") or skill_name,
        "runtime_version": RUNTIME_VERSION,
        "file": str(skill_md),
        "metadata": meta,
        "content": text,
    }


def load_skill_commands(skill_name: str, base_dir: str | Path = ".") -> dict[str, Any]:
    path = _skill_dir(skill_name, base_dir)
    commands_file = path / "commands.yaml"

    if not commands_file.exists():
        raise FileNotFoundError(f"commands.yaml not found: {commands_file}")

    return {
        "load_level": "commands",
        "skill_name": skill_name,
        "runtime_version": RUNTIME_VERSION,
        "file": str(commands_file),
        "content": _read_text(commands_file),
    }


def load_skill_evidence_rules(skill_name: str, base_dir: str | Path = ".") -> dict[str, Any]:
    path = _skill_dir(skill_name, base_dir)
    evidence_file = path / "evidence_rules.yaml"

    if not evidence_file.exists():
        raise FileNotFoundError(f"evidence_rules.yaml not found: {evidence_file}")

    return {
        "load_level": "evidence",
        "skill_name": skill_name,
        "runtime_version": RUNTIME_VERSION,
        "file": str(evidence_file),
        "content": _read_text(evidence_file),
    }


def load_skill_output_schema(skill_name: str, base_dir: str | Path = ".") -> dict[str, Any]:
    path = _skill_dir(skill_name, base_dir)
    schema_file = path / "output_schema.json"

    if not schema_file.exists():
        raise FileNotFoundError(f"output_schema.json not found: {schema_file}")

    data = json.loads(schema_file.read_text(encoding="utf-8"))

    return {
        "load_level": "schema",
        "skill_name": skill_name,
        "runtime_version": RUNTIME_VERSION,
        "file": str(schema_file),
        "schema": data,
    }


def load_skill_runtime_context(
    skill_name: str,
    base_dir: str | Path = ".",
    levels: list[str] | None = None,
) -> dict[str, Any]:
    levels = levels or ["metadata"]

    unknown = sorted(set(levels) - set(LOAD_LEVELS))
    if unknown:
        raise ValueError(f"unknown skill runtime levels: {unknown}")

    metadata = None
    for item in list_skill_metadata(base_dir):
        if item.get("name") == skill_name:
            metadata = item
            break

    if metadata is None:
        raise FileNotFoundError(f"skill not found: {skill_name}")

    context: dict[str, Any] = {
        "runtime_version": RUNTIME_VERSION,
        "load_strategy": "progressive_loading",
        "skill_name": skill_name,
        "loaded_levels": [],
        "metadata": metadata,
    }

    if "metadata" in levels:
        context["loaded_levels"].append("metadata")

    if "instructions" in levels:
        context["instructions"] = load_skill_instructions(skill_name, base_dir)
        context["loaded_levels"].append("instructions")

    if "commands" in levels:
        context["commands"] = load_skill_commands(skill_name, base_dir)
        context["loaded_levels"].append("commands")

    if "evidence" in levels:
        context["evidence"] = load_skill_evidence_rules(skill_name, base_dir)
        context["loaded_levels"].append("evidence")

    if "schema" in levels:
        context["schema"] = load_skill_output_schema(skill_name, base_dir)
        context["loaded_levels"].append("schema")

    return context


def build_runtime_context_for_family(
    family: str,
    base_dir: str | Path = ".",
    levels: list[str] | None = None,
) -> dict[str, Any]:
    metadata = select_skill_metadata_by_family(family, base_dir)

    if not metadata:
        return {
            "runtime_version": RUNTIME_VERSION,
            "load_strategy": "progressive_loading",
            "matched": False,
            "family": family,
            "reason": "no_skill_matched_for_family",
            "loaded_levels": [],
        }

    context = load_skill_runtime_context(
        skill_name=metadata["name"],
        base_dir=base_dir,
        levels=levels or ["metadata"],
    )

    context["matched"] = True
    context["family"] = family
    context["reason"] = "matched_by_family"
    return context


def validate_skill_runtime(base_dir: str | Path = ".") -> dict[str, Any]:
    violations: list[str] = []
    warnings: list[str] = []

    index = build_skill_index(base_dir)

    if index.get("skill_count", 0) <= 0:
        violations.append("no skills found")

    for item in index.get("skills", []):
        name = item.get("name")
        family = item.get("family")

        if not name:
            violations.append("skill metadata missing name")

        if not family:
            violations.append(f"{name}: skill metadata missing family")

        if item.get("risk_level") != "readonly":
            violations.append(f"{name}: risk_level must be readonly")

        if item.get("stage") not in {"v6.3", "v6.4"}:
            warnings.append(f"{name}: unexpected stage {item.get('stage')}")

        try:
            load_skill_runtime_context(
                name,
                base_dir,
                levels=["metadata", "instructions", "commands", "evidence", "schema"],
            )
        except Exception as exc:
            violations.append(f"{name}: full runtime load failed: {exc}")

    return {
        "verdict": "fail" if violations else "pass",
        "runtime_version": RUNTIME_VERSION,
        "load_strategy": "progressive_loading",
        "skill_count": index.get("skill_count", 0),
        "violations": violations,
        "warnings": warnings,
        "index": index,
    }
