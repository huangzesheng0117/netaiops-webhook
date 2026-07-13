from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from netaiops.skill_schema_adapter import (
    SUPPORTED_SKILL_STAGES,
    load_yaml_mapping,
    normalize_commands_document,
    normalize_evidence_document,
    output_schema_facts,
    schema_generation,
)


REQUIRED_SKILL_FILES = [
    "SKILL.md",
    "commands.yaml",
    "evidence_rules.yaml",
    "output_schema.json",
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


def skill_dir(base_dir: str | Path, skill_name: str) -> Path:
    return Path(base_dir) / "skills" / skill_name


def list_skill_dirs(base_dir: str | Path = ".") -> list[Path]:
    root = Path(base_dir) / "skills"
    if not root.exists():
        return []

    return sorted(
        [p for p in root.iterdir() if p.is_dir() and (p / "SKILL.md").exists()]
    )


def load_skill(skill_name: str, base_dir: str | Path = ".") -> dict[str, Any]:
    path = skill_dir(base_dir, skill_name)
    skill_md = path / "SKILL.md"

    if not skill_md.exists():
        raise FileNotFoundError(f"SKILL.md not found for skill: {skill_name}")

    text = _read_text(skill_md)
    meta = _parse_frontmatter(text)
    stage = meta.get("stage", "")

    result = {
        "name": meta.get("name") or skill_name,
        "version": meta.get("version", ""),
        "family": meta.get("family", ""),
        "description": meta.get("description", ""),
        "risk_level": meta.get("risk_level", ""),
        "stage": stage,
        "schema_generation": schema_generation(stage),
        "path": str(path),
        "files": {
            name: str(path / name)
            for name in REQUIRED_SKILL_FILES
            if (path / name).exists()
        },
        "metadata": meta,
        "skill_md": text,
    }

    output_schema_file = path / "output_schema.json"
    if output_schema_file.exists():
        result["output_schema"] = json.loads(
            output_schema_file.read_text(encoding="utf-8")
        )

    return result


def list_skills(base_dir: str | Path = ".") -> list[dict[str, Any]]:
    return [load_skill(path.name, base_dir) for path in list_skill_dirs(base_dir)]


def get_skill_by_family(
    family: str,
    base_dir: str | Path = ".",
) -> dict[str, Any] | None:
    for skill in list_skills(base_dir):
        if skill.get("family") == family:
            return skill
    return None


def validate_skill_package(
    skill_name: str,
    base_dir: str | Path = ".",
) -> dict[str, Any]:
    path = skill_dir(base_dir, skill_name)
    violations: list[str] = []
    warnings: list[str] = []

    if not path.exists():
        return {
            "skill_name": skill_name,
            "verdict": "fail",
            "violations": [f"skill directory not found: {path}"],
            "warnings": [],
        }

    for filename in REQUIRED_SKILL_FILES:
        if not (path / filename).exists():
            violations.append(f"missing required file: {filename}")

    meta: dict[str, str] = {}
    stage = ""
    generation = "current"
    if (path / "SKILL.md").exists():
        text = _read_text(path / "SKILL.md")
        meta = _parse_frontmatter(text)
        stage = _safe_text(meta.get("stage"))
        generation = schema_generation(stage)

        for key in [
            "name",
            "version",
            "family",
            "description",
            "risk_level",
            "stage",
        ]:
            if not _safe_text(meta.get(key)):
                violations.append(f"SKILL.md frontmatter missing: {key}")

        if meta.get("name") and meta.get("name") != skill_name:
            violations.append("SKILL.md name mismatch")

        if meta.get("risk_level") != "readonly":
            violations.append("risk_level must be readonly")

        if stage and stage not in SUPPORTED_SKILL_STAGES:
            violations.append(f"unsupported skill stage: {stage}")

    commands_normalized: dict[str, Any] = {}
    if (path / "commands.yaml").exists():
        try:
            commands = load_yaml_mapping(path / "commands.yaml")
            commands_normalized = normalize_commands_document(commands)
        except Exception as exc:
            violations.append(f"commands.yaml invalid yaml: {exc}")
            commands = {}

        if _safe_text(commands.get("skill_name")) not in {"", skill_name}:
            violations.append("commands.yaml skill_name mismatch")
        if not commands_normalized.get("allowed_tools"):
            violations.append("commands.yaml allowed_tools is empty")
        if not commands_normalized.get("platforms"):
            violations.append("commands.yaml platform_commands is empty")
        if commands_normalized.get("readonly_only") is not True:
            violations.append("commands.yaml readonly_only must be true")
        if generation == "legacy" and not commands_normalized.get(
            "explicit_allowed_capabilities"
        ):
            violations.append(
                "legacy commands.yaml allowed_capabilities is empty"
            )
        non_readonly = [
            item.get("source_template") or item.get("template")
            for item in commands_normalized.get("entries", [])
            if item.get("readonly") is not True
        ]
        for template in non_readonly:
            violations.append(f"commands.yaml command is not readonly: {template}")

        forbidden_patterns = [
            _safe_text(item).lower()
            for item in commands_normalized.get("forbidden_patterns", [])
        ]
        for token in ["configure terminal", "shutdown", "reload"]:
            if not any(token in item for item in forbidden_patterns):
                warnings.append(
                    f"commands.yaml forbidden_patterns does not mention: {token}"
                )

    if (path / "evidence_rules.yaml").exists():
        try:
            evidence = load_yaml_mapping(path / "evidence_rules.yaml")
            evidence_normalized = normalize_evidence_document(evidence)
        except Exception as exc:
            violations.append(f"evidence_rules.yaml invalid yaml: {exc}")
            evidence = {}
            evidence_normalized = {}

        if _safe_text(evidence.get("skill_name")) not in {"", skill_name}:
            violations.append("evidence_rules.yaml skill_name mismatch")
        if not evidence_normalized.get("required_facts"):
            violations.append("evidence_rules.yaml required_facts is empty")
        if not evidence_normalized.get("preferred_facts"):
            violations.append("evidence_rules.yaml preferred_facts is empty")
        if generation == "legacy" and not evidence_normalized.get(
            "manual_review_conditions"
        ):
            violations.append(
                "legacy evidence_rules.yaml manual_review_conditions is empty"
            )

    if (path / "output_schema.json").exists():
        try:
            schema = json.loads(
                (path / "output_schema.json").read_text(encoding="utf-8")
            )
            if not isinstance(schema, dict):
                violations.append("output_schema.json root must be object")
            else:
                if schema.get("skill_name") != skill_name:
                    violations.append("output_schema.json skill_name mismatch")
                if not output_schema_facts(schema):
                    violations.append(
                        "output_schema.json must define facts or object properties"
                    )
        except Exception as exc:
            violations.append(f"output_schema.json invalid json: {exc}")

    return {
        "skill_name": skill_name,
        "verdict": "fail" if violations else "pass",
        "violations": violations,
        "warnings": warnings,
        "metadata": meta,
        "stage": stage,
        "schema_generation": generation,
        "command_schema_shapes": commands_normalized.get("schema_shapes", []),
        "path": str(path),
    }


def validate_all_skills(base_dir: str | Path = ".") -> dict[str, Any]:
    results = [
        validate_skill_package(path.name, base_dir)
        for path in list_skill_dirs(base_dir)
    ]

    violations: list[str] = []
    warnings: list[str] = []

    for item in results:
        for violation in item.get("violations", []):
            violations.append(f"{item.get('skill_name')}: {violation}")
        for warning in item.get("warnings", []):
            warnings.append(f"{item.get('skill_name')}: {warning}")

    return {
        "verdict": "fail" if violations else "pass",
        "skill_count": len(results),
        "violations": violations,
        "warnings": warnings,
        "skills": results,
    }
