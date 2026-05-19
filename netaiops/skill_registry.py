from __future__ import annotations

import json
from pathlib import Path
from typing import Any


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

    return sorted([p for p in root.iterdir() if p.is_dir() and (p / "SKILL.md").exists()])


def load_skill(skill_name: str, base_dir: str | Path = ".") -> dict[str, Any]:
    path = skill_dir(base_dir, skill_name)
    skill_md = path / "SKILL.md"

    if not skill_md.exists():
        raise FileNotFoundError(f"SKILL.md not found for skill: {skill_name}")

    text = _read_text(skill_md)
    meta = _parse_frontmatter(text)

    result = {
        "name": meta.get("name") or skill_name,
        "version": meta.get("version", ""),
        "family": meta.get("family", ""),
        "description": meta.get("description", ""),
        "risk_level": meta.get("risk_level", ""),
        "stage": meta.get("stage", ""),
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
        result["output_schema"] = json.loads(output_schema_file.read_text(encoding="utf-8"))

    return result


def list_skills(base_dir: str | Path = ".") -> list[dict[str, Any]]:
    result = []
    for path in list_skill_dirs(base_dir):
        result.append(load_skill(path.name, base_dir))
    return result


def get_skill_by_family(family: str, base_dir: str | Path = ".") -> dict[str, Any] | None:
    for skill in list_skills(base_dir):
        if skill.get("family") == family:
            return skill
    return None


def validate_skill_package(skill_name: str, base_dir: str | Path = ".") -> dict[str, Any]:
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

    meta = {}
    if (path / "SKILL.md").exists():
        text = _read_text(path / "SKILL.md")
        meta = _parse_frontmatter(text)

        for key in ["name", "version", "family", "description", "risk_level", "stage"]:
            if not _safe_text(meta.get(key)):
                violations.append(f"SKILL.md frontmatter missing: {key}")

        if meta.get("risk_level") != "readonly":
            violations.append("risk_level must be readonly")

        if meta.get("stage") != "v6.3":
            violations.append("stage must be v6.3")

    if (path / "commands.yaml").exists():
        text = _read_text(path / "commands.yaml")
        for token in ["allowed_tools", "allowed_capabilities", "platform_commands", "readonly_only"]:
            if token not in text:
                violations.append(f"commands.yaml missing token: {token}")

        forbidden_tokens = ["configure terminal", "shutdown", "clear counters", "reload"]
        for token in forbidden_tokens:
            if token not in text:
                warnings.append(f"commands.yaml forbidden_patterns does not mention: {token}")

    if (path / "evidence_rules.yaml").exists():
        text = _read_text(path / "evidence_rules.yaml")
        for token in ["required_facts", "preferred_facts", "manual_review_conditions"]:
            if token not in text:
                violations.append(f"evidence_rules.yaml missing token: {token}")

    if (path / "output_schema.json").exists():
        try:
            schema = json.loads((path / "output_schema.json").read_text(encoding="utf-8"))
            if schema.get("skill_name") != skill_name:
                violations.append("output_schema.json skill_name mismatch")
            if not isinstance(schema.get("facts"), dict):
                violations.append("output_schema.json facts must be object")
        except Exception as exc:
            violations.append(f"output_schema.json invalid json: {exc}")

    return {
        "skill_name": skill_name,
        "verdict": "fail" if violations else "pass",
        "violations": violations,
        "warnings": warnings,
        "metadata": meta,
        "path": str(path),
    }


def validate_all_skills(base_dir: str | Path = ".") -> dict[str, Any]:
    skill_paths = list_skill_dirs(base_dir)
    results = [validate_skill_package(path.name, base_dir) for path in skill_paths]

    violations = []
    warnings = []

    for item in results:
        for v in item.get("violations", []):
            violations.append(f"{item.get('skill_name')}: {v}")
        for w in item.get("warnings", []):
            warnings.append(f"{item.get('skill_name')}: {w}")

    return {
        "verdict": "fail" if violations else "pass",
        "skill_count": len(results),
        "violations": violations,
        "warnings": warnings,
        "skills": results,
    }
