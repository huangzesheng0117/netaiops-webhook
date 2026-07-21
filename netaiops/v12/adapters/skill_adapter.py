"""Deterministic read-only adapter for the current Skill Registry."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from netaiops.skill_registry import (
    get_skill_by_family,
    validate_skill_package,
)
from netaiops.skill_schema_adapter import (
    load_yaml_mapping,
    normalize_evidence_document,
)


@dataclass(frozen=True, slots=True)
class SkillResolution:
    matched: bool
    family: str
    skill_name: str | None
    stage: str | None
    schema_generation: str | None
    risk_level: str | None
    validation_verdict: str
    required_facts: tuple[str, ...]
    preferred_facts: tuple[str, ...]
    manual_review_conditions: tuple[str, ...]
    warnings: tuple[str, ...]

    def public_dict(self) -> dict[str, Any]:
        return {
            "matched": self.matched,
            "family": self.family,
            "skill_name": self.skill_name,
            "stage": self.stage,
            "schema_generation": self.schema_generation,
            "risk_level": self.risk_level,
            "validation_verdict": self.validation_verdict,
            "required_facts": list(self.required_facts),
            "preferred_facts": list(self.preferred_facts),
            "manual_review_conditions": list(self.manual_review_conditions),
            "warnings": list(self.warnings),
        }


def _strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    output: list[str] = []
    for item in value:
        text = str(item).strip()
        if text and text not in output:
            output.append(text[:512])
    return tuple(output)


class SkillAdapter:
    """Resolve Skill evidence metadata without exposing command templates."""

    def __init__(self, base_dir: str | Path = "/opt/netaiops-webhook") -> None:
        self.base_dir = Path(base_dir)

    def resolve(self, family: str) -> SkillResolution:
        family_name = str(family or "").strip()
        skill = get_skill_by_family(family_name, self.base_dir)
        if not skill:
            return SkillResolution(
                matched=False,
                family=family_name,
                skill_name=None,
                stage=None,
                schema_generation=None,
                risk_level=None,
                validation_verdict="not_found",
                required_facts=(),
                preferred_facts=(),
                manual_review_conditions=(),
                warnings=("skill_not_found",),
            )

        skill_name = str(skill.get("name") or "").strip()
        validation = validate_skill_package(skill_name, self.base_dir)
        evidence_normalized: Mapping[str, Any] = MappingProxyType({})
        evidence_path = (
            Path(str(skill.get("files", {}).get("evidence_rules.yaml")))
            if skill.get("files", {}).get("evidence_rules.yaml")
            else None
        )
        warnings = [
            str(item)[:512]
            for item in validation.get("warnings", [])
            if str(item).strip()
        ]
        warnings.extend(
            str(item)[:512]
            for item in validation.get("violations", [])
            if str(item).strip()
        )

        if evidence_path is not None and evidence_path.is_file():
            try:
                document = load_yaml_mapping(evidence_path)
                evidence_normalized = MappingProxyType(
                    normalize_evidence_document(document)
                )
            except Exception as exc:
                warnings.append(
                    f"evidence_rules_invalid:{type(exc).__name__}"
                )

        metadata = skill.get("metadata", {}) or {}
        return SkillResolution(
            matched=True,
            family=family_name,
            skill_name=skill_name or None,
            stage=str(skill.get("stage") or "").strip() or None,
            schema_generation=(
                str(skill.get("schema_generation") or "").strip() or None
            ),
            risk_level=str(metadata.get("risk_level") or "").strip() or None,
            validation_verdict=str(
                validation.get("verdict") or "unknown"
            ).strip(),
            required_facts=_strings(
                evidence_normalized.get("required_facts", [])
            ),
            preferred_facts=_strings(
                evidence_normalized.get("preferred_facts", [])
            ),
            manual_review_conditions=_strings(
                evidence_normalized.get("manual_review_conditions", [])
            ),
            warnings=tuple(dict.fromkeys(warnings)),
        )
