"""Deterministic Playbook and Safety Policy adapter for v12 planning."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from netaiops.playbook_loader import find_best_playbook
from netaiops.policy_engine import evaluate_auto_confirm_policy


@dataclass(frozen=True, slots=True)
class PlaybookResolution:
    matched: bool
    playbook_id: str | None
    family: str | None
    skill_name: str | None
    readonly_only: bool
    auto_execute_allowed: bool
    max_commands: int
    command_template_count: int
    prometheus_evidence_enabled: bool
    prometheus_profile: str | None
    prometheus_query_names: tuple[str, ...]
    raw_playbook: Mapping[str, Any]

    def public_dict(self) -> dict[str, Any]:
        return {
            "matched": self.matched,
            "playbook_id": self.playbook_id,
            "family": self.family,
            "skill_name": self.skill_name,
            "readonly_only": self.readonly_only,
            "auto_execute_allowed": self.auto_execute_allowed,
            "max_commands": self.max_commands,
            "command_template_count": self.command_template_count,
            "prometheus_evidence_enabled": self.prometheus_evidence_enabled,
            "prometheus_profile": self.prometheus_profile,
            "prometheus_query_names": list(self.prometheus_query_names),
        }


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _string_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    output: list[str] = []
    for item in value:
        text = _text(item)
        if text and text not in output:
            output.append(text[:128])
    return tuple(output)


class PlaybookAdapter:
    """Select one existing Playbook without rendering or returning commands."""

    def resolve(
        self,
        event: Mapping[str, Any],
        classification: Mapping[str, Any],
    ) -> PlaybookResolution:
        playbook = find_best_playbook(dict(event), dict(classification))
        if not playbook:
            return PlaybookResolution(
                matched=False,
                playbook_id=None,
                family=None,
                skill_name=None,
                readonly_only=True,
                auto_execute_allowed=False,
                max_commands=0,
                command_template_count=0,
                prometheus_evidence_enabled=False,
                prometheus_profile=None,
                prometheus_query_names=(),
                raw_playbook=MappingProxyType({}),
            )

        execution = playbook.get("execution", {}) or {}
        command_templates = execution.get("commands", []) or []
        prometheus = playbook.get("prometheus_evidence_first", {}) or {}

        return PlaybookResolution(
            matched=True,
            playbook_id=_text(playbook.get("playbook_id")) or None,
            family=_text(playbook.get("family")) or None,
            skill_name=_text(playbook.get("skill_name")) or None,
            readonly_only=bool(execution.get("readonly_only", False)),
            auto_execute_allowed=bool(
                execution.get("auto_execute_allowed", False)
            ),
            max_commands=max(
                0,
                int(execution.get("max_commands", 15) or 15),
            ),
            command_template_count=len(
                command_templates
                if isinstance(command_templates, list)
                else []
            ),
            prometheus_evidence_enabled=bool(
                prometheus.get("enabled", False)
            ),
            prometheus_profile=(
                _text(prometheus.get("evidence_profile")) or None
            ),
            prometheus_query_names=_string_tuple(
                prometheus.get("query_names", [])
            ),
            raw_playbook=MappingProxyType(dict(playbook)),
        )

    def evaluate_safety(
        self,
        *,
        event: Mapping[str, Any],
        family_result: Mapping[str, Any],
        classification: Mapping[str, Any],
        capability_plan: Mapping[str, Any],
        playbook: PlaybookResolution,
    ) -> dict[str, Any]:
        capability_readonly = bool(
            capability_plan.get("readonly_only", True)
        )
        declared_readonly = bool(playbook.readonly_only)
        all_readonly = capability_readonly and declared_readonly

        policy_plan = {
            "source": _text(event.get("source")),
            "target_scope": dict(
                family_result.get("target_scope", {}) or {}
            ),
            "readonly_only": all_readonly,
            "guard_result": {"all_readonly": all_readonly},
            "execution_candidates": [],
        }
        raw_playbook = (
            dict(playbook.raw_playbook)
            if playbook.matched
            else {
                "execution": {
                    "readonly_only": True,
                    "auto_execute_allowed": False,
                    "max_commands": 0,
                }
            }
        )
        result = evaluate_auto_confirm_policy(
            policy_plan,
            dict(classification),
            raw_playbook,
        )
        result["capability_readonly_only"] = capability_readonly
        result["playbook_readonly_only"] = declared_readonly
        result["command_generation_performed"] = False
        return result
