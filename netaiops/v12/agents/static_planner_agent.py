"""Deterministic v12 Static Planner Agent.

The planner reuses current Family, Skill, Playbook, Capability, and Safety
Policy metadata. It never calls an LLM and never renders CLI, PromQL, or DSL.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from pydantic import ValidationError

from netaiops.capability_registry import build_capability_plan, get_capability
from netaiops.family_registry import classify_family, to_legacy_classification

from ..adapters.playbook_adapter import PlaybookAdapter
from ..adapters.skill_adapter import SkillAdapter
from ..contracts import (
    ContractNotice,
    EvidencePlan,
    EvidenceSourcePlan,
    UnifiedAlertEvent,
)
from ..execution_context import AgentInvocation, AgentOutcome
from ..schema_validator import build_contract_ref
from ..status import AgentName, AgentStatus, EvidenceSource


_FIXED_SOURCES: tuple[EvidenceSource, ...] = (
    EvidenceSource.METRICS,
    EvidenceSource.DEVICE,
    EvidenceSource.LOGS,
    EvidenceSource.KNOWLEDGE,
)
_METRIC_CATEGORIES = frozenset({"metric", "metrics", "prometheus"})
_LOG_CATEGORIES = frozenset({"log", "logs", "elastic"})


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _unique_strings(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    output: list[str] = []
    for item in value:
        text = _text(item)
        if text and text not in output:
            output.append(text[:128])
    return output


def _legacy_event(unified: UnifiedAlertEvent) -> dict[str, Any]:
    labels = dict(unified.labels)
    annotations = dict(unified.annotations)
    attributes = dict(unified.alert_object.attributes)
    target_scope = dict(_mapping(attributes.get("target_scope")))

    event: dict[str, Any] = {
        "source": unified.source.value,
        "timestamp": unified.occurred_at.isoformat(),
        "alarm_type": unified.alert_name,
        "severity": labels.get("severity", ""),
        "status": unified.alert_status.value,
        "hostname": unified.device.name or "",
        "device_ip": unified.device.ip or "",
        "vendor": unified.device.vendor or "",
        "platform": unified.device.platform or "",
        "site": unified.device.site or "",
        "object_type": unified.alert_object.kind,
        "object_name": unified.alert_object.name,
        "raw_text": " ".join(
            text
            for text in (
                annotations.get("summary", ""),
                annotations.get("description", ""),
            )
            if text
        ),
        "labels": labels,
        "annotations": annotations,
        "family": unified.family or "",
        "playbook_type_hint": unified.family or "",
    }
    for key, value in target_scope.items():
        if value not in (None, "", [], {}) and key not in event:
            event[str(key)] = value

    object_kind = unified.alert_object.kind.lower()
    object_name = unified.alert_object.name
    if object_kind == "interface":
        event.setdefault("interface", object_name)
    elif object_kind in {"neighbor", "peer"}:
        event.setdefault("peer_ip", object_name)
        event.setdefault("object_id", object_name)
    elif object_kind in {"pool_member", "pool-member"}:
        event.setdefault("pool_member", object_name)
        event.setdefault("object_id", object_name)
    return event


def _capability_groups(
    capability_plan: Mapping[str, Any],
) -> dict[EvidenceSource, list[str]]:
    groups: dict[EvidenceSource, list[str]] = {
        source: [] for source in _FIXED_SOURCES
    }
    selected = capability_plan.get("selected_capabilities", []) or []
    for item in selected:
        if not isinstance(item, Mapping):
            continue
        capability = _text(item.get("capability"))
        if not capability:
            continue
        metadata = get_capability(capability) or {}
        category = _text(metadata.get("category")).lower()
        if (
            category in _METRIC_CATEGORIES
            or capability.startswith("query_prometheus")
        ):
            source = EvidenceSource.METRICS
        elif (
            category in _LOG_CATEGORIES
            or capability.startswith("query_elastic")
        ):
            source = EvidenceSource.LOGS
        else:
            source = EvidenceSource.DEVICE
        if capability not in groups[source]:
            groups[source].append(capability)
    return groups


class StaticPlannerAgent:
    """Build one fixed EvidencePlan from the Triage contract."""

    def __init__(
        self,
        *,
        skill_adapter: SkillAdapter | None = None,
        playbook_adapter: PlaybookAdapter | None = None,
    ) -> None:
        self.skill_adapter = skill_adapter or SkillAdapter()
        self.playbook_adapter = playbook_adapter or PlaybookAdapter()

    async def run(self, invocation: AgentInvocation) -> AgentOutcome:
        if invocation.agent_name != AgentName.STATIC_PLANNER:
            return self._failed(
                "static_planner_agent_name_mismatch",
                "StaticPlannerAgent can only run as static_planner",
            )

        triage_output = _mapping(
            invocation.prior_outputs.get(AgentName.TRIAGE.value)
        )
        raw_unified = triage_output.get("unified_event")
        if not isinstance(raw_unified, Mapping):
            return self._failed(
                "static_planner_triage_output_missing",
                "Triage output did not contain unified_event",
            )

        try:
            unified = UnifiedAlertEvent.model_validate(raw_unified)
        except ValidationError as exc:
            return self._failed(
                "static_planner_event_invalid",
                "unified_event failed contract validation",
                details={"issue_count": len(exc.errors())},
            )

        if unified.request_id != invocation.request_id:
            return self._failed(
                "static_planner_request_id_mismatch",
                "unified_event request_id did not match invocation",
            )

        event = _legacy_event(unified)
        family_result = classify_family(dict(event))
        family = _text(
            family_result.get("family") or unified.family
        ) or "generic_network_readonly"
        classification = to_legacy_classification(
            dict(family_result),
            dict(event),
        )
        capability_plan = build_capability_plan(
            dict(event),
            dict(family_result),
        )
        skill = self.skill_adapter.resolve(family)
        playbook = self.playbook_adapter.resolve(
            event,
            classification,
        )
        safety = self.playbook_adapter.evaluate_safety(
            event=event,
            family_result=family_result,
            classification=classification,
            capability_plan=capability_plan,
            playbook=playbook,
        )

        if (
            not bool(capability_plan.get("readonly_only", True))
            or not playbook.readonly_only
        ):
            return self._failed(
                "static_planner_readonly_policy_rejected",
                "Static planning inputs were not readonly-only",
                details={
                    "capability_readonly_only": bool(
                        capability_plan.get("readonly_only", True)
                    ),
                    "playbook_readonly_only": playbook.readonly_only,
                },
            )

        groups = _capability_groups(capability_plan)
        sources = self._build_sources(
            groups=groups,
            playbook=playbook,
            safety=safety,
        )
        selected_capabilities = [
            capability
            for source in _FIXED_SOURCES
            for capability in groups[source]
        ]
        plan_identifier = self._plan_identifier(
            invocation.request_id,
            unified,
            family,
            playbook.playbook_id,
            selected_capabilities,
        )
        plan_ref = build_contract_ref(
            "plan",
            invocation.request_id,
            "evidence_plan",
            plan_identifier,
        )
        plan = EvidencePlan(
            schema_version="v12.1",
            request_id=invocation.request_id,
            plan_ref=plan_ref,
            planner_mode="deterministic",
            family=family,
            selected_playbook=playbook.playbook_id,
            sources=sources,
            readonly_only=True,
            created_at=unified.received_at,
        )

        warnings: list[ContractNotice] = []
        if not skill.matched:
            warnings.append(
                self._warning(
                    "static_planner_skill_not_found",
                    "No Skill package matched the classified family",
                )
            )
        elif skill.validation_verdict != "pass":
            warnings.append(
                self._warning(
                    "static_planner_skill_validation_not_pass",
                    "Matched Skill package did not pass validation",
                )
            )
        if not playbook.matched:
            warnings.append(
                self._warning(
                    "static_planner_playbook_not_found",
                    "No Playbook matched; capability mapping was retained",
                )
            )
        if not safety.get("auto_confirm_allowed", False):
            warnings.append(
                self._warning(
                    "static_planner_safety_policy_blocked",
                    "Safety Policy did not allow automatic execution",
                    details={
                        "reasons": list(safety.get("reasons", [])),
                    },
                )
            )
        if not selected_capabilities:
            warnings.append(
                self._warning(
                    "static_planner_capability_plan_empty",
                    "No deterministic capability was selected",
                )
            )

        status = AgentStatus.PARTIAL if warnings else AgentStatus.SUCCESS
        return AgentOutcome(
            status=status,
            output_refs=(plan_ref,),
            output={
                "evidence_plan": plan.model_dump(mode="json"),
                "family": family,
                "skill": skill.public_dict(),
                "playbook": playbook.public_dict(),
                "capability_ids": selected_capabilities,
                "safety_policy": safety,
                "dynamic_source_selection": False,
                "command_generation_performed": False,
                "promql_generation_performed": False,
                "dsl_generation_performed": False,
            },
            warnings=tuple(warnings),
        )

    def _build_sources(
        self,
        *,
        groups: Mapping[EvidenceSource, list[str]],
        playbook: Any,
        safety: Mapping[str, Any],
    ) -> list[EvidenceSourcePlan]:
        metric_ids = list(groups[EvidenceSource.METRICS])
        device_ids = list(groups[EvidenceSource.DEVICE])
        log_ids = list(groups[EvidenceSource.LOGS])

        metrics_required = bool(
            metric_ids or playbook.prometheus_evidence_enabled
        )
        device_required = bool(
            device_ids or playbook.command_template_count > 0
        )

        return [
            EvidenceSourcePlan(
                source=EvidenceSource.METRICS,
                required=metrics_required,
                capability_ids=metric_ids,
                constraints={
                    "reuse_existing_evidence": True,
                    "promql_generation_allowed": False,
                    "planner_mode": "deterministic",
                    "evidence_profile": playbook.prometheus_profile,
                    "query_names": list(playbook.prometheus_query_names),
                },
                max_items=max(1, len(metric_ids)),
            ),
            EvidenceSourcePlan(
                source=EvidenceSource.DEVICE,
                required=device_required,
                capability_ids=device_ids,
                constraints={
                    "readonly_only": True,
                    "command_generation_allowed": False,
                    "safety_policy_allowed": bool(
                        safety.get("auto_confirm_allowed", False)
                    ),
                    "safety_policy_reasons": list(
                        safety.get("reasons", [])
                    ),
                    "playbook_command_template_count": (
                        playbook.command_template_count
                    ),
                    "playbook_max_commands": playbook.max_commands,
                },
                max_items=max(
                    1,
                    len(device_ids),
                    min(playbook.max_commands, 100),
                ),
            ),
            EvidenceSourcePlan(
                source=EvidenceSource.LOGS,
                required=False,
                capability_ids=log_ids,
                constraints={
                    "enabled": False,
                    "reason": "logs_evidence_not_approved",
                    "dsl_generation_allowed": False,
                },
                max_items=0,
            ),
            EvidenceSourcePlan(
                source=EvidenceSource.KNOWLEDGE,
                required=False,
                capability_ids=[],
                constraints={
                    "enabled": False,
                    "reason": "local_knowledge_base_not_built",
                    "evidence_kind": "context",
                },
                max_items=0,
            ),
        ]

    def _plan_identifier(
        self,
        request_id: str,
        unified: UnifiedAlertEvent,
        family: str,
        playbook_id: str | None,
        capabilities: list[str],
    ) -> str:
        payload = json.dumps(
            {
                "request_id": request_id,
                "event_id": unified.event_id,
                "family": family,
                "playbook_id": playbook_id,
                "capabilities": capabilities,
                "sources": [source.value for source in _FIXED_SOURCES],
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return "static-" + hashlib.sha256(
            payload.encode("utf-8")
        ).hexdigest()[:24]

    def _warning(
        self,
        code: str,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> ContractNotice:
        return ContractNotice(
            code=code,
            message=message,
            stage="static_planner",
            retryable=False,
            details=dict(details or {}),
        )

    def _failed(
        self,
        code: str,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> AgentOutcome:
        return AgentOutcome(
            status=AgentStatus.FAILED,
            errors=(
                ContractNotice(
                    code=code,
                    message=message,
                    stage="static_planner",
                    retryable=False,
                    details=dict(details or {}),
                ),
            ),
        )
