"""Governed Proposal Builder and state machine for NetAIOps Webhook v11.

Batch 4 converts eligible Learning Signals into deterministic, reviewable
Proposal records.  Proposals contain descriptive change intent only: they do
not contain executable shell/Git/device commands, arbitrary PromQL, arbitrary
Elasticsearch DSL, or any auto-apply behaviour.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence

from pydantic import ValidationError

from .contracts import LEARNING_SIGNAL_TYPES, ProposalStatus
from .schemas import (
    ArtifactReference,
    IncidentMemoryRecord,
    LearningSignalRecord,
    ProposalRecord,
    validate_governance_id,
)

_COMPONENT_RE = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")
_FORBIDDEN_EXECUTABLE_KEYS = frozenset(
    {
        "command",
        "commands",
        "shell",
        "shell_command",
        "git_command",
        "device_command",
        "device_commands",
        "promql",
        "query_dsl",
        "elasticsearch_dsl",
        "script",
        "executable",
        "execute",
        "auto_execute",
        "auto_apply_code",
    }
)
_COMMAND_PREFIX_RE = re.compile(
    r"^\s*(?:\$\s*)?(?:git|curl|wget|bash|sh|python|python3|sudo|show|configure|conf\s+t|clear|debug|reload|shutdown|no\s+shutdown)\b",
    re.IGNORECASE,
)


class ProposalBuilderError(ValueError):
    """Base error raised by governed Proposal construction."""


class ProposalNotEligibleError(ProposalBuilderError):
    """Raised when a signal must not produce a Proposal."""


class InvalidProposalTransition(ProposalBuilderError):
    """Raised when the Proposal state machine rejects a transition."""


@dataclass(frozen=True)
class ProposalTemplate:
    affected_components: tuple[str, ...]
    objective: str
    expected_benefit: str
    candidate_paths: tuple[str, ...]
    risk_level: str
    risk_concerns: tuple[str, ...]
    replay_checks: tuple[str, ...]


_TEMPLATES: Mapping[str, ProposalTemplate] = MappingProxyType(
    {
        "classification_fallback": ProposalTemplate(
            ("family_classifier", "classification_catalog"),
            "Improve deterministic family classification coverage for the affected alert family.",
            "Reduce generic or fallback classifications while preserving deterministic routing.",
            ("netaiops/", "playbooks/", "skills/"),
            "medium",
            ("A broader rule could misclassify adjacent alert families.",),
            ("family_match", "fallback_rate", "safety_policy_result"),
        ),
        "playbook_missing": ProposalTemplate(
            ("playbook_catalog", "skill_catalog"),
            "Add or refine a governed read-only Playbook mapping for the affected family.",
            "Increase deterministic evidence-plan coverage without introducing free-form tool use.",
            ("playbooks/", "skills/"),
            "medium",
            ("An overly broad Playbook match could select unsuitable evidence steps.",),
            ("selected_playbook", "readonly_only", "policy_result"),
        ),
        "policy_blocked": ProposalTemplate(
            ("safety_policy", "evidence_plan"),
            "Review why the deterministic evidence plan was blocked and clarify the governed boundary.",
            "Reduce avoidable policy blocks without weakening the read-only safety posture.",
            ("netaiops/", "playbooks/"),
            "high",
            ("Relaxing policy controls could permit unsafe or unsupported operations.",),
            ("policy_result", "blocked_reasons", "readonly_only"),
        ),
        "prometheus_not_configured": ProposalTemplate(
            ("prometheus_profile", "playbook_catalog"),
            "Define a governed metrics profile for the affected family when an approved metric exists.",
            "Make missing metrics configuration explicit and improve evidence completeness.",
            ("playbooks/", "netaiops/"),
            "medium",
            ("A profile may query the wrong labels or an unsupported metric.",),
            ("metrics_status", "profile_match", "query_budget"),
        ),
        "prometheus_no_data": ProposalTemplate(
            ("prometheus_profile", "metric_mapping"),
            "Review metric labels, time window, and family-to-profile mapping for no-data cases.",
            "Reduce false no-data results while retaining deterministic one-minute evidence semantics.",
            ("playbooks/", "netaiops/"),
            "medium",
            ("Wider windows or label changes may hide real collection gaps.",),
            ("metrics_status", "sample_presence", "label_match"),
        ),
        "prometheus_failed": ProposalTemplate(
            ("prometheus_adapter", "prometheus_profile"),
            "Improve governed error handling or profile compatibility for failed metrics evidence.",
            "Lower metrics evidence failures without changing the external safety boundary.",
            ("netaiops/", "playbooks/"),
            "medium",
            ("Retry or timeout changes could increase latency and resource use.",),
            ("metrics_status", "error_class", "latency_budget"),
        ),
        "command_failed": ProposalTemplate(
            ("device_evidence_template", "playbook_catalog"),
            "Review failed read-only evidence templates for platform and version compatibility.",
            "Reduce device evidence failures while keeping command selection deterministic and read-only.",
            ("playbooks/", "skills/"),
            "high",
            ("A replacement template may be unsupported on another platform variant.",),
            ("device_status", "failure_reason", "platform_matrix", "readonly_only"),
        ),
        "cli_hard_error": ProposalTemplate(
            ("cli_error_classifier", "device_evidence_template"),
            "Correct the governed template or parser condition that produced a CLI hard error.",
            "Eliminate known invalid-input paths and improve evidence reliability.",
            ("netaiops/", "playbooks/", "skills/"),
            "high",
            ("A syntax adjustment may regress a different vendor or software version.",),
            ("hard_error_count", "platform_matrix", "device_status"),
        ),
        "review_missing_evidence": ProposalTemplate(
            ("review", "evidence_requirements"),
            "Clarify required evidence or missing-section handling for the affected family.",
            "Improve review completeness and make evidence gaps explicit.",
            ("netaiops/", "playbooks/", "skills/"),
            "medium",
            ("Stricter requirements may increase partial results for legitimate limited cases.",),
            ("missing_evidence", "review_status", "evidence_scope"),
        ),
        "notification_failed": ProposalTemplate(
            ("notification_builder", "notification_sender"),
            "Improve governed notification failure handling and fallback observability.",
            "Reduce undelivered summaries while preserving Evidence Hub as the source of truth.",
            ("netaiops/"),
            "medium",
            ("Fallback changes may duplicate or lengthen notifications.",),
            ("notification_status", "fallback_status", "message_length"),
        ),
        "runner_false_negative": ProposalTemplate(
            ("acceptance_runner", "result_parser"),
            "Correct the acceptance result selector or assertion that disagreed with the production chain.",
            "Reduce tooling false negatives without masking real production failures.",
            ("tools/", "tests/"),
            "medium",
            ("Looser assertions could hide genuine acceptance failures.",),
            ("runner_result", "production_result", "artifact_selector"),
        ),
        "model_parse_failed": ProposalTemplate(
            ("llm_response_parser", "analysis_contract"),
            "Improve structured-response validation or bounded fallback handling for parse failures.",
            "Reduce unusable analysis records while keeping model output contract enforcement strict.",
            ("netaiops/", "tests/"),
            "medium",
            ("A permissive parser could accept malformed or ambiguous results.",),
            ("analysis_status", "parse_result", "contract_validity"),
        ),
    }
)

_ALLOWED_TRANSITIONS: Mapping[ProposalStatus, frozenset[ProposalStatus]] = MappingProxyType(
    {
        ProposalStatus.DRAFT: frozenset({ProposalStatus.PENDING_REVIEW}),
        ProposalStatus.PENDING_REVIEW: frozenset(
            {ProposalStatus.APPROVED, ProposalStatus.REJECTED}
        ),
        ProposalStatus.APPROVED: frozenset({ProposalStatus.IMPLEMENTED}),
        ProposalStatus.IMPLEMENTED: frozenset({ProposalStatus.VERIFIED}),
        ProposalStatus.REJECTED: frozenset(),
        ProposalStatus.VERIFIED: frozenset(),
    }
)


@dataclass(frozen=True)
class _SignalContext:
    signal_id: str
    request_id: str
    signal_type: str
    proposal_eligible: bool
    evidence_refs: tuple[ArtifactReference, ...]
    affected_family: str


def _aware_utc(value: datetime | None, *, field_name: str) -> datetime:
    result = value or datetime.now(timezone.utc)
    if result.tzinfo is None or result.utcoffset() is None:
        raise ProposalBuilderError(f"{field_name} must include timezone information")
    return result.astimezone(timezone.utc)


def _bounded_text(value: Any, *, field_name: str, limit: int = 240) -> str:
    text = " ".join(str(value or "").split()).strip()
    if not text:
        raise ProposalBuilderError(f"{field_name} must not be empty")
    if len(text) > limit:
        raise ProposalBuilderError(f"{field_name} exceeds {limit} characters")
    return text


def _artifact_refs(value: Any) -> tuple[ArtifactReference, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ProposalBuilderError("evidence_refs must be a non-empty sequence")
    refs: list[ArtifactReference] = []
    for item in value:
        try:
            refs.append(
                item if isinstance(item, ArtifactReference) else ArtifactReference.model_validate(item)
            )
        except (ValidationError, ValueError, TypeError) as exc:
            raise ProposalBuilderError(f"invalid evidence reference: {exc}") from exc
    if not refs:
        raise ProposalBuilderError("evidence_refs must not be empty")
    return tuple(refs)


def _coerce_signal(
    signal: LearningSignalRecord | Mapping[str, Any],
    *,
    affected_family: str | None,
) -> _SignalContext:
    if isinstance(signal, LearningSignalRecord):
        signal_id = signal.signal_id
        request_id = signal.request_id
        signal_type = signal.signal_type
        proposal_eligible = signal.proposal_eligible
        refs = tuple(signal.evidence_refs)
        family_value = affected_family
    elif isinstance(signal, Mapping):
        try:
            signal_id = validate_governance_id(
                str(signal.get("signal_id") or ""), field_name="signal_id"
            )
        except ValueError as exc:
            raise ProposalBuilderError(str(exc)) from exc
        request_id_raw = str(signal.get("request_id") or "unknown")
        try:
            request_id = validate_governance_id(request_id_raw, field_name="request_id")
        except ValueError as exc:
            raise ProposalBuilderError(str(exc)) from exc
        signal_type = str(signal.get("signal_type") or "").strip()
        proposal_eligible = bool(
            signal.get("proposal_eligible", signal_type != "logs_not_available")
        )
        refs = _artifact_refs(signal.get("evidence_refs"))
        family_value = affected_family or str(signal.get("affected_family") or "")
    else:
        raise TypeError("signal must be a LearningSignalRecord or mapping")

    if signal_type not in LEARNING_SIGNAL_TYPES:
        raise ProposalBuilderError(f"unknown learning signal type: {signal_type!r}")
    family = _bounded_text(family_value, field_name="affected_family", limit=160)
    return _SignalContext(
        signal_id=signal_id,
        request_id=request_id,
        signal_type=signal_type,
        proposal_eligible=proposal_eligible,
        evidence_refs=refs,
        affected_family=family,
    )


def _proposal_id(context: _SignalContext) -> str:
    material = (
        f"{context.signal_id}|{context.signal_type}|{context.affected_family}"
    ).encode("utf-8")
    return f"proposal_{hashlib.sha256(material).hexdigest()[:24]}"


def _normalise_component(value: str) -> str:
    text = str(value or "").strip().lower().replace(" ", "_")
    if not _COMPONENT_RE.fullmatch(text):
        raise ProposalBuilderError(f"invalid affected component: {value!r}")
    return text


def _walk_non_executable(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalised = str(key).strip().lower().replace("-", "_").replace(" ", "_")
            if normalised in _FORBIDDEN_EXECUTABLE_KEYS:
                raise ProposalBuilderError(f"executable Proposal field is forbidden: {path}.{key}")
            _walk_non_executable(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _walk_non_executable(child, f"{path}[{index}]")
    elif isinstance(value, str) and _COMMAND_PREFIX_RE.search(value):
        raise ProposalBuilderError(f"command-like Proposal content is forbidden at {path}")


def proposal_safety_summary(proposal: ProposalRecord | Mapping[str, Any]) -> dict[str, Any]:
    record = (
        proposal
        if isinstance(proposal, ProposalRecord)
        else ProposalRecord.model_validate(dict(proposal))
    )
    payload = record.to_payload()
    try:
        _walk_non_executable(payload)
    except ProposalBuilderError as exc:
        return {
            "safe": False,
            "reason": str(exc),
            "auto_apply": bool(record.risk.get("auto_apply", False)),
        }
    return {
        "safe": not bool(record.risk.get("auto_apply", False)),
        "reason": "",
        "auto_apply": bool(record.risk.get("auto_apply", False)),
        "evidence_ref_count": len(record.evidence_refs),
        "status": record.status.value,
    }


class ProposalBuilder:
    """Build deterministic draft Proposals from eligible Learning Signals."""

    def build(
        self,
        signal: LearningSignalRecord | Mapping[str, Any],
        *,
        affected_family: str | None = None,
        generated_at: datetime | None = None,
    ) -> ProposalRecord:
        context = _coerce_signal(signal, affected_family=affected_family)
        if not context.proposal_eligible:
            raise ProposalNotEligibleError(
                f"signal is not proposal eligible: {context.signal_type}"
            )
        template = _TEMPLATES.get(context.signal_type)
        if template is None:
            raise ProposalNotEligibleError(
                f"no governed Proposal template for signal: {context.signal_type}"
            )

        timestamp = _aware_utc(generated_at, field_name="generated_at")
        affected_components = [
            _normalise_component(item) for item in template.affected_components
        ]
        suggested_change = {
            "objective": template.objective,
            "rationale": (
                f"Governed learning signal {context.signal_type} requires human review "
                f"for family {context.affected_family}."
            ),
            "candidate_paths": list(template.candidate_paths),
            "constraints": [
                "Human review is required before any implementation.",
                "Do not auto-apply changes to production files.",
                "Do not add unapproved device operations or bypass Safety Policy.",
                "Validate the candidate with offline replay before implementation.",
            ],
        }
        risk = {
            "level": template.risk_level,
            "concerns": list(template.risk_concerns),
            "mitigations": [
                "Use the frozen Fixture Matrix and family-specific historical cases.",
                "Require reviewer approval and preserve the audit trail.",
                "Keep production configuration and runtime data outside Git.",
            ],
            "auto_apply": False,
        }
        replay_scope = {
            "mode": "offline",
            "request_ids": [] if context.request_id == "unknown" else [context.request_id],
            "affected_family": context.affected_family,
            "signal_types": [context.signal_type],
            "required_checks": list(template.replay_checks),
            "external_calls": {
                "glm": False,
                "prometheus": False,
                "device": False,
                "notification": False,
                "production_write": False,
            },
        }
        audit_trail = [
            {
                "from_status": "",
                "to_status": ProposalStatus.DRAFT.value,
                "at": timestamp.isoformat(),
                "reviewer": "",
                "note": "Created from an eligible governed Learning Signal.",
                "automatic": True,
            }
        ]

        candidate = ProposalRecord(
            proposal_id=_proposal_id(context),
            signal_id=context.signal_id,
            signal_type=context.signal_type,
            affected_family=context.affected_family,
            affected_components=affected_components,
            evidence_refs=list(context.evidence_refs),
            suggested_change=suggested_change,
            expected_benefit=template.expected_benefit,
            risk=risk,
            replay_scope=replay_scope,
            status=ProposalStatus.DRAFT,
            reviewer="",
            created_at=timestamp,
            updated_at=timestamp,
            audit_trail=audit_trail,
        )
        _walk_non_executable(candidate.to_payload())
        if candidate.risk.get("auto_apply") is not False:
            raise ProposalBuilderError("Proposal must explicitly disable auto_apply")
        return candidate

    def build_for_memory(
        self,
        signal: LearningSignalRecord | Mapping[str, Any],
        memory: IncidentMemoryRecord | Mapping[str, Any],
        *,
        generated_at: datetime | None = None,
    ) -> ProposalRecord:
        record = (
            memory
            if isinstance(memory, IncidentMemoryRecord)
            else IncidentMemoryRecord.model_validate(dict(memory))
        )
        signal_request_id = (
            signal.request_id
            if isinstance(signal, LearningSignalRecord)
            else str(signal.get("request_id") or "unknown")
        )
        if signal_request_id not in {"unknown", record.request_id}:
            raise ProposalBuilderError(
                "signal request_id does not match Incident Memory request_id"
            )
        return self.build(
            signal,
            affected_family=record.family,
            generated_at=generated_at,
        )


def can_transition(current: ProposalStatus | str, target: ProposalStatus | str) -> bool:
    try:
        current_status = current if isinstance(current, ProposalStatus) else ProposalStatus(current)
        target_status = target if isinstance(target, ProposalStatus) else ProposalStatus(target)
    except ValueError:
        return False
    return target_status in _ALLOWED_TRANSITIONS.get(current_status, frozenset())


def transition_proposal(
    proposal: ProposalRecord | Mapping[str, Any],
    target_status: ProposalStatus | str,
    *,
    reviewer: str,
    note: str = "",
    changed_at: datetime | None = None,
) -> ProposalRecord:
    """Return a new Proposal with one audited, human-attributed state change."""

    record = (
        proposal
        if isinstance(proposal, ProposalRecord)
        else ProposalRecord.model_validate(dict(proposal))
    )
    try:
        target = (
            target_status
            if isinstance(target_status, ProposalStatus)
            else ProposalStatus(target_status)
        )
    except ValueError as exc:
        raise InvalidProposalTransition(f"unknown target status: {target_status!r}") from exc

    if not can_transition(record.status, target):
        raise InvalidProposalTransition(
            f"transition not allowed: {record.status.value} -> {target.value}"
        )
    reviewer_text = _bounded_text(reviewer, field_name="reviewer", limit=160)
    note_text = " ".join(str(note or "").split()).strip()
    if len(note_text) > 800:
        raise ProposalBuilderError("transition note exceeds 800 characters")
    timestamp = _aware_utc(changed_at, field_name="changed_at")
    if timestamp < record.updated_at:
        raise InvalidProposalTransition("changed_at must not be earlier than updated_at")

    event = {
        "from_status": record.status.value,
        "to_status": target.value,
        "at": timestamp.isoformat(),
        "reviewer": reviewer_text,
        "note": note_text,
        "automatic": False,
    }
    updated = record.model_copy(
        update={
            "status": target,
            "reviewer": reviewer_text,
            "updated_at": timestamp,
            "audit_trail": [*record.audit_trail, event],
        },
        deep=True,
    )
    # model_copy does not rerun every validator; revalidate the final payload.
    validated = ProposalRecord.model_validate(updated.to_payload())
    _walk_non_executable(validated.to_payload())
    return validated


def proposal_workflow_summary(
    proposals: Iterable[ProposalRecord],
) -> dict[str, Any]:
    records = tuple(proposals)
    by_status: dict[str, int] = {}
    by_signal: dict[str, int] = {}
    for proposal in records:
        status = proposal.status.value
        by_status[status] = by_status.get(status, 0) + 1
        by_signal[proposal.signal_type] = by_signal.get(proposal.signal_type, 0) + 1
    return {
        "total": len(records),
        "by_status": dict(sorted(by_status.items())),
        "by_signal_type": dict(sorted(by_signal.items())),
        "auto_apply_enabled": sum(
            1 for proposal in records if bool(proposal.risk.get("auto_apply", False))
        ),
    }


__all__ = [
    "InvalidProposalTransition",
    "ProposalBuilder",
    "ProposalBuilderError",
    "ProposalNotEligibleError",
    "ProposalTemplate",
    "can_transition",
    "proposal_safety_summary",
    "proposal_workflow_summary",
    "transition_proposal",
]
