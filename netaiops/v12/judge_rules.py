"""Deterministic evidence quality rules for v12 Evidence Judge."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Mapping

from .contracts import (
    ContextEnvelope,
    EvidenceBundle,
    EvidenceConflict,
    EvidenceEnvelope,
    EvidenceJudgeResult,
    EvidencePlan,
)
from .schema_validator import parse_contract_ref
from .status import (
    EvidenceBundleStatus,
    EvidenceSource,
    EvidenceStatus,
    JudgeStatus,
)


RULES_VERSION = "v12-judge-rules-1"
MAX_EVIDENCE_SKEW_SECONDS = 30 * 60

_SOURCE_ORDER = (
    EvidenceSource.METRICS,
    EvidenceSource.DEVICE,
    EvidenceSource.LOGS,
    EvidenceSource.KNOWLEDGE,
)
_HARD_MISSING = frozenset(
    {
        EvidenceStatus.FAILED,
        EvidenceStatus.SKIPPED,
        EvidenceStatus.NOT_AVAILABLE,
    }
)
_WEAK_STATUSES = frozenset(
    {
        EvidenceStatus.PARTIAL,
        EvidenceStatus.NO_DATA,
    }
)
_STATE_KEYS = frozenset(
    {
        "judge_state",
        "observed_state",
        "oper_status",
        "operational_status",
        "link_state",
        "health_state",
        "availability_state",
        "interface_state",
    }
)
_POSITIVE_STATES = frozenset(
    {
        "up",
        "healthy",
        "ok",
        "active",
        "available",
        "reachable",
        "running",
        "normal",
        "true",
        "1",
    }
)
_NEGATIVE_STATES = frozenset(
    {
        "down",
        "failed",
        "unhealthy",
        "critical",
        "unavailable",
        "unreachable",
        "inactive",
        "stopped",
        "false",
        "0",
    }
)
_SCOPE_GROUPS = (
    ("device_ip", ("device_ip", "ip")),
    ("hostname", ("hostname", "device_name")),
    (
        "interface",
        ("interface", "if_name", "ifName", "interface_name"),
    ),
)


class EvidenceJudgeRuleError(ValueError):
    """Raised when deterministic judge rules receive inconsistent contracts."""


def _unique_sources(
    values: Iterable[EvidenceSource],
) -> list[EvidenceSource]:
    selected = set(values)
    return [source for source in _SOURCE_ORDER if source in selected]


def _unique_refs(values: Iterable[str]) -> list[str]:
    return sorted(set(values))


def _source_plan_map(plan: EvidencePlan) -> dict[EvidenceSource, Any]:
    return {item.source: item for item in plan.sources}


def _envelope_map(
    bundle: EvidenceBundle,
) -> dict[EvidenceSource, EvidenceEnvelope | ContextEnvelope]:
    return {
        EvidenceSource.METRICS: bundle.evidence.metrics,
        EvidenceSource.DEVICE: bundle.evidence.device,
        EvidenceSource.LOGS: bundle.evidence.logs,
        EvidenceSource.KNOWLEDGE: bundle.evidence.knowledge,
    }


def _evidence_refs(
    bundle: EvidenceBundle,
) -> list[str]:
    refs: list[str] = []
    for envelope in (
        bundle.evidence.metrics,
        bundle.evidence.device,
        bundle.evidence.logs,
    ):
        refs.extend(envelope.evidence_refs)
    return _unique_refs(refs)


def _is_stale(
    collected_at: datetime,
    plan_created_at: datetime,
) -> bool:
    delta = abs((collected_at - plan_created_at).total_seconds())
    return delta > MAX_EVIDENCE_SKEW_SECONDS


def _scope_value(
    scope: Mapping[str, Any],
    keys: tuple[str, ...],
) -> str:
    for key in keys:
        value = scope.get(key)
        if value not in (None, "", [], {}):
            return str(value).strip().lower()
    return ""


def _state_signals(value: Any) -> set[str]:
    output: set[str] = set()

    def walk(item: Any) -> None:
        if isinstance(item, Mapping):
            for key, child in item.items():
                normalized_key = str(key).strip().lower()
                if normalized_key in _STATE_KEYS:
                    normalized_value = str(child).strip().lower()
                    if normalized_value in _POSITIVE_STATES:
                        output.add("positive")
                    elif normalized_value in _NEGATIVE_STATES:
                        output.add("negative")
                walk(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                walk(child)

    walk(value)
    return output


def _conflict_refs(
    metrics: EvidenceEnvelope,
    device: EvidenceEnvelope,
) -> list[str]:
    refs = [
        *metrics.evidence_refs[:1],
        *device.evidence_refs[:1],
    ]
    return _unique_refs(refs)


def detect_conflicts(
    metrics: EvidenceEnvelope,
    device: EvidenceEnvelope,
) -> list[EvidenceConflict]:
    """Detect only explicit, deterministic metrics/device contradictions."""

    refs = _conflict_refs(metrics, device)
    if len(refs) < 2:
        return []

    conflicts: list[EvidenceConflict] = []

    for label, keys in _SCOPE_GROUPS:
        metrics_value = _scope_value(metrics.scope, keys)
        device_value = _scope_value(device.scope, keys)
        if (
            metrics_value
            and device_value
            and metrics_value != device_value
        ):
            conflicts.append(
                EvidenceConflict(
                    statement=(
                        "Metrics and device evidence scopes disagree "
                        f"on {label}."
                    ),
                    evidence_refs=refs,
                    severity="high",
                )
            )

    metrics_states = _state_signals(metrics.facts)
    device_states = _state_signals(device.facts)
    if (
        ("positive" in metrics_states and "negative" in device_states)
        or (
            "negative" in metrics_states
            and "positive" in device_states
        )
    ):
        conflicts.append(
            EvidenceConflict(
                statement=(
                    "Metrics and device evidence report contradictory "
                    "operational states."
                ),
                evidence_refs=refs,
                severity="high",
            )
        )

    unique: dict[str, EvidenceConflict] = {}
    for conflict in conflicts:
        unique[conflict.statement] = conflict
    return [unique[key] for key in sorted(unique)]


def missing_reference_sources(
    plan: EvidencePlan,
    raw_bundle: Mapping[str, Any],
) -> tuple[list[EvidenceSource], list[EvidenceSource]]:
    """Preflight malformed success/partial inputs before Pydantic rejection."""

    evidence = raw_bundle.get("evidence")
    if not isinstance(evidence, Mapping):
        return [], []

    source_plan = _source_plan_map(plan)
    required: list[EvidenceSource] = []
    optional: list[EvidenceSource] = []

    for source in (
        EvidenceSource.METRICS,
        EvidenceSource.DEVICE,
        EvidenceSource.LOGS,
    ):
        raw = evidence.get(source.value)
        if not isinstance(raw, Mapping):
            continue
        status = str(raw.get("status") or "").strip().lower()
        refs = raw.get("evidence_refs")
        if status not in {"success", "partial"}:
            continue
        if isinstance(refs, list) and refs:
            continue
        target = (
            required
            if source_plan.get(source) is not None
            and source_plan[source].required
            else optional
        )
        target.append(source)

    raw_knowledge = evidence.get(EvidenceSource.KNOWLEDGE.value)
    if isinstance(raw_knowledge, Mapping):
        status = str(
            raw_knowledge.get("status") or ""
        ).strip().lower()
        refs = raw_knowledge.get("source_refs")
        if status == "success" and not (
            isinstance(refs, list) and refs
        ):
            target = (
                required
                if source_plan.get(EvidenceSource.KNOWLEDGE)
                is not None
                and source_plan[EvidenceSource.KNOWLEDGE].required
                else optional
            )
            target.append(EvidenceSource.KNOWLEDGE)

    return _unique_sources(required), _unique_sources(optional)


def _raw_status_missing_sources(
    plan: EvidencePlan,
    raw_bundle: Mapping[str, Any],
) -> tuple[list[EvidenceSource], list[EvidenceSource]]:
    """Collect other missing sources while handling malformed refs."""

    evidence = raw_bundle.get("evidence")
    if not isinstance(evidence, Mapping):
        return [], []

    source_plan = _source_plan_map(plan)
    required: list[EvidenceSource] = []
    optional: list[EvidenceSource] = []
    missing_statuses = {
        "partial",
        "no_data",
        "failed",
        "skipped",
        "not_available",
    }

    for source in _SOURCE_ORDER:
        raw = evidence.get(source.value)
        if not isinstance(raw, Mapping):
            continue
        status = str(raw.get("status") or "").strip().lower()
        if status not in missing_statuses:
            continue
        target = (
            required
            if source_plan.get(source) is not None
            and source_plan[source].required
            else optional
        )
        target.append(source)

    return _unique_sources(required), _unique_sources(optional)


def judge_missing_references(
    plan: EvidencePlan,
    raw_bundle: Mapping[str, Any],
) -> EvidenceJudgeResult | None:
    ref_required, ref_optional = missing_reference_sources(
        plan,
        raw_bundle,
    )
    if not ref_required and not ref_optional:
        return None

    status_required, status_optional = _raw_status_missing_sources(
        plan,
        raw_bundle,
    )
    required_missing = _unique_sources(
        [*ref_required, *status_required]
    )
    optional_missing = _unique_sources(
        [*ref_optional, *status_optional]
    )

    judged_at = plan.created_at
    raw_built_at = raw_bundle.get("built_at")
    if isinstance(raw_built_at, str):
        text = raw_built_at
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is not None and parsed.utcoffset() is not None:
                judged_at = parsed
        except ValueError:
            pass

    status = (
        JudgeStatus.INSUFFICIENT
        if required_missing
        else JudgeStatus.PARTIAL
    )
    return EvidenceJudgeResult(
        schema_version="v12.1",
        request_id=plan.request_id,
        status=status,
        required_sources=_unique_sources(
            item.source for item in plan.sources if item.required
        ),
        missing_required_sources=required_missing,
        missing_optional_sources=optional_missing,
        conflicts=[],
        rca_allowed=not required_missing,
        confidence_cap=0.0 if required_missing else 0.75,
        evidence_refs=[],
        judged_at=judged_at,
    )


def evaluate_evidence(
    plan: EvidencePlan,
    bundle: EvidenceBundle,
) -> EvidenceJudgeResult:
    """Apply the frozen rule matrix to one validated EvidenceBundle."""

    if plan.request_id != bundle.request_id:
        raise EvidenceJudgeRuleError(
            "EvidencePlan and EvidenceBundle request_id mismatch"
        )

    source_plan = _source_plan_map(plan)
    envelopes = _envelope_map(bundle)
    required_sources = _unique_sources(
        source for source, item in source_plan.items() if item.required
    )
    missing_required: list[EvidenceSource] = []
    missing_optional: list[EvidenceSource] = []
    hard_missing_required: set[EvidenceSource] = set()
    weak_required: set[EvidenceSource] = set()
    stale_required: set[EvidenceSource] = set()
    stale_optional: set[EvidenceSource] = set()
    required_usable = 0

    for source in _SOURCE_ORDER:
        envelope = envelopes[source]
        required = bool(
            source_plan.get(source)
            and source_plan[source].required
        )
        status = envelope.status

        if status == EvidenceStatus.SUCCESS:
            if required:
                required_usable += 1
        elif status == EvidenceStatus.PARTIAL:
            if required:
                required_usable += 1
                weak_required.add(source)
                missing_required.append(source)
            else:
                missing_optional.append(source)
        elif status == EvidenceStatus.NO_DATA:
            if required:
                weak_required.add(source)
                missing_required.append(source)
            else:
                missing_optional.append(source)
        elif status in _HARD_MISSING:
            if required:
                hard_missing_required.add(source)
                missing_required.append(source)
            else:
                missing_optional.append(source)

        if status in {
            EvidenceStatus.SUCCESS,
            EvidenceStatus.PARTIAL,
        } and _is_stale(
            envelope.collected_at,
            plan.created_at,
        ):
            if required:
                stale_required.add(source)
                if source not in missing_required:
                    missing_required.append(source)
            else:
                stale_optional.add(source)
                if source not in missing_optional:
                    missing_optional.append(source)

    conflicts = detect_conflicts(
        bundle.evidence.metrics,
        bundle.evidence.device,
    )
    refs = _evidence_refs(bundle)

    all_missing = all(
        envelope.status
        in {
            EvidenceStatus.NO_DATA,
            EvidenceStatus.FAILED,
            EvidenceStatus.SKIPPED,
            EvidenceStatus.NOT_AVAILABLE,
        }
        for envelope in envelopes.values()
    )

    if (
        bundle.bundle_status == EvidenceBundleStatus.BLOCKED
        or conflicts
    ):
        status = JudgeStatus.BLOCKED
        rca_allowed = False
        confidence_cap = 0.0
    elif (
        hard_missing_required
        or stale_required
        or all_missing
        or (weak_required and required_usable == 0)
    ):
        status = JudgeStatus.INSUFFICIENT
        rca_allowed = False
        confidence_cap = 0.0
    elif (
        weak_required
        or missing_optional
        or stale_optional
        or bundle.bundle_status
        in {
            EvidenceBundleStatus.PARTIAL,
            EvidenceBundleStatus.INSUFFICIENT,
        }
    ):
        status = JudgeStatus.PARTIAL
        rca_allowed = True
        confidence_cap = 0.85
        if weak_required:
            confidence_cap = min(confidence_cap, 0.65)
        if stale_optional:
            confidence_cap = min(confidence_cap, 0.70)
    else:
        status = JudgeStatus.READY
        rca_allowed = True
        confidence_cap = 1.0

    return EvidenceJudgeResult(
        schema_version="v12.1",
        request_id=plan.request_id,
        status=status,
        required_sources=required_sources,
        missing_required_sources=_unique_sources(missing_required),
        missing_optional_sources=_unique_sources(missing_optional),
        conflicts=conflicts,
        rca_allowed=rca_allowed,
        confidence_cap=confidence_cap,
        evidence_refs=refs,
        judged_at=bundle.built_at,
    )
