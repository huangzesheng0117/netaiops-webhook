"""Deterministic Learning Signal detection for v11 Incident Memory.

Batch 3 consumes only the compact Incident Memory produced by Batch 2.  It does
not reread raw request artifacts, call external services, modify Skill or
Playbook files, or write production data.  Each emitted signal carries bounded
metadata-only evidence references and a stable dedupe key.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence

from pydantic import ValidationError

from .contracts import (
    EvidenceSourceStatus,
    LEARNING_SIGNAL_TYPES,
    LearningSignalSeverity,
)
from .schemas import ArtifactReference, IncidentMemoryRecord, LearningSignalRecord


@dataclass(frozen=True)
class SignalRule:
    severity: LearningSignalSeverity
    proposal_eligible: bool
    detected_from: tuple[str, ...]
    evidence_kinds: tuple[str, ...]


_SIGNAL_RULES: Mapping[str, SignalRule] = MappingProxyType(
    {
        "classification_fallback": SignalRule(
            LearningSignalSeverity.WARNING,
            True,
            ("incident_memory.quality_flags",),
            ("plan", "analysis", "pipeline"),
        ),
        "playbook_missing": SignalRule(
            LearningSignalSeverity.WARNING,
            True,
            ("incident_memory.quality_flags",),
            ("plan",),
        ),
        "policy_blocked": SignalRule(
            LearningSignalSeverity.ERROR,
            True,
            ("incident_memory.quality_flags",),
            ("plan",),
        ),
        "prometheus_not_configured": SignalRule(
            LearningSignalSeverity.WARNING,
            True,
            ("incident_memory.evidence_status.metrics",),
            ("prometheus_evidence", "evidence_hub_summary"),
        ),
        "prometheus_no_data": SignalRule(
            LearningSignalSeverity.WARNING,
            True,
            ("incident_memory.evidence_status.metrics",),
            ("prometheus_evidence", "evidence_hub_summary"),
        ),
        "prometheus_failed": SignalRule(
            LearningSignalSeverity.ERROR,
            True,
            ("incident_memory.evidence_status.metrics",),
            ("prometheus_evidence", "evidence_hub_summary"),
        ),
        "command_failed": SignalRule(
            LearningSignalSeverity.ERROR,
            True,
            ("incident_memory.command_summary.failed",),
            ("execution", "review"),
        ),
        "cli_hard_error": SignalRule(
            LearningSignalSeverity.ERROR,
            True,
            ("incident_memory.command_summary.hard_error_count",),
            ("execution", "review"),
        ),
        "review_missing_evidence": SignalRule(
            LearningSignalSeverity.WARNING,
            True,
            (
                "incident_memory.review_summary.missing_evidence_count",
                "incident_memory.review_summary.read_error_count",
                "incident_memory.evidence_status.review",
            ),
            ("review", "evidence_hub_summary"),
        ),
        "notification_failed": SignalRule(
            LearningSignalSeverity.ERROR,
            True,
            ("incident_memory.notification_result.status",),
            (
                "notification_send_result",
                "notification_summary_slim",
                "notification_summary",
            ),
        ),
        "runner_false_negative": SignalRule(
            LearningSignalSeverity.ERROR,
            True,
            ("incident_memory.quality_flags",),
            ("pipeline", "review"),
        ),
        "model_parse_failed": SignalRule(
            LearningSignalSeverity.ERROR,
            True,
            ("incident_memory.quality_flags",),
            ("analysis", "pipeline"),
        ),
        "logs_not_available": SignalRule(
            LearningSignalSeverity.INFO,
            False,
            ("incident_memory.evidence_status.logs",),
            ("evidence_hub_summary",),
        ),
    }
)


def _coerce_memory(value: IncidentMemoryRecord | Mapping[str, Any]) -> IncidentMemoryRecord:
    if isinstance(value, IncidentMemoryRecord):
        return value
    if not isinstance(value, Mapping):
        raise TypeError("memory must be an IncidentMemoryRecord or mapping")
    try:
        return IncidentMemoryRecord.model_validate(dict(value))
    except ValidationError as exc:
        raise ValueError(f"invalid incident memory: {exc}") from exc


def _non_negative_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _status_value(value: Any) -> str:
    if isinstance(value, EvidenceSourceStatus):
        return value.value
    return str(value or "").strip().lower()


def _detected_signal_types(memory: IncidentMemoryRecord) -> tuple[str, ...]:
    detected: set[str] = {
        flag for flag in memory.quality_flags if flag in LEARNING_SIGNAL_TYPES
    }

    metrics_status = _status_value(memory.evidence_status.get("metrics"))
    if metrics_status == EvidenceSourceStatus.NO_DATA.value:
        detected.add("prometheus_no_data")
    elif metrics_status == EvidenceSourceStatus.FAILED.value:
        detected.add("prometheus_failed")
    elif metrics_status == EvidenceSourceStatus.NOT_CONFIGURED.value:
        detected.add("prometheus_not_configured")

    if _non_negative_int(memory.command_summary.get("failed")) > 0:
        detected.add("command_failed")
    if _non_negative_int(memory.command_summary.get("hard_error_count")) > 0:
        detected.add("cli_hard_error")

    review_status = _status_value(memory.evidence_status.get("review"))
    if (
        _non_negative_int(memory.review_summary.get("missing_evidence_count")) > 0
        or _non_negative_int(memory.review_summary.get("read_error_count")) > 0
        or review_status == EvidenceSourceStatus.SKIPPED.value
    ):
        detected.add("review_missing_evidence")

    if _status_value(memory.notification_result.get("status")) == "failed":
        detected.add("notification_failed")

    if _status_value(memory.evidence_status.get("logs")) == EvidenceSourceStatus.NOT_AVAILABLE.value:
        detected.add("logs_not_available")

    return tuple(item for item in LEARNING_SIGNAL_TYPES if item in detected)


def _select_evidence_refs(
    memory: IncidentMemoryRecord,
    preferred_kinds: Sequence[str],
) -> list[ArtifactReference]:
    selected: list[ArtifactReference] = []
    seen: set[tuple[str, str]] = set()
    preferred = set(preferred_kinds)

    for ref in memory.artifact_refs:
        if ref.kind not in preferred:
            continue
        key = (ref.kind, ref.path)
        if key not in seen:
            selected.append(ref)
            seen.add(key)

    # LearningSignalRecord requires at least one evidence reference.  Falling
    # back to the first metadata-only request artifact keeps the signal
    # traceable without copying any raw content.
    if not selected:
        selected.append(memory.artifact_refs[0])
    return selected


def _dedupe_key(memory: IncidentMemoryRecord, signal_type: str) -> str:
    hostname = str(memory.device.get("hostname") or memory.device.get("device_ip") or "unknown")
    object_name = str(memory.object.get("name") or memory.object.get("interface") or "unknown")
    family = memory.family or "unknown"
    value = f"{signal_type}|{family}|{hostname}|{object_name}"
    return value[:512]


def _signal_id(memory: IncidentMemoryRecord, signal_type: str, dedupe_key: str) -> str:
    material = f"{memory.request_id}|{signal_type}|{dedupe_key}".encode("utf-8")
    digest = hashlib.sha256(material).hexdigest()[:24]
    return f"signal_{digest}"


def _reason(memory: IncidentMemoryRecord, signal_type: str) -> str:
    reasons = {
        "classification_fallback": "Incident classification used a fallback or generic family.",
        "playbook_missing": "No governed Playbook matched the incident plan.",
        "policy_blocked": "The evidence plan was blocked by the safety policy.",
        "prometheus_not_configured": "Prometheus evidence was not configured for this incident.",
        "prometheus_no_data": "Prometheus evidence completed without usable data.",
        "prometheus_failed": "Prometheus evidence collection failed.",
        "command_failed": (
            "One or more read-only device commands failed "
            f"(failed={_non_negative_int(memory.command_summary.get('failed'))})."
        ),
        "cli_hard_error": (
            "Device output contained CLI hard errors "
            f"(count={_non_negative_int(memory.command_summary.get('hard_error_count'))})."
        ),
        "review_missing_evidence": "Review identified missing or unreadable evidence.",
        "notification_failed": "The governed AI notification was not sent successfully.",
        "runner_false_negative": "An acceptance runner result conflicted with the production-chain result.",
        "model_parse_failed": "The model response could not be parsed into the required structure.",
        "logs_not_available": (
            "Logs evidence is not available because the Elasticsearch query interface is pending."
        ),
    }
    return reasons[signal_type]


def detect_learning_signals(
    memory: IncidentMemoryRecord | Mapping[str, Any],
    *,
    generated_at: datetime | None = None,
) -> tuple[LearningSignalRecord, ...]:
    """Return deterministic, schema-valid Learning Signals for one memory.

    This function is side-effect free.  It does not write the Governance Store
    and never performs network or device calls.
    """

    record = _coerce_memory(memory)
    created_at = generated_at or datetime.now(timezone.utc)
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise ValueError("generated_at must include timezone information")
    created_at = created_at.astimezone(timezone.utc)

    signals: list[LearningSignalRecord] = []
    for signal_type in _detected_signal_types(record):
        rule = _SIGNAL_RULES[signal_type]
        dedupe_key = _dedupe_key(record, signal_type)
        signals.append(
            LearningSignalRecord(
                signal_id=_signal_id(record, signal_type, dedupe_key),
                request_id=record.request_id,
                created_at=created_at,
                signal_type=signal_type,
                severity=rule.severity,
                detected_from=list(rule.detected_from),
                reason=_reason(record, signal_type),
                evidence_refs=_select_evidence_refs(record, rule.evidence_kinds),
                dedupe_key=dedupe_key,
                proposal_eligible=rule.proposal_eligible,
            )
        )
    return tuple(signals)


def signal_detection_summary(signals: Iterable[LearningSignalRecord]) -> dict[str, Any]:
    records = tuple(signals)
    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    eligible = 0
    for signal in records:
        by_type[signal.signal_type] = by_type.get(signal.signal_type, 0) + 1
        severity = (
            signal.severity.value
            if isinstance(signal.severity, LearningSignalSeverity)
            else str(signal.severity)
        )
        by_severity[severity] = by_severity.get(severity, 0) + 1
        if signal.proposal_eligible:
            eligible += 1
    return {
        "total": len(records),
        "proposal_eligible": eligible,
        "non_proposal": len(records) - eligible,
        "by_type": dict(sorted(by_type.items())),
        "by_severity": dict(sorted(by_severity.items())),
    }


__all__ = [
    "SignalRule",
    "detect_learning_signals",
    "signal_detection_summary",
]
