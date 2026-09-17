"""Deterministic incident-time resolution with explicit provenance audit."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .logs_contracts import IncidentTimeDecision, IncidentTimeSource


class IncidentTimeResolutionError(ValueError):
    pass


def _parse(value: Any, label: str) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise IncidentTimeResolutionError(f"invalid {label} timestamp") from exc
    else:
        raise IncidentTimeResolutionError(f"unsupported {label} timestamp type")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise IncidentTimeResolutionError(f"{label} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def resolve_incident_time(
    *,
    explicit_fault_time: Any = None,
    alertmanager_starts_at: Any = None,
    prometheus_firing_time: Any = None,
    webhook_received_at: Any = None,
) -> IncidentTimeDecision:
    ordered = (
        (IncidentTimeSource.EXPLICIT_FAULT_TIME, explicit_fault_time),
        (IncidentTimeSource.ALERTMANAGER_STARTS_AT, alertmanager_starts_at),
        (IncidentTimeSource.PROMETHEUS_FIRING_TIME, prometheus_firing_time),
        (IncidentTimeSource.WEBHOOK_RECEIVED_AT, webhook_received_at),
    )
    parsed: list[tuple[IncidentTimeSource, datetime]] = []
    invalid: list[IncidentTimeSource] = []
    present: list[IncidentTimeSource] = []
    for source, raw in ordered:
        if raw in (None, ""):
            continue
        present.append(source)
        try:
            value = _parse(raw, source.value)
        except IncidentTimeResolutionError:
            invalid.append(source)
            continue
        if value is not None:
            parsed.append((source, value))
    if not parsed:
        raise IncidentTimeResolutionError("no valid incident-time source available")
    selected_source, selected_time = parsed[0]
    fallback_used = selected_source == IncidentTimeSource.WEBHOOK_RECEIVED_AT
    reason = f"selected highest-priority valid source: {selected_source.value}"
    if invalid:
        reason += "; invalid higher/lower candidates audited"
    return IncidentTimeDecision(
        incident_time=selected_time,
        source=selected_source,
        fallback_used=fallback_used,
        selection_reason=reason,
        candidates_present=tuple(present),
        candidates_invalid=tuple(invalid),
    )
