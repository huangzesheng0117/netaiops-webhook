"""Build compact v11 Incident Memory records from v10 request artifacts.

Incident Memory is a governed summary, not a second copy of the runtime data.
This module extracts bounded facts and statuses, retains metadata-only artifact
references, and never copies raw payloads, device output, Prometheus samples,
or notification payload previews into the memory record.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from .artifact_reader import RequestArtifactBundle, git_metadata
from .contracts import EvidenceSourceStatus, LOGS_NOT_AVAILABLE_REASON
from .schemas import ArtifactReference, IncidentMemoryRecord

_WHITESPACE_RE = re.compile(r"\s+")


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> Sequence[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return value
    return ()


def _pick(mapping: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        value = mapping.get(name)
        if value not in (None, "", [], {}):
            return value
    return None


def _text(value: Any, *, limit: int = 600) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        text = str(value)
    else:
        return ""
    text = _WHITESPACE_RE.sub(" ", text).strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + "..."


def _integer(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    try:
        result = int(value)
    except (TypeError, ValueError):
        return default
    return max(0, result)


def _aware_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _unwrap_section(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    data = payload.get("data")
    return data if isinstance(data, Mapping) else payload


def _first_event(normalized: Mapping[str, Any]) -> Mapping[str, Any]:
    events = normalized.get("events")
    if isinstance(events, list) and events and isinstance(events[0], Mapping):
        return events[0]
    event = normalized.get("event")
    return event if isinstance(event, Mapping) else {}


def _status_text(value: Any) -> str:
    return _text(value, limit=80).lower().replace(" ", "_")


def _metrics_status(
    prometheus: Mapping[str, Any],
    evidence_hub_summary: Mapping[str, Any],
    evidence_hub_metrics: Mapping[str, Any],
) -> EvidenceSourceStatus:
    direct = _status_text(_pick(prometheus, "status", "evidence_status"))
    if direct in {"success", "ok", "completed", "found"}:
        return EvidenceSourceStatus.SUCCESS
    if direct in {"partial", "warning"}:
        return EvidenceSourceStatus.PARTIAL
    if direct in {"no_data", "nodata", "empty", "missing"}:
        return EvidenceSourceStatus.NO_DATA
    if direct in {"failed", "error", "timeout"}:
        return EvidenceSourceStatus.FAILED
    if direct in {"not_configured", "disabled"}:
        return EvidenceSourceStatus.NOT_CONFIGURED

    summary = _mapping(evidence_hub_summary.get("summary"))
    statuses = _mapping(summary.get("evidence_status"))
    hub_status = _status_text(statuses.get("metrics"))
    section_status = _status_text(evidence_hub_metrics.get("status"))
    combined = hub_status or section_status
    if combined in {"found", "generated", "success", "ok"}:
        return EvidenceSourceStatus.SUCCESS
    if combined in {"partial", "warning"}:
        return EvidenceSourceStatus.PARTIAL
    if combined in {"missing", "no_data", "empty"}:
        return EvidenceSourceStatus.NO_DATA
    if combined in {"failed", "error", "read_error"}:
        return EvidenceSourceStatus.FAILED
    return EvidenceSourceStatus.NOT_CONFIGURED


def _device_status(execution: Mapping[str, Any]) -> EvidenceSourceStatus:
    status = _status_text(_pick(execution, "execution_status", "status"))
    if status in {"completed", "success", "ok"}:
        return EvidenceSourceStatus.SUCCESS
    if status in {"partial", "warning", "needs_attention"}:
        return EvidenceSourceStatus.PARTIAL
    if status in {"failed", "error", "timeout", "blocked"}:
        return EvidenceSourceStatus.FAILED
    if status in {"not_configured", "disabled"}:
        return EvidenceSourceStatus.NOT_CONFIGURED
    return EvidenceSourceStatus.SKIPPED


def _review_status(review: Mapping[str, Any]) -> EvidenceSourceStatus:
    status = _status_text(_pick(review, "review_status", "status"))
    if status in {"completed", "success", "ok"}:
        return EvidenceSourceStatus.SUCCESS
    if status in {"needs_attention", "partial", "warning"}:
        return EvidenceSourceStatus.PARTIAL
    if status in {"failed", "error", "blocked"}:
        return EvidenceSourceStatus.FAILED
    return EvidenceSourceStatus.SKIPPED


def _notification_status(send_result: Mapping[str, Any]) -> EvidenceSourceStatus:
    if not send_result:
        return EvidenceSourceStatus.SKIPPED
    if bool(send_result.get("sent")) and bool(send_result.get("ok", True)):
        return EvidenceSourceStatus.SUCCESS
    if send_result.get("sent") is False or send_result.get("error"):
        return EvidenceSourceStatus.FAILED
    return EvidenceSourceStatus.PARTIAL


def _command_summary(execution: Mapping[str, Any]) -> dict[str, Any]:
    stats = _mapping(execution.get("stats"))
    results = execution.get("command_results")
    total = _integer(
        _pick(stats, "total_commands", "command_total"),
        len(results) if isinstance(results, list) else 0,
    )
    completed = _integer(
        _pick(stats, "completed_commands", "command_completed", "success_count")
    )
    failed = _integer(
        _pick(stats, "failed_commands", "command_failed", "failed_count")
    )
    partial = _integer(
        _pick(stats, "partial_commands", "command_partial", "partial_count")
    )
    hard_errors = _integer(
        _pick(stats, "hard_error_count", "cli_hard_error_count")
    )
    return {
        "status": _text(_pick(execution, "execution_status", "status"), limit=80),
        "total": total,
        "completed": completed,
        "failed": failed,
        "partial": partial,
        "hard_error_count": hard_errors,
        "readonly_only": bool(execution.get("readonly_only", False)),
        "execution_source": _text(execution.get("execution_source"), limit=80),
    }


def _review_summary(
    review: Mapping[str, Any],
    evidence_hub_summary: Mapping[str, Any],
) -> dict[str, Any]:
    findings = review.get("key_findings")
    recommendations = review.get("recommendations")
    missing_sections = evidence_hub_summary.get("missing_sections")
    read_errors = evidence_hub_summary.get("read_error_sections")
    return {
        "status": _text(_pick(review, "review_status", "status"), limit=80),
        "execution_status": _text(review.get("execution_status"), limit=80),
        "conclusion": _text(review.get("conclusion"), limit=700),
        "key_findings_count": len(findings) if isinstance(findings, list) else 0,
        "recommendations_count": (
            len(recommendations) if isinstance(recommendations, list) else 0
        ),
        "missing_evidence_count": (
            len(missing_sections) if isinstance(missing_sections, list) else 0
        ),
        "read_error_count": len(read_errors) if isinstance(read_errors, list) else 0,
    }


def _notification_result(
    slim: Mapping[str, Any],
    send_result: Mapping[str, Any],
) -> dict[str, Any]:
    status = _notification_status(send_result)
    return {
        "status": status.value,
        "sent": bool(send_result.get("sent", False)),
        "transport": _text(send_result.get("transport"), limit=80),
        "http_code": _integer(send_result.get("http_code")),
        "business_code": _text(send_result.get("business_code"), limit=80),
        "error": _text(send_result.get("error"), limit=240),
        "detail_available": bool(slim.get("detail_available", False)),
        "detail_url": _text(slim.get("detail_url"), limit=500),
    }


def _quality_flags(
    *,
    bundle: RequestArtifactBundle,
    analysis: Mapping[str, Any],
    plan: Mapping[str, Any],
    execution: Mapping[str, Any],
    review: Mapping[str, Any],
    statuses: Mapping[str, EvidenceSourceStatus],
    command_summary: Mapping[str, Any],
) -> list[str]:
    flags: set[str] = set()
    if bundle.read_errors:
        flags.add("artifact_read_error")
    if bundle.warnings:
        flags.add("artifact_discovery_warning")

    analysis_status = _status_text(_pick(analysis, "analysis_status", "status"))
    if analysis_status and analysis_status not in {"success", "completed", "ok"}:
        flags.add("analysis_failed")
    if _text(analysis.get("error_type"), limit=80):
        flags.add("model_parse_failed")

    classification = _mapping(plan.get("classification"))
    family = _status_text(classification.get("family"))
    match_reason = _status_text(classification.get("match_reason"))
    if "fallback" in family or "fallback" in match_reason or family.startswith("generic_"):
        flags.add("classification_fallback")

    playbook = _mapping(plan.get("playbook"))
    if playbook and playbook.get("matched") is False:
        flags.add("playbook_missing")

    policy = _mapping(plan.get("policy_result"))
    policy_status = _status_text(_pick(policy, "status", "result", "decision"))
    plan_status = _status_text(_pick(plan, "plan_status", "status"))
    if policy_status in {"blocked", "denied", "rejected"} or plan_status == "blocked":
        flags.add("policy_blocked")

    metrics = statuses["metrics"]
    if metrics == EvidenceSourceStatus.NO_DATA:
        flags.add("prometheus_no_data")
    elif metrics == EvidenceSourceStatus.FAILED:
        flags.add("prometheus_failed")
    elif metrics == EvidenceSourceStatus.NOT_CONFIGURED:
        flags.add("prometheus_not_configured")

    if _integer(command_summary.get("failed")) > 0:
        flags.add("command_failed")
    if _integer(command_summary.get("hard_error_count")) > 0:
        flags.add("cli_hard_error")

    review_state = _status_text(_pick(review, "review_status", "status"))
    if review_state == "needs_attention":
        flags.add("review_needs_attention")
    if statuses["review"] == EvidenceSourceStatus.SKIPPED:
        flags.add("review_missing_evidence")

    if statuses["notification"] == EvidenceSourceStatus.FAILED:
        flags.add("notification_failed")

    # This is an environment capability status, not a production failure and
    # must not become proposal-eligible automatically in Batch 3.
    flags.add("logs_not_available")
    return sorted(flags)


def build_incident_memory(
    bundle: RequestArtifactBundle,
    *,
    generated_at: datetime | None = None,
    source_git_metadata: Mapping[str, Any] | None = None,
) -> IncidentMemoryRecord:
    """Build one strict Incident Memory record from a read-only bundle."""

    if not bundle.artifact_refs:
        raise ValueError(f"no request artifacts found for {bundle.request_id}")

    normalized = bundle.get("normalized_event")
    event = _first_event(normalized)
    analysis = bundle.get("analysis")
    analysis_result = _mapping(analysis.get("result"))
    plan = bundle.get("plan")
    target = _mapping(plan.get("target_scope"))
    classification = _mapping(plan.get("classification"))
    prometheus = bundle.get("prometheus_evidence")
    execution = bundle.get("execution")
    review = bundle.get("review")
    hub_summary = bundle.get("evidence_hub_summary")
    slim = bundle.get("notification_summary_slim")
    send_result = bundle.get("notification_send_result")
    hub_summary_body = _mapping(hub_summary.get("summary"))

    hostname = _text(
        _pick(event, "hostname", "device_name")
        or _pick(target, "hostname", "device_name")
        or _mapping(hub_summary_body.get("device")).get("hostname"),
        limit=255,
    )
    device_ip = _text(
        _pick(event, "device_ip", "ip")
        or _pick(target, "device_ip", "ip")
        or _mapping(hub_summary_body.get("device")).get("device_ip"),
        limit=128,
    )
    object_name = _text(
        _pick(event, "object_name", "interface")
        or _pick(target, "object_name", "interface")
        or hub_summary_body.get("object"),
        limit=255,
    )
    family = _text(
        _pick(review, "family")
        or _pick(classification, "family")
        or _pick(event, "family")
        or hub_summary_body.get("family"),
        limit=160,
    )

    alert_summary = _text(
        _pick(slim, "alert_content")
        or _pick(event, "description", "raw_text", "alarm_type")
        or _pick(plan, "summary")
        or _pick(analysis_result, "summary"),
        limit=600,
    )
    analysis_summary = _text(
        _pick(analysis_result, "summary", "alarm_interpretation")
        or _pick(plan, "summary")
        or hub_summary_body.get("judgement"),
        limit=700,
    )

    statuses: dict[str, EvidenceSourceStatus] = {
        "metrics": _metrics_status(prometheus, hub_summary, {}),
        "device": _device_status(execution),
        "review": _review_status(review),
        "notification": _notification_status(send_result),
        "logs": EvidenceSourceStatus.NOT_AVAILABLE,
    }
    command_summary = _command_summary(execution)
    review_summary = _review_summary(review, hub_summary)
    notification_result = _notification_result(slim, send_result)

    refs = [ArtifactReference.model_validate(ref.to_dict()) for ref in bundle.artifact_refs]
    created_at = generated_at or datetime.now(timezone.utc)
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise ValueError("generated_at must include timezone information")

    return IncidentMemoryRecord(
        memory_id=f"memory_{bundle.request_id}",
        request_id=bundle.request_id,
        created_at=created_at.astimezone(timezone.utc),
        source_type=_text(
            _pick(normalized, "source") or _pick(analysis, "source") or "unknown",
            limit=80,
        ),
        alert_time=_aware_datetime(
            _pick(event, "timestamp", "starts_at", "startsAt")
            or normalized.get("created_at")
            or analysis.get("created_at")
        ),
        device={
            "hostname": hostname,
            "device_ip": device_ip,
            "vendor": _text(
                _pick(event, "vendor") or _pick(target, "vendor"),
                limit=80,
            ),
            "platform": _text(target.get("platform"), limit=80),
        },
        object={
            "type": _text(event.get("object_type"), limit=80),
            "name": object_name,
            "interface": _text(
                _pick(event, "interface") or _pick(target, "interface"),
                limit=255,
            ),
            "direction": _text(
                _pick(event, "direction")
                or _pick(target, "direction", "traffic_direction"),
                limit=80,
            ),
        },
        family=family,
        alert_summary=alert_summary,
        analysis_summary=analysis_summary,
        evidence_status=statuses,
        command_summary=command_summary,
        review_summary=review_summary,
        notification_result=notification_result,
        quality_flags=_quality_flags(
            bundle=bundle,
            analysis=analysis,
            plan=plan,
            execution=execution,
            review=review,
            statuses=statuses,
            command_summary=command_summary,
        ),
        git_metadata=dict(source_git_metadata or git_metadata(bundle.project_root)),
        artifact_refs=refs,
    )


def memory_safety_summary(memory: IncidentMemoryRecord) -> dict[str, Any]:
    """Return explicit non-sensitive assertions for acceptance tooling."""

    payload = memory.to_payload()
    # Artifact references are allowed to name raw source files. Safety here
    # checks only the embedded summary body, excluding metadata-only refs.
    payload.pop("artifact_refs", None)
    serialised = str(payload).lower()
    forbidden_keys = (
        "raw_payload",
        "raw_output",
        "command_results",
        "prometheus_samples",
        "payload_preview",
    )
    present = [item for item in forbidden_keys if item in serialised]
    return {
        "safe": not present,
        "forbidden_markers_present": present,
        "artifact_ref_count": len(memory.artifact_refs),
        "logs_status": memory.evidence_status["logs"].value,
        "logs_reason": LOGS_NOT_AVAILABLE_REASON,
    }


__all__ = [
    "build_incident_memory",
    "memory_safety_summary",
]
