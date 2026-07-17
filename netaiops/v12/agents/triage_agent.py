"""Deterministic v12 Triage Agent.

Batch D wraps the existing Alertmanager / Elastic normalizers and the current
Family Registry. It performs no aggregation and no external calls.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping

from pydantic import ValidationError

from netaiops.family_registry import classify_family

from ..adapters.normalizer_adapter import (
    NormalizedEventSelectionError,
    NormalizerAdapter,
    UnsupportedAlertSourceError,
)
from ..contracts import (
    AlertObject,
    ContractNotice,
    DeviceIdentity,
    UnifiedAlertEvent,
)
from ..execution_context import AgentInvocation, AgentOutcome
from ..schema_validator import build_contract_ref, sanitize_sensitive_data
from ..status import (
    AgentName,
    AgentStatus,
    AlertLifecycleStatus,
    AlertSource,
)


_IDENTIFIER_RE = re.compile(r"[^A-Za-z0-9._:@/-]+")
_RESOLVED_VALUES = frozenset(
    {"resolved", "recovered", "recovery", "closed", "clear", "cleared", "ok"}
)


def _text(value: Any) -> str:
    if value in (None, "", [], {}):
        return ""
    return str(value).strip()


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _pick(event: Mapping[str, Any], *keys: str) -> str:
    labels = _mapping(event.get("labels"))
    annotations = _mapping(event.get("annotations"))
    for key in keys:
        for source in (event, labels, annotations):
            value = source.get(key)
            text = _text(value)
            if text:
                return text
    return ""


def _optional(value: Any) -> str | None:
    text = _text(value)
    return text or None


def _safe_identifier(value: Any, fallback: str) -> str:
    text = _IDENTIFIER_RE.sub("-", _text(value)).strip("-./:")
    if not text:
        text = fallback
    if not text[0].isalnum():
        text = f"x-{text}"
    return text[:128]


def _safe_string_map(value: Any) -> dict[str, str]:
    output: dict[str, str] = {}
    for key, item in sorted(_mapping(value).items(), key=lambda pair: str(pair[0])):
        if isinstance(item, (str, int, float, bool)) or item is None:
            output[str(key)] = _text(item)[:2048]
    return output


def _aware_datetime(
    value: Any,
    *,
    fallback: datetime,
) -> tuple[datetime, str | None]:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = _text(value)
        if not text:
            return fallback, "timestamp_missing"
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return fallback, "timestamp_invalid"

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return parsed.replace(tzinfo=timezone.utc), "timestamp_timezone_assumed"
    return parsed, None


def _lifecycle_status(value: Any) -> tuple[AlertLifecycleStatus, str | None]:
    status = _text(value).lower()
    if status in _RESOLVED_VALUES:
        return AlertLifecycleStatus.RESOLVED, None
    if status in {"", "firing", "active", "open", "triggered", "failed", "failure"}:
        warning = "lifecycle_status_missing" if not status else None
        return AlertLifecycleStatus.FIRING, warning
    return AlertLifecycleStatus.FIRING, "lifecycle_status_unrecognized"


def _stable_digest(parts: list[str], length: int = 24) -> str:
    canonical = json.dumps(parts, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:length]


def _correlation_hints(
    *,
    family: str,
    device_name: str,
    device_ip: str,
    object_kind: str,
    object_name: str,
    site: str,
    event_key: str,
) -> list[str]:
    values = [
        f"family:{family}",
        f"event_key:{event_key}",
    ]
    if device_ip:
        values.append(f"device_ip:{device_ip}")
    if device_name:
        values.append(f"hostname:{device_name}")
    if object_name:
        values.append(f"object:{object_kind}:{object_name}")
    if site:
        values.append(f"site:{site}")

    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = value[:512]
        if normalized not in seen:
            seen.add(normalized)
            output.append(normalized)
    return output


class TriageAgent:
    """Normalize one alert and classify it through the current Family Registry."""

    def __init__(
        self,
        *,
        source: str,
        payload: Mapping[str, Any],
        event_index: int = 0,
        received_at: datetime | None = None,
        raw_payload_ref: str | None = None,
        adapter: NormalizerAdapter | None = None,
    ) -> None:
        self.source = _text(source).lower()
        self.payload = dict(payload)
        self.event_index = int(event_index)
        self.received_at = received_at
        self.raw_payload_ref = raw_payload_ref
        self.adapter = adapter or NormalizerAdapter()

    async def run(self, invocation: AgentInvocation) -> AgentOutcome:
        if invocation.agent_name != AgentName.TRIAGE:
            return self._failed(
                "triage_agent_name_mismatch",
                "TriageAgent can only run as the triage Agent",
            )

        now = self.received_at or datetime.now(timezone.utc)
        if now.tzinfo is None or now.utcoffset() is None:
            return self._failed(
                "triage_received_at_naive",
                "received_at must include timezone information",
            )

        try:
            event = self.adapter.select_event(
                self.source,
                self.payload,
                event_index=self.event_index,
            )
            family_result = classify_family(dict(event))
            unified, warnings = self._build_unified_event(
                invocation.request_id,
                event,
                family_result,
                now,
            )
        except (
            UnsupportedAlertSourceError,
            NormalizedEventSelectionError,
            ValidationError,
            ValueError,
        ) as exc:
            return self._failed(
                "triage_validation_failed",
                "Triage input could not be normalized into UnifiedAlertEvent",
                details={"exception_type": type(exc).__name__},
            )

        output_ref = build_contract_ref(
            "event",
            invocation.request_id,
            "unified_alert",
            unified.event_id,
        )
        status = AgentStatus.PARTIAL if warnings else AgentStatus.SUCCESS
        return AgentOutcome(
            status=status,
            output_refs=(output_ref,),
            output={
                "unified_event": unified.model_dump(mode="json"),
                "event_key": unified.event_key,
                "correlation_hints": list(unified.correlation_hints),
                "aggregation_performed": False,
            },
            warnings=tuple(warnings),
        )

    def _build_unified_event(
        self,
        request_id: str,
        event: Mapping[str, Any],
        family_result: Mapping[str, Any],
        received_at: datetime,
    ) -> tuple[UnifiedAlertEvent, list[ContractNotice]]:
        warnings: list[ContractNotice] = []

        source = AlertSource(self.source)
        alert_status, lifecycle_warning = _lifecycle_status(
            _pick(event, "status", "alert_status", "outcome")
        )
        if lifecycle_warning:
            warnings.append(self._warning(lifecycle_warning))

        occurred_at, time_warning = _aware_datetime(
            _pick(event, "timestamp", "occurred_at", "startsAt"),
            fallback=received_at,
        )
        if time_warning:
            warnings.append(self._warning(time_warning))

        ends_at: datetime | None = None
        raw_ends_at = _pick(event, "_v12_ends_at", "ends_at", "endsAt")
        if raw_ends_at:
            ends_at, ends_warning = _aware_datetime(
                raw_ends_at,
                fallback=received_at,
            )
            if ends_warning:
                warnings.append(self._warning(f"ends_at_{ends_warning}"))

        alert_name = _pick(event, "alarm_type", "event_type", "alertname")
        if not alert_name:
            alert_name = "unknown-alert"
            warnings.append(self._warning("alert_name_missing"))

        device_name = _pick(
            event,
            "hostname",
            "device_name",
            "sysName",
            "host",
            "instance",
        )
        device_ip = _pick(event, "device_ip", "ip", "host_ip")
        if not device_ip:
            warnings.append(self._warning("device_ip_missing"))
        if not device_name and not device_ip:
            device_name = "unknown-device"
            warnings.append(self._warning("device_identity_missing"))

        family = _safe_identifier(
            family_result.get("family"),
            "generic_network_readonly",
        )
        target_scope = dict(_mapping(family_result.get("target_scope")))
        object_kind = _safe_identifier(
            family_result.get("target_kind")
            or _pick(event, "object_type", "kind"),
            "generic",
        )
        object_name = (
            _pick(
                event,
                "object_name",
                "interface",
                "ifName",
                "if_name",
                "pool_member",
                "peer_ip",
                "neighbor_ip",
            )
            or _text(target_scope.get("interface"))
            or _text(target_scope.get("pool_member"))
            or _text(target_scope.get("peer_ip"))
            or alert_name
        )
        if object_name == alert_name:
            warnings.append(self._warning("alert_object_fallback"))

        site = _pick(event, "site")
        vendor = _pick(event, "vendor")
        platform = _pick(event, "platform")

        event_key = (
            f"event:{source.value}:{family}:"
            f"{_stable_digest([device_name, device_ip, object_kind, object_name, alert_name])}"
        )
        raw_fingerprint = _pick(event, "_v12_fingerprint", "fingerprint")
        if raw_fingerprint:
            event_id = _safe_identifier(raw_fingerprint, "event")
        else:
            event_id = (
                "evt-"
                + _stable_digest(
                    [
                        event_key,
                        occurred_at.isoformat(),
                        str(self.event_index),
                    ]
                )
            )

        hints = _correlation_hints(
            family=family,
            device_name=device_name,
            device_ip=device_ip,
            object_kind=object_kind,
            object_name=object_name,
            site=site,
            event_key=event_key,
        )

        attributes = sanitize_sensitive_data(
            {
                "family_confidence": family_result.get("family_confidence", ""),
                "match_source": family_result.get("match_source", ""),
                "match_reason": family_result.get("match_reason", ""),
                "auto_execute_allowed": bool(
                    family_result.get("auto_execute_allowed", False)
                ),
                "target_scope": target_scope,
                "aggregation_performed": False,
            }
        )

        unified = UnifiedAlertEvent(
            schema_version="v12.1",
            request_id=request_id,
            event_id=event_id,
            source=source,
            alert_status=alert_status,
            alert_name=alert_name[:512],
            occurred_at=occurred_at,
            received_at=received_at,
            ends_at=ends_at,
            device=DeviceIdentity(
                name=_optional(device_name),
                ip=_optional(device_ip),
                vendor=_optional(vendor),
                platform=_optional(platform),
                site=_optional(site),
            ),
            alert_object=AlertObject(
                kind=object_kind,
                name=object_name[:512],
                identifier=_optional(object_name[:512]),
                attributes=attributes,
            ),
            labels=_safe_string_map(event.get("labels")),
            annotations=_safe_string_map(event.get("annotations")),
            family=family,
            event_key=event_key,
            correlation_hints=hints,
            raw_payload_ref=self.raw_payload_ref,
        )
        return unified, warnings

    def _warning(self, code: str) -> ContractNotice:
        messages = {
            "alert_name_missing": "Alert name was missing and a safe fallback was used",
            "alert_object_fallback": "Alert object used the alert name fallback",
            "device_identity_missing": "Device name and IP were both missing",
            "device_ip_missing": "Device IP was not available",
            "lifecycle_status_missing": "Lifecycle status was missing and treated as firing",
            "lifecycle_status_unrecognized": (
                "Lifecycle status was unrecognized and treated as firing"
            ),
            "timestamp_invalid": "Alert timestamp was invalid and received_at was used",
            "timestamp_missing": "Alert timestamp was missing and received_at was used",
            "timestamp_timezone_assumed": (
                "Alert timestamp had no timezone and UTC was assumed"
            ),
        }
        return ContractNotice(
            code=_safe_identifier(code, "triage_warning"),
            message=messages.get(code, "Triage normalized an incomplete field"),
            stage="triage",
            retryable=False,
        )

    def _failed(
        self,
        code: str,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> AgentOutcome:
        return AgentOutcome(
            status=AgentStatus.FAILED,
            errors=(
                ContractNotice(
                    code=code,
                    message=message,
                    stage="triage",
                    retryable=False,
                    details=details or {},
                ),
            ),
        )
