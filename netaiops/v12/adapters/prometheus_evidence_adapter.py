"""Read-only adapter for existing Prometheus evidence artifacts.

Batch F never calls Prometheus MCP and never renders PromQL. It only reuses the
artifact already produced for the same request by the current v8/v9 sidecar.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from ..contracts import ContractNotice
from ..schema_validator import (
    build_contract_ref,
    build_evidence_ref,
    sanitize_sensitive_data,
    validate_request_id,
)
from ..status import EvidenceStatus


_DEFAULT_ROOT = Path("/opt/netaiops-webhook/data/prometheus_evidence")
_MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
_ALLOWED_SCOPE_KEYS = (
    "vendor",
    "platform",
    "hostname",
    "device_ip",
    "ip",
    "instance",
    "if_name",
    "ifName",
    "interface",
    "interface_name",
    "interface_regex",
    "interfaces",
    "direction",
    "traffic_direction",
    "link_name",
    "capacity_bps",
    "link_capacity_bps",
    "aggregate_circuit",
    "interface_count",
)
_NO_DATA_STATUSES = frozenset(
    {
        "no_data",
        "empty",
        "empty_result",
        "no_series",
        "no_samples",
        "no_data_or_query_failed",
    }
)
_NOT_AVAILABLE_RECORD_STATUSES = frozenset(
    {
        "runtime_disabled",
        "unavailable",
        "skipped",
        "not_available",
        "not_configured",
        "disabled",
    }
)
_FAILURE_TOKENS = (
    "timeout",
    "exception",
    "failed",
    "error",
    "invalid",
    "mapping",
    "no_usable_query",
    "query_names_empty",
)


class PrometheusEvidenceAdapterError(ValueError):
    """Raised when an existing artifact cannot be safely normalized."""


@dataclass(frozen=True, slots=True)
class NormalizedPrometheusEvidence:
    status: EvidenceStatus
    summary: str
    facts: Mapping[str, Any]
    scope: Mapping[str, Any]
    evidence_refs: tuple[str, ...]
    warnings: tuple[ContractNotice, ...]
    errors: tuple[ContractNotice, ...]
    collected_at: datetime
    reason: str | None
    source_artifact_ref: str
    source_filename: str


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _safe_identifier(value: Any, fallback: str) -> str:
    text = re_sub_identifier(_text(value))
    return (text or fallback)[:191]


def re_sub_identifier(value: str) -> str:
    output = []
    for char in value:
        if (char.isascii() and char.isalnum()) or char in "._:@-":
            output.append(char)
        else:
            output.append("-")
    normalized = "".join(output).strip("-._:@")
    if normalized and not normalized[0].isalnum():
        normalized = "x-" + normalized
    return normalized


def _aware_datetime(value: Any, fallback: datetime) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = _text(value)
        if not text:
            return fallback
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return fallback
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return fallback
    return parsed


def _notice(
    code: str,
    message: str,
    *,
    details: Mapping[str, Any] | None = None,
) -> ContractNotice:
    return ContractNotice(
        code=code,
        message=message,
        stage="metrics_evidence",
        retryable=False,
        details=dict(details or {}),
    )


def _step_is_one_minute(value: Any) -> bool:
    normalized = _text(value).lower().replace(" ", "")
    return normalized in {"60", "60s", "1m", "1min", "1minute"}


def _attempt_has_transport_failure(item: Mapping[str, Any]) -> bool:
    attempts = item.get("attempts") or []
    if not isinstance(attempts, list):
        return False
    for attempt in attempts:
        if not isinstance(attempt, Mapping):
            continue
        if attempt.get("bridge_error") or attempt.get("mcp_error"):
            return True
        if attempt.get("bridge_ok") is False:
            return True
    return False


def _item_class(item: Mapping[str, Any]) -> str:
    if bool(item.get("ok")):
        return "success"
    status = _text(item.get("status")).lower()
    if status in _NO_DATA_STATUSES and not _attempt_has_transport_failure(item):
        return "no_data"
    if any(token in status for token in _FAILURE_TOKENS):
        return "failed"
    if _attempt_has_transport_failure(item):
        return "failed"
    return "no_data" if status in {"", "no_data_or_query_failed"} else "failed"


def _analysis_facts(item: Mapping[str, Any]) -> list[dict[str, Any]]:
    analysis = _mapping(item.get("analysis"))
    analyses = analysis.get("analyses") or []
    output: list[dict[str, Any]] = []
    if not isinstance(analyses, list):
        return output
    allowed = (
        "current",
        "offset",
        "delta",
        "change_ratio",
        "window_max",
        "window_min",
        "window_avg",
        "trend_verdict",
        "sample_count",
    )
    for raw in analyses[:20]:
        if not isinstance(raw, Mapping):
            continue
        fact = {
            key: sanitize_sensitive_data(raw.get(key))
            for key in allowed
            if raw.get(key) is not None
        }
        metric = _mapping(raw.get("metric"))
        if metric:
            safe_metric = {
                str(key): sanitize_sensitive_data(value)
                for key, value in metric.items()
                if str(key).lower()
                not in {"authorization", "cookie", "password", "secret", "token"}
            }
            if safe_metric:
                fact["metric"] = safe_metric
        output.append(fact)
    return output


def _query_fact(item: Mapping[str, Any]) -> dict[str, Any]:
    window = _mapping(item.get("query_window"))
    analysis = _mapping(item.get("analysis"))
    return {
        "query_name": _text(item.get("query_name"))[:128],
        "status": _item_class(item),
        "unit": _text(item.get("unit"))[:64],
        "direction": _text(item.get("direction"))[:64],
        "query_window": {
            "lookback_minutes": window.get("lookback_minutes"),
            "compare_offset_minutes": window.get("compare_offset_minutes"),
            "step": _text(window.get("step"))[:32],
            "start_iso_utc": _text(window.get("start_iso_utc"))[:64],
            "end_iso_utc": _text(window.get("end_iso_utc"))[:64],
        },
        "series_count": analysis.get("series_count"),
        "analyses": _analysis_facts(item),
    }


class PrometheusEvidenceAdapter:
    """Locate and normalize one existing evidence artifact for a request."""

    def __init__(
        self,
        evidence_root: str | Path = _DEFAULT_ROOT,
        *,
        utcnow: Any | None = None,
    ) -> None:
        self.evidence_root = Path(evidence_root)
        self._utcnow = utcnow or (lambda: datetime.now(timezone.utc))

    def find_existing(self, request_id: str) -> Path | None:
        request_id = validate_request_id(request_id)
        root = self.evidence_root
        if not root.exists():
            return None
        if not root.is_dir():
            raise PrometheusEvidenceAdapterError(
                "Prometheus evidence root is not a directory"
            )
        resolved_root = root.resolve()
        patterns = (
            f"*_{request_id}.prometheus_evidence.json",
            f"*_{request_id}.prometheus_evidence.error.json",
        )
        candidates: list[Path] = []
        for pattern in patterns:
            for path in root.glob(pattern):
                if path.is_symlink() or not path.is_file():
                    continue
                resolved = path.resolve()
                if resolved_root not in resolved.parents:
                    continue
                candidates.append(path)
        if not candidates:
            return None
        candidates.sort(
            key=lambda path: (path.stat().st_mtime_ns, path.name),
            reverse=True,
        )
        return candidates[0]

    def load_existing(
        self,
        request_id: str,
    ) -> NormalizedPrometheusEvidence | None:
        path = self.find_existing(request_id)
        if path is None:
            return None
        if path.stat().st_size > _MAX_ARTIFACT_BYTES:
            raise PrometheusEvidenceAdapterError(
                "Prometheus evidence artifact exceeds the read-only size limit"
            )
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PrometheusEvidenceAdapterError(
                f"Prometheus evidence artifact is unreadable: {type(exc).__name__}"
            ) from exc
        if not isinstance(payload, dict):
            raise PrometheusEvidenceAdapterError(
                "Prometheus evidence artifact root must be an object"
            )
        return self.normalize(request_id, payload, source_filename=path.name)

    def normalize(
        self,
        request_id: str,
        payload: Mapping[str, Any],
        *,
        source_filename: str = "existing.prometheus_evidence.json",
    ) -> NormalizedPrometheusEvidence:
        request_id = validate_request_id(request_id)
        record = sanitize_sensitive_data(dict(payload))
        record_request_id = _text(record.get("request_id"))
        if record_request_id and record_request_id != request_id:
            raise PrometheusEvidenceAdapterError(
                "Prometheus evidence request_id does not match invocation"
            )

        now = self._utcnow()
        if now.tzinfo is None or now.utcoffset() is None:
            raise PrometheusEvidenceAdapterError(
                "utcnow provider must return a timezone-aware datetime"
            )
        collected_at = _aware_datetime(record.get("created_at"), now)
        record_status = _text(record.get("status")).lower()
        raw_items = record.get("evidences") or []
        if not isinstance(raw_items, list):
            raise PrometheusEvidenceAdapterError(
                "Prometheus evidence evidences must be a list"
            )

        query_facts: list[dict[str, Any]] = []
        success_names: list[str] = []
        no_data_names: list[str] = []
        failed_names: list[str] = []
        warnings: list[ContractNotice] = []
        errors: list[ContractNotice] = []
        evidence_refs: list[str] = []

        for index, raw_item in enumerate(raw_items):
            if not isinstance(raw_item, Mapping):
                warnings.append(
                    _notice(
                        "metrics_item_invalid",
                        "A Prometheus evidence item was not an object",
                        details={"index": index},
                    )
                )
                continue
            item = sanitize_sensitive_data(dict(raw_item))
            fact = _query_fact(item)
            query_facts.append(fact)
            query_name = fact["query_name"] or f"query-{index + 1}"
            classification = fact["status"]
            if classification == "success":
                success_names.append(query_name)
                identifier = _safe_identifier(
                    f"{query_name}-{hashlib.sha256(query_name.encode('utf-8')).hexdigest()[:10]}",
                    f"query-{index + 1}",
                )
                evidence_refs.append(
                    build_evidence_ref(request_id, "metrics", identifier)
                )
            elif classification == "no_data":
                no_data_names.append(query_name)
            else:
                failed_names.append(query_name)

            step = _mapping(item.get("query_window")).get("step")
            if step and not _step_is_one_minute(step):
                warnings.append(
                    _notice(
                        "metrics_step_not_1m",
                        "Existing Prometheus evidence did not use 1m precision",
                        details={"query_name": query_name, "step": _text(step)},
                    )
                )

        reason: str | None = None
        if record_status in _NOT_AVAILABLE_RECORD_STATUSES and not raw_items:
            status = EvidenceStatus.NOT_AVAILABLE
            reason = _text(record.get("reason")) or record_status
        elif success_names and (no_data_names or failed_names or warnings):
            status = EvidenceStatus.PARTIAL
        elif success_names:
            status = EvidenceStatus.SUCCESS
        elif no_data_names and not failed_names:
            status = EvidenceStatus.NO_DATA
        elif failed_names or any(
            token in record_status for token in _FAILURE_TOKENS
        ):
            status = EvidenceStatus.FAILED
        elif not raw_items:
            status = EvidenceStatus.NOT_AVAILABLE
            reason = (
                _text(record.get("reason"))
                or record_status
                or "existing_prometheus_evidence_empty"
            )
        else:
            status = EvidenceStatus.FAILED

        for name in failed_names:
            errors.append(
                _notice(
                    "metrics_query_failed",
                    "Existing Prometheus query evidence failed",
                    details={"query_name": name},
                )
            )
        for name in no_data_names:
            warnings.append(
                _notice(
                    "metrics_query_no_data",
                    "Existing Prometheus query returned no usable data",
                    details={"query_name": name},
                )
            )

        profile = _text(record.get("profile"))[:128]
        target = _mapping(record.get("target_context"))
        if not target and raw_items:
            target = _mapping(_mapping(raw_items[0]).get("target"))
        scope = {
            key: sanitize_sensitive_data(target.get(key))
            for key in _ALLOWED_SCOPE_KEYS
            if target.get(key) not in (None, "", [], {})
        }
        if profile:
            scope["profile"] = profile
        scope["query_names"] = [
            _text(item.get("query_name"))[:128]
            for item in query_facts
            if _text(item.get("query_name"))
        ]

        facts = {
            "reuse_existing_evidence": True,
            "prometheus_mcp_called": False,
            "promql_generation_performed": False,
            "source_record_status": record_status,
            "query_count": len(query_facts),
            "successful_query_count": len(success_names),
            "no_data_query_count": len(no_data_names),
            "failed_query_count": len(failed_names),
            "successful_query_names": success_names,
            "no_data_query_names": no_data_names,
            "failed_query_names": failed_names,
            "query_results": query_facts,
        }

        source_digest = hashlib.sha256(
            source_filename.encode("utf-8")
        ).hexdigest()[:16]
        source_artifact_ref = build_contract_ref(
            "artifact",
            request_id,
            "prometheus_evidence",
            f"existing-{source_digest}",
        )

        if status == EvidenceStatus.SUCCESS:
            summary = (
                f"Reused existing Prometheus evidence: "
                f"{len(success_names)}/{len(query_facts)} queries succeeded."
            )
        elif status == EvidenceStatus.PARTIAL:
            summary = (
                f"Reused partial Prometheus evidence: "
                f"{len(success_names)} succeeded, "
                f"{len(no_data_names)} no_data, "
                f"{len(failed_names)} failed."
            )
        elif status == EvidenceStatus.NO_DATA:
            summary = (
                f"Existing Prometheus evidence contained no usable series "
                f"for {len(no_data_names)} queries."
            )
        elif status == EvidenceStatus.NOT_AVAILABLE:
            summary = "Existing Prometheus evidence was not available."
        else:
            summary = "Existing Prometheus evidence failed normalization or query checks."

        return NormalizedPrometheusEvidence(
            status=status,
            summary=summary,
            facts=MappingProxyType(sanitize_sensitive_data(facts)),
            scope=MappingProxyType(sanitize_sensitive_data(scope)),
            evidence_refs=tuple(evidence_refs),
            warnings=tuple(warnings),
            errors=tuple(errors),
            collected_at=collected_at,
            reason=reason,
            source_artifact_ref=source_artifact_ref,
            source_filename=source_filename,
        )
