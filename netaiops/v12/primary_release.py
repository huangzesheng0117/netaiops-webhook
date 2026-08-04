"""v12 controlled primary integration with legacy-compatible delivery.

The v12 primary path is intentionally mounted after the existing legacy
notification completes. For approved alert families it creates the canonical
v12 Evidence/Judge/RCA/Report artifacts by using the production-approved
Prometheus MCP, read-only Netmiko MCP and GLM 5.2 collectors. The existing
notification remains the delivery compatibility layer for the initial v12
release, so this module never sends a second card and never replaces the
legacy notification result.

Any failure is fail-open to the already-completed legacy result. Logs and
Knowledge remain not_available and no FastMCP, Evidence MCP, Analytics MCP,
OPS ES API, arbitrary PromQL, arbitrary CLI, DSL, write command or automatic
follow-up query is introduced here.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

import yaml

from netaiops.family_registry import classify_family

from .atomic_writer import AtomicJsonWriter
from .p2_controlled_canary import DEFAULT_ALLOWED_FAMILIES
from .p2_rca_continue import CheckpointedGLMRCACollectorV8
from .p2_real_canary import (
    P2CanarySample,
    P2RealCanaryError,
    P2RealCanaryRunner,
    build_active_p2_settings,
    discover_real_canary_sample,
    load_production_config,
)
from .schema_validator import sanitize_sensitive_data, validate_request_id


PRIMARY_SCHEMA_VERSION = "v12-primary-release-1"
DEFAULT_PROJECT_ROOT = Path("/opt/netaiops-webhook")
DEFAULT_RUNTIME_CONFIG = DEFAULT_PROJECT_ROOT / "config" / "v12_primary.yaml"
DEFAULT_TRACE_ROOT = DEFAULT_PROJECT_ROOT / "data" / "evidence_hub" / "requests"
DEFAULT_GOVERNANCE_ROOT = (
    DEFAULT_PROJECT_ROOT / "data" / "governance" / "agent_traces"
)
DEFAULT_RUNTIME_ROOT = DEFAULT_PROJECT_ROOT / "data" / "v12_primary_runtime"
APPROVED_FAMILIES = (
    "interface_status_or_flap",
    "interface_or_link_utilization_high",
    "interface_traffic_anomaly",
)
_ALLOWED_CONFIG_KEYS = frozenset(
    {
        "schema_version",
        "activation_id",
        "enabled",
        "mode",
        "fail_open_to_legacy",
        "notifications_use_v12",
        "logs_enabled",
        "knowledge_enabled",
        "metrics_real_calls_enabled",
        "device_real_calls_enabled",
        "rca_real_calls_enabled",
        "reuse_existing_evidence_before_real_call",
        "allowed_families",
        "max_metrics_calls_per_request",
        "max_device_calls_per_request",
        "max_rca_calls_per_request",
        "max_total_external_calls_per_request",
    }
)
_FORBIDDEN_CONFIG_KEYS = frozenset(
    {
        "password",
        "passwd",
        "api_key",
        "apikey",
        "authorization",
        "bearer",
        "token",
        "secret",
        "private_key",
    }
)


class PrimaryReleaseError(RuntimeError):
    """Raised when the frozen v12 primary boundary is violated."""


@dataclass(frozen=True, slots=True)
class PrimarySettings:
    schema_version: str
    activation_id: str
    enabled: bool
    mode: str
    fail_open_to_legacy: bool
    notifications_use_v12: bool
    logs_enabled: bool
    knowledge_enabled: bool
    metrics_real_calls_enabled: bool
    device_real_calls_enabled: bool
    rca_real_calls_enabled: bool
    reuse_existing_evidence_before_real_call: bool
    allowed_families: tuple[str, ...]
    max_metrics_calls_per_request: int
    max_device_calls_per_request: int
    max_rca_calls_per_request: int
    max_total_external_calls_per_request: int

    def validate_frozen_boundary(self) -> None:
        if self.schema_version != PRIMARY_SCHEMA_VERSION:
            raise PrimaryReleaseError("primary schema_version mismatch")
        if not self.activation_id.strip():
            raise PrimaryReleaseError("primary activation_id is required")
        if self.mode != "primary":
            raise PrimaryReleaseError("primary mode must be primary")
        if self.fail_open_to_legacy is not True:
            raise PrimaryReleaseError("primary fail_open_to_legacy must be true")
        if self.notifications_use_v12 is not False:
            raise PrimaryReleaseError(
                "initial v12 release must retain legacy-compatible delivery"
            )
        if self.logs_enabled is not False:
            raise PrimaryReleaseError("Logs Agent must remain not_available")
        if self.knowledge_enabled is not False:
            raise PrimaryReleaseError("Knowledge Agent must remain not_available")
        if self.reuse_existing_evidence_before_real_call is not True:
            raise PrimaryReleaseError(
                "primary must inspect existing request artifacts before real calls"
            )
        if not all(
            (
                self.metrics_real_calls_enabled,
                self.device_real_calls_enabled,
                self.rca_real_calls_enabled,
            )
        ):
            raise PrimaryReleaseError(
                "approved primary families require Metrics, Device and RCA"
            )
        if (
            self.max_metrics_calls_per_request,
            self.max_device_calls_per_request,
            self.max_rca_calls_per_request,
            self.max_total_external_calls_per_request,
        ) != (1, 1, 1, 3):
            raise PrimaryReleaseError(
                "primary external-call budget must remain 1/1/1 and total 3"
            )
        normalized = tuple(
            dict.fromkeys(
                str(item).strip()
                for item in self.allowed_families
                if str(item).strip()
            )
        )
        if normalized != self.allowed_families:
            raise PrimaryReleaseError(
                "primary allowed_families must be unique and normalized"
            )
        if not normalized:
            raise PrimaryReleaseError("primary allowed_families is empty")
        unknown = sorted(set(normalized) - set(APPROVED_FAMILIES))
        if unknown:
            raise PrimaryReleaseError(
                "unapproved primary family: " + ", ".join(unknown)
            )
        if set(normalized) - set(DEFAULT_ALLOWED_FAMILIES):
            raise PrimaryReleaseError(
                "primary family is outside the frozen P2 contract"
            )


def _aware_now() -> datetime:
    return datetime.now(timezone.utc)


def _read_json(path: Path) -> Mapping[str, Any] | None:
    if path.is_symlink() or not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, Mapping) else None


def _write_audit(
    *,
    trace_root: Path,
    request_id: str,
    payload: Mapping[str, Any],
) -> Path:
    target = trace_root / request_id / "v12"
    writer = AtomicJsonWriter(target)
    return writer.write_json(
        "primary_integration.json",
        sanitize_sensitive_data(dict(payload)),
    )


def load_primary_settings(
    path: str | Path = DEFAULT_RUNTIME_CONFIG,
) -> PrimarySettings | None:
    config_path = Path(path)
    if not config_path.exists():
        return None
    if config_path.is_symlink() or not config_path.is_file():
        raise PrimaryReleaseError("primary runtime config must be a regular file")
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise PrimaryReleaseError("primary runtime config cannot be decoded") from exc
    if not isinstance(raw, Mapping):
        raise PrimaryReleaseError("primary runtime config root must be an object")
    keys = {str(key) for key in raw}
    unknown = sorted(keys - _ALLOWED_CONFIG_KEYS)
    if unknown:
        raise PrimaryReleaseError(
            "unknown primary runtime keys: " + ", ".join(unknown)
        )
    lowered = {key.lower() for key in keys}
    secret_keys = sorted(lowered & _FORBIDDEN_CONFIG_KEYS)
    if secret_keys:
        raise PrimaryReleaseError(
            "primary runtime config must not contain secrets: "
            + ", ".join(secret_keys)
        )
    families_raw = raw.get("allowed_families") or []
    if isinstance(families_raw, str):
        families_raw = [families_raw]
    settings = PrimarySettings(
        schema_version=str(raw.get("schema_version") or ""),
        activation_id=str(raw.get("activation_id") or ""),
        enabled=raw.get("enabled") is True,
        mode=str(raw.get("mode") or ""),
        fail_open_to_legacy=raw.get("fail_open_to_legacy") is True,
        notifications_use_v12=raw.get("notifications_use_v12") is True,
        logs_enabled=raw.get("logs_enabled") is True,
        knowledge_enabled=raw.get("knowledge_enabled") is True,
        metrics_real_calls_enabled=(
            raw.get("metrics_real_calls_enabled") is True
        ),
        device_real_calls_enabled=(
            raw.get("device_real_calls_enabled") is True
        ),
        rca_real_calls_enabled=raw.get("rca_real_calls_enabled") is True,
        reuse_existing_evidence_before_real_call=(
            raw.get("reuse_existing_evidence_before_real_call") is True
        ),
        allowed_families=tuple(str(item).strip() for item in families_raw),
        max_metrics_calls_per_request=int(
            raw.get("max_metrics_calls_per_request", -1)
        ),
        max_device_calls_per_request=int(
            raw.get("max_device_calls_per_request", -1)
        ),
        max_rca_calls_per_request=int(
            raw.get("max_rca_calls_per_request", -1)
        ),
        max_total_external_calls_per_request=int(
            raw.get("max_total_external_calls_per_request", -1)
        ),
    )
    settings.validate_frozen_boundary()
    return settings




def discover_request_family(project_root: Path, request_id: str) -> str:
    """Read the already-persisted normalized event and classify its family."""
    normalized_root = project_root / "data" / "normalized"
    matches = sorted(normalized_root.glob(f"*_{request_id}.json"))
    if len(matches) != 1:
        raise PrimaryReleaseError(
            "primary normalized request artifact count mismatch: "
            f"request_id={request_id}, observed={len(matches)}"
        )
    payload = _read_json(matches[0])
    if payload is None:
        raise PrimaryReleaseError("primary normalized artifact cannot be decoded")
    events = payload.get("events")
    if not isinstance(events, list) or len(events) != 1:
        raise PrimaryReleaseError("primary requires one normalized event")
    event = events[0]
    if not isinstance(event, Mapping):
        raise PrimaryReleaseError("primary normalized event must be an object")
    result = classify_family(dict(event))
    family = str(result.get("family") or event.get("family") or "").strip()
    if not family:
        raise PrimaryReleaseError("primary request family is empty")
    return family


def _legacy_notification_count(value: Mapping[str, Any] | None) -> int:
    payload = value if isinstance(value, Mapping) else {}
    for key in ("sent_count", "notification_count", "count"):
        try:
            count = int(payload.get(key) or 0)
        except (TypeError, ValueError):
            count = 0
        if count > 0:
            return count
    return 1 if payload.get("ok") is True else 0


def _audit_payload(
    *,
    request_id: str,
    settings: PrimarySettings | None,
    status: str,
    reason: str,
    started_at: datetime,
    notify_result: Mapping[str, Any] | None,
    family: str = "",
    result: Mapping[str, Any] | None = None,
    error: BaseException | None = None,
) -> dict[str, Any]:
    finished_at = _aware_now()
    safe_result = result if isinstance(result, Mapping) else {}
    ledger = safe_result.get("call_ledger")
    ledger = ledger if isinstance(ledger, Mapping) else {}
    call_counts = ledger.get("call_counts")
    call_counts = call_counts if isinstance(call_counts, Mapping) else {}
    payload: dict[str, Any] = {
        "schema_version": PRIMARY_SCHEMA_VERSION,
        "request_id": request_id,
        "activation_id": settings.activation_id if settings else "",
        "enabled": settings.enabled if settings else False,
        "mode": "primary",
        "status": status,
        "reason": reason,
        "family": family,
        "legacy_preserved": True,
        "fail_open_to_legacy": True,
        "legacy_notification_count": _legacy_notification_count(notify_result),
        "v12_notification_count": 0,
        "notification_count_delta": 0,
        "notification_sent": False,
        "second_card_sent": False,
        "production_card_replaced": False,
        "notifications_use_v12": False,
        "logs_status": "not_available",
        "knowledge_status": "not_available",
        "prometheus_mcp_calls": int(call_counts.get("prometheus_mcp") or 0),
        "netmiko_mcp_calls": int(call_counts.get("netmiko_mcp") or 0),
        "glm_rca_calls": int(call_counts.get("glm_rca") or 0),
        "evidence_mcp_called": False,
        "analytics_mcp_called": False,
        "ops_es_api_called": False,
        "fastmcp_called": False,
        "elasticsearch_called": False,
        "write_command_executed": False,
        "command_generation_performed": False,
        "promql_generation_performed": False,
        "dsl_generation_performed": False,
        "automatic_followup_queries": False,
        "trace_written": safe_result.get("status") == "completed",
        "governance_ok": safe_result.get("governance_ok") is True,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_ms": max(
            0,
            int((finished_at - started_at).total_seconds() * 1000),
        ),
    }
    if error is not None:
        payload["error_type"] = type(error).__name__
        payload["error"] = str(error)[:500]
    return payload


def _default_runner_factory(
    *,
    settings: PrimarySettings,
    sample: P2CanarySample,
    request_id: str,
    project_root: Path,
    trace_root: Path,
    governance_root: Path,
    runtime_root: Path,
    production_config: Mapping[str, Any],
) -> P2RealCanaryRunner:
    activation_hash = hashlib.sha256(
        f"{settings.activation_id}:{request_id}".encode("utf-8")
    ).hexdigest()[:12]
    p2_settings = build_active_p2_settings(
        f"q-primary-{settings.activation_id}-{activation_hash}"
    )
    state_root = runtime_root / request_id / "rca"
    state_root.mkdir(parents=True, exist_ok=True)
    os.chmod(state_root, 0o700)
    rca_collector = CheckpointedGLMRCACollectorV8(
        production_config=production_config,
        state_root=state_root,
    )
    return P2RealCanaryRunner(
        settings=p2_settings,
        sample=sample,
        project_root=project_root,
        trace_root=trace_root,
        governance_root=governance_root,
        work_root=runtime_root / request_id,
        production_config=production_config,
        rca_collector=rca_collector,
    )


def run_v12_primary_after_legacy_safe(
    *,
    request_id: str,
    notify_result: Mapping[str, Any] | None = None,
    logger: Any | None = None,
    project_root: str | Path = DEFAULT_PROJECT_ROOT,
    runtime_config: str | Path = DEFAULT_RUNTIME_CONFIG,
    trace_root: str | Path = DEFAULT_TRACE_ROOT,
    governance_root: str | Path = DEFAULT_GOVERNANCE_ROOT,
    runtime_root: str | Path = DEFAULT_RUNTIME_ROOT,
    family_loader: Callable[[Path, str], str] = discover_request_family,
    sample_loader: Callable[..., P2CanarySample] = discover_real_canary_sample,
    production_config_loader: Callable[..., Mapping[str, Any]] = (
        load_production_config
    ),
    runner_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Run the approved v12 primary path once and always preserve legacy.

    This entry is deliberately safe for FastAPI BackgroundTasks. It returns a
    structured status for every branch, never sends a notification and never
    raises into the already-completed legacy response path.
    """

    started_at = _aware_now()
    project = Path(project_root)
    trace = Path(trace_root)
    governance = Path(governance_root)
    runtime = Path(runtime_root)
    try:
        validate_request_id(request_id)
    except Exception as exc:
        return _audit_payload(
            request_id=str(request_id),
            settings=None,
            status="failed_open",
            reason="invalid_request_id",
            started_at=started_at,
            notify_result=notify_result,
            error=exc,
        )

    audit_path = trace / request_id / "v12" / "primary_integration.json"
    existing = _read_json(audit_path)
    if existing and str(existing.get("status")) in {
        "completed",
        "fallback_legacy",
        "failed_open",
    }:
        return dict(existing)

    lock_dir = runtime / "locks"
    lock_path = lock_dir / f"{request_id}.lock"
    try:
        lock_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(lock_dir, 0o700)
        descriptor = os.open(
            lock_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        os.close(descriptor)
    except FileExistsError:
        return _audit_payload(
            request_id=request_id,
            settings=None,
            status="skipped_duplicate",
            reason="primary_request_already_running",
            started_at=started_at,
            notify_result=notify_result,
        )
    except OSError as exc:
        payload = _audit_payload(
            request_id=request_id,
            settings=None,
            status="failed_open",
            reason="primary_lock_failed",
            started_at=started_at,
            notify_result=notify_result,
            error=exc,
        )
        try:
            _write_audit(trace_root=trace, request_id=request_id, payload=payload)
        except Exception:
            pass
        return payload

    settings: PrimarySettings | None = None
    try:
        settings = load_primary_settings(runtime_config)
        if settings is None or not settings.enabled:
            payload = _audit_payload(
                request_id=request_id,
                settings=settings,
                status="disabled",
                reason="v12_primary_disabled",
                started_at=started_at,
                notify_result=notify_result,
            )
            _write_audit(trace_root=trace, request_id=request_id, payload=payload)
            return payload

        family = family_loader(project, request_id)
        if family not in settings.allowed_families:
            payload = _audit_payload(
                request_id=request_id,
                settings=settings,
                status="fallback_legacy",
                reason="family_not_approved_for_v12_primary",
                family=family,
                started_at=started_at,
                notify_result=notify_result,
            )
            _write_audit(trace_root=trace, request_id=request_id, payload=payload)
            return payload

        sample = sample_loader(
            project,
            preferred_request_id=request_id,
        )
        if sample.original_request_id != request_id:
            raise PrimaryReleaseError(
                "pinned primary discovery drifted to another request"
            )
        if sample.family != family:
            raise PrimaryReleaseError(
                "primary Family drifted between normalized event and P2 discovery"
            )

        production_config = production_config_loader(project / "config.yaml")
        factory = runner_factory or _default_runner_factory
        runner = factory(
            settings=settings,
            sample=sample,
            request_id=request_id,
            project_root=project,
            trace_root=trace,
            governance_root=governance,
            runtime_root=runtime,
            production_config=production_config,
        )
        raw_result = asyncio.run(runner.run(request_id))
        if not isinstance(raw_result, Mapping):
            raise PrimaryReleaseError("primary runner result must be an object")
        if raw_result.get("status") != "completed":
            raise PrimaryReleaseError("primary runner did not complete")
        payload = _audit_payload(
            request_id=request_id,
            settings=settings,
            status="completed",
            reason="approved_family_v12_primary_completed",
            family=sample.family,
            started_at=started_at,
            notify_result=notify_result,
            result=raw_result,
        )
        counts = (
            payload["prometheus_mcp_calls"],
            payload["netmiko_mcp_calls"],
            payload["glm_rca_calls"],
        )
        if counts != (1, 1, 1):
            raise PrimaryReleaseError(
                f"primary external-call count mismatch: {counts}"
            )
        _write_audit(trace_root=trace, request_id=request_id, payload=payload)
        return payload
    except Exception as exc:
        payload = _audit_payload(
            request_id=request_id,
            settings=settings,
            status="failed_open",
            reason="v12_primary_failed_open_to_legacy",
            started_at=started_at,
            notify_result=notify_result,
            error=exc,
        )
        payload["traceback_sha256"] = hashlib.sha256(
            traceback.format_exc().encode("utf-8")
        ).hexdigest()
        try:
            _write_audit(trace_root=trace, request_id=request_id, payload=payload)
        except Exception:
            pass
        try:
            if logger is not None:
                logger.exception(
                    "v12 primary failed open request_id=%s: %r",
                    request_id,
                    exc,
                )
        except Exception:
            pass
        return payload
    finally:
        try:
            lock_path.unlink(missing_ok=True)
        except Exception:
            pass
