"""W1 ingress collector, delayed worker, and restart recovery sidecar.

No caller can provide an MCP URL, Elasticsearch index/cluster, DSL, credential,
or unbounded time range. Runtime defaults are disabled. Logs collection is an
independent sidecar and never sends notifications or calls GLM/10004.
"""
from __future__ import annotations

import hashlib
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from .incident_time import IncidentTimeResolutionError, resolve_incident_time
from .logs_artifact_store import (
    LogsArtifactStore,
    sanitize_result_for_checkpoint,
)
from .logs_contracts import (
    LogsArtifactPhase,
    LogsCollectionRequest,
    LogsCollectionResult,
)
from .logs_job_store import (
    AmbiguousPhaseCallError,
    LogsJobRecord,
    LogsJobStore,
    RetryBudgetExhaustedError,
)
from .logs_mcp_client import (
    LogsMcpClient,
    LogsMcpContractError,
    LogsMcpTransportError,
    StreamableHttpMcpTransport,
)
from .profile_resolver import resolve_log_profile
from .runtime_config import (
    FIXED_EVIDENCE_MCP_URL,
    WORKER_POLL_SECONDS,
    LogsRuntimeSettings,
    load_runtime_settings,
)

PROJECT_ROOT = Path("/opt/netaiops-webhook")
ClientFactory = Callable[[], LogsMcpClient]
PROCESS_STARTED_AT = datetime.now(timezone.utc)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _first(mapping: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return None


def _raw_alert_for_index(
    source: str,
    raw_payload: Mapping[str, Any],
    index: int,
) -> Mapping[str, Any]:
    if source != "alertmanager":
        return {}
    alerts = raw_payload.get("alerts")
    if (
        isinstance(alerts, list)
        and 0 <= index < len(alerts)
        and isinstance(alerts[index], Mapping)
    ):
        return alerts[index]
    return {}


def _time_decision(
    source: str,
    raw_alert: Mapping[str, Any],
    event: Mapping[str, Any],
    webhook_received_at: str,
):
    labels = _mapping(event.get("labels"))
    annotations = _mapping(event.get("annotations"))

    explicit = _first(event, ("fault_time", "event_time", "occurred_at"))
    if explicit is None:
        explicit = _first(
            labels,
            ("fault_time", "event_time", "occurred_at"),
        ) or _first(
            annotations,
            ("fault_time", "event_time", "occurred_at"),
        )
    # Elastic's source @timestamp is the explicit event time available to the
    # existing normalized event.  Alertmanager must preserve raw startsAt as a
    # distinct higher-quality provenance instead of inferring from timestamp.
    if explicit is None and source == "elastic":
        explicit = event.get("timestamp")

    starts_at = (
        raw_alert.get("startsAt")
        if source == "alertmanager"
        else None
    )
    firing = (
        _first(event, ("prometheus_firing_time", "firing_time"))
        or _first(
            labels,
            ("prometheus_firing_time", "firing_time", "firingTime"),
        )
        or _first(
            annotations,
            ("prometheus_firing_time", "firing_time", "firingTime"),
        )
    )
    return resolve_incident_time(
        explicit_fault_time=explicit,
        alertmanager_starts_at=starts_at,
        prometheus_firing_time=firing,
        webhook_received_at=webhook_received_at,
    )


def _selectors(event: Mapping[str, Any]) -> dict[str, Any]:
    labels = _mapping(event.get("labels"))
    annotations = _mapping(event.get("annotations"))
    event_code = _first(event, ("event_code",)) or _first(
        labels,
        ("event_code", "mnemonic"),
    )
    severity = event.get("severity") or labels.get("severity")
    keywords: list[str] = []
    # Persist only controlled selector terms. Alert annotations may contain
    # arbitrary operational text and must not be copied into durable job state.
    for value in (event.get("alarm_type"),):
        text = str(value or "").strip()
        if text and len(text) <= 128 and text not in keywords:
            keywords.append(text)
    return {
        "device_ip": str(event.get("device_ip") or "").strip() or None,
        "device_name": str(event.get("hostname") or "").strip() or None,
        "event_code": str(event_code or "").strip() or None,
        "severity": str(severity or "").strip() or None,
        "keywords": tuple(keywords[:5]),
    }


def _default_client() -> LogsMcpClient:
    transport = StreamableHttpMcpTransport(
        FIXED_EVIDENCE_MCP_URL,
        timeout_seconds=45.0,
    )
    try:
        transport.initialize()
    except Exception:
        transport.close()
        raise
    return LogsMcpClient(transport)


def _activation(job: LogsJobRecord, phase: LogsArtifactPhase) -> str:
    material = f"{job.activation_id}:{job.job_id}:{phase.value}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def _request_for_phase(
    job: LogsJobRecord,
    phase: LogsArtifactPhase,
) -> LogsCollectionRequest:
    data = job.collection_request.model_dump(mode="python")
    data["phase"] = phase
    return LogsCollectionRequest.model_validate(data)


def _persist_downstream(
    *,
    settings: LogsRuntimeSettings,
    store: LogsJobStore,
    artifacts: LogsArtifactStore,
    job: LogsJobRecord,
    phase: LogsArtifactPhase,
    activation: str,
    result: LogsCollectionResult,
    query_executed_at: datetime | None = None,
) -> dict[str, Any]:
    existing = artifacts.existing_phase_refs(
        request_id=job.request_id,
        job_id=job.job_id,
        phase=phase,
    )
    if existing is None:
        artifact_ref, evidence_ref = artifacts.write_phase(
            request_id=job.request_id,
            job_id=job.job_id,
            event_index=job.event_index,
            decision=job.incident_time_decision,
            ingestion_grace_seconds=job.ingestion_grace_seconds,
            result=result,
            include_in_analysis=settings.include_in_analysis,
            include_in_review=settings.include_in_review,
            include_in_rca=settings.include_in_rca,
            include_in_card=settings.include_in_card,
            query_executed_at=query_executed_at or _now(),
        )
    else:
        artifact_ref, evidence_ref = existing

    store.finish_completed(
        job.job_id,
        phase,
        activation_id=activation,
        artifact_ref=artifact_ref,
        evidence_status=result.status.value,
    )
    return {
        "job_id": job.job_id,
        "phase": phase.value,
        "status": result.status.value,
        "artifact_ref": artifact_ref,
        "evidence_ref": evidence_ref,
    }


def _run_phase(
    *,
    project_root: Path,
    settings: LogsRuntimeSettings,
    store: LogsJobStore,
    artifacts: LogsArtifactStore,
    job: LogsJobRecord,
    phase: LogsArtifactPhase,
    client_factory: ClientFactory = _default_client,
    claim_now: datetime | None = None,
) -> dict[str, Any]:
    del project_root  # project boundary is already embodied by store/artifacts.
    activation = _activation(job, phase)
    try:
        claim = store.claim_phase(
            job.job_id,
            phase,
            activation_id=activation,
            now=claim_now,
        )
    except AmbiguousPhaseCallError:
        return {
            "job_id": job.job_id,
            "phase": phase.value,
            "status": "ambiguous_no_retry",
            "collect_call_attempted": False,
            "external_call": False,
        }
    except RetryBudgetExhaustedError:
        return {
            "job_id": job.job_id,
            "phase": phase.value,
            "status": "retry_budget_exhausted",
            "collect_call_attempted": False,
            "external_call": False,
        }

    if claim.downstream_resume:
        try:
            payload = store.load_result_checkpoint(job.job_id, phase)
            result = LogsCollectionResult.model_validate(payload)
            downstream = _persist_downstream(
                settings=settings,
                store=store,
                artifacts=artifacts,
                job=job,
                phase=phase,
                activation=claim.activation_id or activation,
                result=result,
                query_executed_at=claim.query_executed_at,
            )
        except Exception as exc:
            return {
                "job_id": job.job_id,
                "phase": phase.value,
                "status": "downstream_resume_failed",
                "exception_type": type(exc).__name__,
                "collect_call_attempted": False,
                "external_call": False,
            }
        return {
            **downstream,
            "status": "resumed_downstream_only",
            "evidence_status": result.status.value,
            "collect_call_attempted": False,
            "external_call": False,
        }

    if not claim.execute:
        status = "in_progress" if claim.in_progress else "reused_or_not_due"
        return {
            "job_id": job.job_id,
            "phase": phase.value,
            "status": status,
            "collect_call_attempted": False,
            "external_call": False,
            "artifact_ref": claim.artifact_ref,
        }

    request = _request_for_phase(job, phase)
    client: LogsMcpClient | None = None
    collect_attempted = False
    query_executed_at: datetime | None = None
    try:
        client = client_factory()
        client.validate_tools()
        collect_attempted = True
        result = client.collect_log_evidence(request)
        query_executed_at = _now()
    except LogsMcpTransportError as exc:
        # initialize/tools-list are bounded read-only contract checks.  If they
        # fail before collect_log_evidence is attempted, the log query has not
        # crossed its exactly-once boundary and the phase may use bounded retry.
        if not collect_attempted or exc.safe_to_retry:
            store.finish_safe_retry(
                job.job_id,
                phase,
                activation_id=activation,
                error_code=type(exc).__name__,
            )
            return {
                "job_id": job.job_id,
                "phase": phase.value,
                "status": "safe_retry_scheduled",
                "collect_call_attempted": collect_attempted,
                "external_call": collect_attempted,
            }
        store.mark_ambiguous(
            job.job_id,
            phase,
            activation_id=activation,
            error_code=type(exc).__name__,
        )
        return {
            "job_id": job.job_id,
            "phase": phase.value,
            "status": "ambiguous_no_retry",
            "collect_call_attempted": collect_attempted,
            "external_call": collect_attempted,
        }
    except LogsMcpContractError as exc:
        if collect_attempted:
            store.mark_ambiguous(
                job.job_id,
                phase,
                activation_id=activation,
                error_code=type(exc).__name__,
            )
            status = "contract_error_after_collect_no_retry"
        else:
            store.finish_terminal_without_query(
                job.job_id,
                phase,
                activation_id=activation,
                error_code=type(exc).__name__,
            )
            status = "tools_contract_error_no_collect"
        return {
            "job_id": job.job_id,
            "phase": phase.value,
            "status": status,
            "collect_call_attempted": collect_attempted,
            "external_call": collect_attempted,
        }
    except Exception as exc:
        if collect_attempted:
            store.mark_ambiguous(
                job.job_id,
                phase,
                activation_id=activation,
                error_code=type(exc).__name__,
            )
            status = "unknown_after_collect_no_retry"
        else:
            store.finish_terminal_without_query(
                job.job_id,
                phase,
                activation_id=activation,
                error_code=type(exc).__name__,
            )
            status = "prequery_internal_failure"
        return {
            "job_id": job.job_id,
            "phase": phase.value,
            "status": status,
            "exception_type": type(exc).__name__,
            "collect_call_attempted": collect_attempted,
            "external_call": collect_attempted,
        }
    finally:
        transport = getattr(client, "transport", None)
        close = getattr(transport, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                # Local transport cleanup must never erase a successful query
                # result or override a state transition already recorded above.
                pass

    # Successful external query: first persist the bounded normalized result.
    # If any later write fails, restart recovery can continue downstream from
    # this checkpoint and MUST NOT repeat the successful collect call.
    try:
        store.checkpoint_result(
            job.job_id,
            phase,
            activation_id=activation,
            result_payload=sanitize_result_for_checkpoint(result),
            query_executed_at=query_executed_at,
        )
    except Exception as exc:
        try:
            store.mark_ambiguous(
                job.job_id,
                phase,
                activation_id=activation,
                error_code="result_checkpoint_failed_after_success",
            )
        except Exception:
            # If even the job-state write is unavailable, preserve the old
            # started state. Restart reconciliation will conservatively turn
            # it ambiguous/no-retry; never issue the successful query again.
            pass
        return {
            "job_id": job.job_id,
            "phase": phase.value,
            "status": "result_checkpoint_failed_no_retry",
            "exception_type": type(exc).__name__,
            "collect_call_attempted": True,
            "external_call": True,
        }

    try:
        downstream = _persist_downstream(
            settings=settings,
            store=store,
            artifacts=artifacts,
            job=job,
            phase=phase,
            activation=activation,
            result=result,
            query_executed_at=query_executed_at,
        )
    except Exception as exc:
        return {
            "job_id": job.job_id,
            "phase": phase.value,
            "status": "downstream_failed_result_persisted",
            "exception_type": type(exc).__name__,
            "collect_call_attempted": True,
            "external_call": True,
        }

    return {
        **downstream,
        "collect_call_attempted": True,
        "external_call": True,
    }


def mount_ingress_safe(
    *,
    request_id: str,
    source: str,
    raw_payload: Mapping[str, Any],
    normalized_events: list[Mapping[str, Any]],
    webhook_received_at: str,
    project_root: str | Path = PROJECT_ROOT,
    settings_path: str | Path | None = None,
    client_factory: ClientFactory = _default_client,
    execute_initial: bool = False,
) -> dict[str, Any]:
    root = Path(project_root)
    settings = load_runtime_settings(
        settings_path or root / "config/v14_logs_w1.yaml"
    )
    if not settings.enabled:
        return {
            "status": "disabled",
            "request_id": request_id,
            "external_calls": 0,
            "production_writes": 0,
        }
    if not settings.store_evidence_enabled:
        return {
            "status": "enabled_store_disabled",
            "request_id": request_id,
            "external_calls": 0,
            "production_writes": 0,
        }
    if not settings.real_query_enabled:
        return {
            "status": "store_only_real_query_disabled",
            "request_id": request_id,
            "external_calls": 0,
            "production_writes": 0,
        }

    state = LogsJobStore(
        root / "data/v14_logs_w1",
        max_attempts_per_phase=settings.max_attempts_per_phase,
        retry_delay_seconds=settings.retry_delay_seconds,
    )
    artifacts = LogsArtifactStore(root / "data/evidence_hub")
    results: list[dict[str, Any]] = []

    for index, event in enumerate(normalized_events):
        if not isinstance(event, Mapping):
            continue
        profile = resolve_log_profile(event)
        if not profile.profile_id:
            results.append(
                {
                    "event_index": index,
                    "status": "not_available",
                    "reason": profile.reason,
                    "external_call": False,
                }
            )
            continue

        raw_alert = _raw_alert_for_index(source, raw_payload, index)
        try:
            decision = _time_decision(
                source,
                raw_alert,
                event,
                webhook_received_at,
            )
        except IncidentTimeResolutionError:
            results.append(
                {
                    "event_index": index,
                    "status": "not_available",
                    "reason": "incident_time_unresolved",
                    "external_call": False,
                }
            )
            continue

        selectors = _selectors(event)
        try:
            request = LogsCollectionRequest(
                profile_id=profile.profile_id,
                incident_time=decision.incident_time,
                window_before_minutes=settings.window_before_minutes,
                window_after_minutes=settings.window_after_minutes,
                phase=LogsArtifactPhase.INITIAL,
                max_raw_samples=settings.max_raw_samples,
                **selectors,
            )
        except Exception:
            results.append(
                {
                    "event_index": index,
                    "status": "not_available",
                    "reason": "selector_contract_invalid",
                    "external_call": False,
                }
            )
            continue

        try:
            job = state.create_or_load(
                request_id=request_id,
                event_index=index,
                request=request,
                incident_time_decision=decision,
                profile_reason=profile.reason,
                activation_id=settings.activation_id,
                ingestion_grace_seconds=settings.ingestion_grace_seconds,
                late_check_enabled=settings.late_check_enabled,
                late_check_delay_seconds=settings.late_check_delay_seconds,
            )
        except Exception as exc:
            results.append(
                {
                    "event_index": index,
                    "status": "job_contract_failed",
                    "exception_type": type(exc).__name__,
                    "external_call": False,
                }
            )
            continue

        if execute_initial:
            results.append(
                _run_phase(
                    project_root=root,
                    settings=settings,
                    store=state,
                    artifacts=artifacts,
                    job=job,
                    phase=LogsArtifactPhase.INITIAL,
                    client_factory=client_factory,
                )
            )
        else:
            results.append(
                {
                    "job_id": job.job_id,
                    "event_index": index,
                    "phase": LogsArtifactPhase.INITIAL.value,
                    "status": "queued_initial",
                    "collect_call_attempted": False,
                    "external_call": False,
                }
            )

    return {
        "status": "processed",
        "request_id": request_id,
        "jobs": results,
        "external_calls": sum(
            1 for item in results if item.get("external_call")
        ),
        "notification_calls": 0,
        "glm_calls": 0,
        "analytics_mcp_calls": 0,
    }


def recover_due_jobs_safe(
    *,
    project_root: str | Path = PROJECT_ROOT,
    settings_path: str | Path | None = None,
    client_factory: ClientFactory = _default_client,
    now: datetime | None = None,
    process_started_at: datetime | None = None,
) -> dict[str, Any]:
    root = Path(project_root)
    settings = load_runtime_settings(
        settings_path or root / "config/v14_logs_w1.yaml"
    )
    if not (
        settings.enabled
        and settings.store_evidence_enabled
        and settings.real_query_enabled
    ):
        return {
            "status": "disabled",
            "recovered": 0,
            "external_calls": 0,
        }

    state = LogsJobStore(
        root / "data/v14_logs_w1",
        max_attempts_per_phase=settings.max_attempts_per_phase,
        retry_delay_seconds=settings.retry_delay_seconds,
    )
    reconciled = state.reconcile_inflight(
        stale_before=process_started_at or PROCESS_STARTED_AT
    )
    artifacts = LogsArtifactStore(root / "data/evidence_hub")
    actions = state.recover_actions(
        now=now,
        limit=settings.startup_recovery_max_jobs,
    )
    results = [
        _run_phase(
            project_root=root,
            settings=settings,
            store=state,
            artifacts=artifacts,
            job=job,
            phase=phase,
            client_factory=client_factory,
            claim_now=now,
        )
        for job, phase in actions
    ]
    return {
        "status": "processed",
        "reconciled_ambiguous_jobs": reconciled,
        "recovered": len(results),
        "external_calls": sum(
            1 for item in results if item.get("external_call")
        ),
        "jobs": results,
    }


def worker_should_start(
    *,
    project_root: str | Path = PROJECT_ROOT,
    settings_path: str | Path | None = None,
) -> bool:
    root = Path(project_root)
    settings = load_runtime_settings(
        settings_path or root / "config/v14_logs_w1.yaml"
    )
    return bool(
        settings.enabled
        and settings.store_evidence_enabled
        and settings.real_query_enabled
    )


def run_recovery_worker(
    *,
    stop_event: threading.Event,
    project_root: str | Path = PROJECT_ROOT,
    settings_path: str | Path | None = None,
    client_factory: ClientFactory = _default_client,
    poll_seconds: int = WORKER_POLL_SECONDS,
) -> dict[str, int]:
    """Run a fixed, bounded polling loop for due persistent jobs.

    The loop performs one immediate recovery pass, then waits a fixed interval.
    Job-level locking and checkpoints provide exactly-once behavior if ingress,
    startup recovery, and the worker encounter the same phase concurrently.
    """
    interval = int(poll_seconds)
    if interval < 1 or interval > 300:
        raise ValueError("worker poll_seconds must be 1..300")
    cycles = 0
    recovered = 0
    external_calls = 0
    while not stop_event.is_set():
        result = recover_due_jobs_safe(
            project_root=project_root,
            settings_path=settings_path,
            client_factory=client_factory,
        )
        cycles += 1
        recovered += int(result.get("recovered") or 0)
        external_calls += int(result.get("external_calls") or 0)
        if stop_event.wait(interval):
            break
    return {
        "cycles": cycles,
        "recovered": recovered,
        "external_calls": external_calls,
    }
