"""Non-blocking v11 Governance integration and historical backfill helpers.

Batch 10 connects the already-tested Governance builders to completed v10
request artifacts.  The production hook is a sidecar: failures are isolated and
returned as structured diagnostics; they never replace the main pipeline result.
All processing is local and deterministic.  No GLM, MCP, device, Elasticsearch,
or notification endpoint is called.
"""
from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .artifact_reader import git_metadata, read_request_artifacts
from .contracts import GOVERNANCE_SCHEMA_VERSION
from .memory_builder import build_incident_memory, memory_safety_summary
from .proposal_builder import ProposalBuilder, ProposalNotEligibleError, proposal_safety_summary
from .schemas import IncidentMemoryRecord, LearningSignalRecord, ProposalRecord
from .signal_detector import detect_learning_signals, signal_detection_summary
from .store import DEFAULT_GOVERNANCE_ROOT, GovernanceStore

INTEGRATION_VERSION = "11.0.0-governance-integration-v1"
_EXTERNAL_CALLS_FALSE = {
    "glm": False,
    "prometheus": False,
    "device": False,
    "notification": False,
    "elasticsearch": False,
    "production_write": False,
}


class GovernanceIntegrationError(RuntimeError):
    """Raised for invalid integration/backfill configuration."""


def _aware_utc(value: datetime | None = None) -> datetime:
    result = value or datetime.now(timezone.utc)
    if result.tzinfo is None or result.utcoffset() is None:
        raise GovernanceIntegrationError("generated_at must include timezone information")
    return result.astimezone(timezone.utc)


def _record_exists(store: GovernanceStore, collection: str, record_id: str) -> bool:
    return store.record_path(collection, record_id).is_file()


def _load_existing_memory(store: GovernanceStore, memory_id: str) -> IncidentMemoryRecord | None:
    if not _record_exists(store, "incident_memory", memory_id):
        return None
    return IncidentMemoryRecord.model_validate(store.read("incident_memory", memory_id))


def _load_existing_signal(store: GovernanceStore, signal_id: str) -> LearningSignalRecord | None:
    if not _record_exists(store, "signals", signal_id):
        return None
    return LearningSignalRecord.model_validate(store.read("signals", signal_id))


def _load_existing_proposal(store: GovernanceStore, proposal_id: str) -> ProposalRecord | None:
    if not _record_exists(store, "proposals", proposal_id):
        return None
    return ProposalRecord.model_validate(store.read("proposals", proposal_id))


def _write_result_payload(result: Any) -> dict[str, Any]:
    return {
        "collection": result.collection,
        "record_id": result.record_id,
        "path": result.path,
        "sha256": result.sha256,
        "size_bytes": result.size_bytes,
        "created": result.created,
    }


def build_governance_artifacts(
    request_id: str,
    *,
    project_root: Path | str = Path("/opt/netaiops-webhook"),
    governance_root: Path | str = DEFAULT_GOVERNANCE_ROOT,
    include_signals: bool = True,
    include_proposals: bool = True,
    write: bool = True,
    force: bool = False,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Build Memory, Signals and optional draft Proposals for one request.

    ``write=False`` performs a pure dry run.  With ``write=True`` stable record
    identifiers make repeated runs idempotent.  Existing records are reused
    unless ``force=True`` is explicitly requested.
    """

    started = time.monotonic()
    timestamp = _aware_utc(generated_at)
    root = Path(project_root).expanduser().resolve(strict=False)
    output = Path(governance_root).expanduser().resolve(strict=False)
    store = GovernanceStore(output)
    memory_id = f"memory_{request_id}"

    existing_memory = None if force or not write else _load_existing_memory(store, memory_id)
    if existing_memory is None:
        bundle = read_request_artifacts(root, request_id)
        memory = build_incident_memory(
            bundle,
            generated_at=timestamp,
            source_git_metadata=git_metadata(root),
        )
    else:
        memory = existing_memory

    memory_safety = memory_safety_summary(memory)
    if not memory_safety.get("safe", False):
        raise GovernanceIntegrationError(
            f"incident memory failed safety check: {memory_safety}"
        )

    writes: list[dict[str, Any]] = []
    reused: list[dict[str, str]] = []
    if write:
        if existing_memory is not None:
            reused.append({"collection": "incident_memory", "record_id": memory.memory_id})
        else:
            writes.append(
                _write_result_payload(
                    store.write("incident_memory", memory.memory_id, memory, overwrite=True)
                )
            )

    signals: tuple[LearningSignalRecord, ...] = ()
    if include_signals:
        detected = detect_learning_signals(memory, generated_at=timestamp)
        resolved_signals: list[LearningSignalRecord] = []
        for signal in detected:
            existing = None if force or not write else _load_existing_signal(store, signal.signal_id)
            record = existing or signal
            resolved_signals.append(record)
            if write:
                if existing is not None:
                    reused.append({"collection": "signals", "record_id": record.signal_id})
                else:
                    writes.append(
                        _write_result_payload(
                            store.write("signals", record.signal_id, record, overwrite=True)
                        )
                    )
        signals = tuple(resolved_signals)

    proposals: list[ProposalRecord] = []
    proposal_skips: list[dict[str, str]] = []
    if include_proposals:
        builder = ProposalBuilder()
        for signal in signals:
            if not signal.proposal_eligible:
                proposal_skips.append(
                    {
                        "signal_id": signal.signal_id,
                        "signal_type": signal.signal_type,
                        "reason": "not_proposal_eligible",
                    }
                )
                continue
            try:
                candidate = builder.build_for_memory(
                    signal,
                    memory,
                    generated_at=timestamp,
                )
            except ProposalNotEligibleError as exc:
                proposal_skips.append(
                    {
                        "signal_id": signal.signal_id,
                        "signal_type": signal.signal_type,
                        "reason": str(exc),
                    }
                )
                continue
            safety = proposal_safety_summary(candidate)
            if not safety.get("safe", False):
                raise GovernanceIntegrationError(
                    f"proposal failed safety check: {candidate.proposal_id}: {safety}"
                )
            existing = (
                None
                if force or not write
                else _load_existing_proposal(store, candidate.proposal_id)
            )
            record = existing or candidate
            proposals.append(record)
            if write:
                if existing is not None:
                    reused.append(
                        {"collection": "proposals", "record_id": record.proposal_id}
                    )
                else:
                    writes.append(
                        _write_result_payload(
                            store.write("proposals", record.proposal_id, record, overwrite=True)
                        )
                    )

    external_calls = dict(_EXTERNAL_CALLS_FALSE)
    external_calls["production_write"] = bool(write and output == DEFAULT_GOVERNANCE_ROOT.resolve(strict=False))
    elapsed_ms = int((time.monotonic() - started) * 1000)
    return {
        "ok": True,
        "status": "completed" if write else "dry_run",
        "integration_version": INTEGRATION_VERSION,
        "schema_version": GOVERNANCE_SCHEMA_VERSION,
        "request_id": memory.request_id,
        "governance_root": str(output),
        "memory_id": memory.memory_id,
        "memory_safety": memory_safety,
        "signal_summary": signal_detection_summary(signals),
        "signal_ids": [item.signal_id for item in signals],
        "proposal_ids": [item.proposal_id for item in proposals],
        "proposal_skips": proposal_skips,
        "writes": writes,
        "reused": reused,
        "created_count": sum(1 for item in writes if item.get("created")),
        "reused_count": len(reused),
        "dry_run": not write,
        "force": bool(force),
        "external_calls": external_calls,
        "duration_ms": elapsed_ms,
    }


def build_governance_artifacts_safe(
    request_id: str,
    *,
    project_root: Path | str = Path("/opt/netaiops-webhook"),
    governance_root: Path | str = DEFAULT_GOVERNANCE_ROOT,
    include_signals: bool = True,
    include_proposals: bool = True,
    write: bool = True,
    force: bool = False,
    generated_at: datetime | None = None,
    logger: Any | None = None,
) -> dict[str, Any]:
    """Non-blocking sidecar wrapper used by the production app and backfill."""

    try:
        return build_governance_artifacts(
            request_id,
            project_root=project_root,
            governance_root=governance_root,
            include_signals=include_signals,
            include_proposals=include_proposals,
            write=write,
            force=force,
            generated_at=generated_at,
        )
    except Exception as exc:  # deliberate sidecar isolation boundary
        if logger is not None:
            try:
                logger.exception(
                    "governance sidecar failed request_id=%s: %r", request_id, exc
                )
            except Exception:
                pass
        return {
            "ok": False,
            "status": "failed",
            "integration_version": INTEGRATION_VERSION,
            "request_id": str(request_id),
            "error": f"{type(exc).__name__}: {exc}",
            "dry_run": not write,
            "external_calls": dict(_EXTERNAL_CALLS_FALSE),
        }


def discover_request_ids(
    project_root: Path | str,
    *,
    limit: int = 20,
) -> tuple[str, ...]:
    """Return newest request IDs from Evidence Hub directory names."""

    if isinstance(limit, bool) or int(limit) < 1 or int(limit) > 10000:
        raise GovernanceIntegrationError("limit must be between 1 and 10000")
    root = Path(project_root).expanduser().resolve(strict=False)
    requests_dir = root / "data" / "evidence_hub" / "requests"
    if not requests_dir.is_dir() or requests_dir.is_symlink():
        return ()
    values: list[str] = []
    for item in requests_dir.iterdir():
        if not item.is_dir() or item.is_symlink():
            continue
        name = item.name
        try:
            from .schemas import validate_governance_id

            validate_governance_id(name, field_name="request_id")
        except ValueError:
            continue
        values.append(name)
    return tuple(sorted(set(values), reverse=True)[: int(limit)])


def _backfill_id(started_at: datetime, request_ids: Iterable[str], mode: str) -> str:
    material = json.dumps(
        {
            "version": INTEGRATION_VERSION,
            "started_at": started_at.isoformat(),
            "request_ids": list(request_ids),
            "mode": mode,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"backfill_{hashlib.sha256(material).hexdigest()[:24]}"


def run_backfill(
    *,
    project_root: Path | str,
    governance_root: Path | str,
    request_ids: Iterable[str] | None = None,
    limit: int = 20,
    dry_run: bool = True,
    include_proposals: bool = True,
    force: bool = False,
    generated_at: datetime | None = None,
    persist_run_record: bool = True,
) -> dict[str, Any]:
    """Process a bounded set of historical requests with failure isolation."""

    started_clock = time.monotonic()
    started_at = _aware_utc(generated_at)
    ids = tuple(request_ids or discover_request_ids(project_root, limit=limit))[: int(limit)]
    mode = "dry_run" if dry_run else "execute"
    results: list[dict[str, Any]] = []
    for request_id in ids:
        results.append(
            build_governance_artifacts_safe(
                request_id,
                project_root=project_root,
                governance_root=governance_root,
                include_signals=True,
                include_proposals=include_proposals,
                write=not dry_run,
                force=force,
                generated_at=started_at,
            )
        )

    success_count = sum(1 for item in results if item.get("ok"))
    failure_count = len(results) - success_count
    report: dict[str, Any] = {
        "schema_version": GOVERNANCE_SCHEMA_VERSION,
        "integration_version": INTEGRATION_VERSION,
        "backfill_id": _backfill_id(started_at, ids, mode),
        "created_at": started_at.isoformat(),
        "mode": mode,
        "project_root": str(Path(project_root).expanduser().resolve(strict=False)),
        "governance_root": str(Path(governance_root).expanduser().resolve(strict=False)),
        "limit": int(limit),
        "request_ids": list(ids),
        "request_count": len(ids),
        "success_count": success_count,
        "failure_count": failure_count,
        "status": "completed" if failure_count == 0 else "partial",
        "results": results,
        "external_calls": dict(_EXTERNAL_CALLS_FALSE),
        "duration_ms": int((time.monotonic() - started_clock) * 1000),
    }

    if not dry_run and persist_run_record:
        store = GovernanceStore(governance_root)
        payload = dict(report)
        payload["results"] = [
            {
                "request_id": item.get("request_id", ""),
                "ok": bool(item.get("ok")),
                "status": item.get("status", ""),
                "created_count": int(item.get("created_count", 0) or 0),
                "reused_count": int(item.get("reused_count", 0) or 0),
                "error": str(item.get("error", ""))[:500],
            }
            for item in results
        ]
        write_result = store.write("backfill", report["backfill_id"], payload, overwrite=True)
        report["backfill_record"] = _write_result_payload(write_result)
    else:
        report["backfill_record"] = None
    return report


__all__ = [
    "INTEGRATION_VERSION",
    "GovernanceIntegrationError",
    "build_governance_artifacts",
    "build_governance_artifacts_safe",
    "discover_request_ids",
    "run_backfill",
]
