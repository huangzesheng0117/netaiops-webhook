"""Immutable per-job Logs Evidence artifacts inside Evidence Hub."""
from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, Mapping

from netaiops.v12.atomic_writer import AtomicJsonWriter
from netaiops.v12.schema_validator import build_evidence_ref, validate_request_id
from .logs_contracts import (
    IncidentTimeDecision,
    LogsArtifactPhase,
    LogsCollectionResult,
    LogsEvidenceStatus,
)


class LogsArtifactStoreError(RuntimeError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _bounded_text(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    return str(value)[:limit]


def _bounded_count(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed < 0:
        return None
    return min(parsed, 2**63 - 1)


def _clean_sample(value: Mapping[str, Any]) -> dict[str, Any]:
    limits = {
        "timestamp": 64,
        "device_ip": 64,
        "device_name": 256,
        "event_code": 256,
        "severity": 64,
        "message": 512,
    }
    out: dict[str, Any] = {}
    for key, limit in limits.items():
        if key not in value:
            continue
        item = _bounded_text(value.get(key), limit)
        if item is not None:
            out[key] = item
    return out


def _clean_histogram_bucket(value: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    stamp = _bounded_text(value.get("timestamp"), 64)
    count = _bounded_count(value.get("count"))
    if stamp is not None:
        out["timestamp"] = stamp
    if count is not None:
        out["count"] = count
    return out


def _clean_distribution_bucket(value: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    key = _bounded_text(value.get("key"), 256)
    count = _bounded_count(value.get("count"))
    if key is not None:
        out["key"] = key
    if count is not None:
        out["count"] = count
    return out


def _clean_error(value: Mapping[str, Any]) -> dict[str, Any]:
    # Do not persist arbitrary upstream error messages; only bounded identity
    # fields are needed to audit the evidence-health state.
    out: dict[str, Any] = {}
    for key in ("code", "type"):
        if value.get(key) is not None:
            out[key] = str(value.get(key))[:128]
    return out


def sanitize_result_for_checkpoint(
    result: LogsCollectionResult,
) -> dict[str, Any]:
    """Persist only the bounded normalized evidence needed for downstream resume.

    FastMCP LogDocument may carry ``raw_fields``.  W1/W2 must never persist
    those raw fields in Webhook state; representative samples are reduced to
    the explicit safe subset used by Evidence Hub.
    """
    data = result.model_dump(mode="json")
    data["representative_samples"] = [
        _clean_sample(item)
        for item in data.get("representative_samples", [])
        if isinstance(item, Mapping)
    ]
    data["time_histogram"] = [
        _clean_histogram_bucket(item)
        for item in data.get("time_histogram", [])
        if isinstance(item, Mapping)
    ]
    for field in (
        "severity_distribution",
        "event_code_distribution",
        "facility_distribution",
        "process_distribution",
    ):
        data[field] = [
            _clean_distribution_bucket(item)
            for item in data.get(field, [])
            if isinstance(item, Mapping)
        ]
    data["missing_evidence"] = [
        str(item)[:256] for item in data.get("missing_evidence", [])[:32]
    ]
    data["warnings"] = [
        str(item)[:256] for item in data.get("warnings", [])[:32]
    ]
    data["errors"] = [
        _clean_error(item)
        for item in data.get("errors", [])[:32]
        if isinstance(item, Mapping)
    ]
    return data


def _semantic_state(result: LogsCollectionResult) -> tuple[str, bool]:
    phase = result.phase
    status = result.status
    if status == LogsEvidenceStatus.PARTIAL:
        return "partial", False
    if status == LogsEvidenceStatus.FAILED:
        return "failed", False
    if status == LogsEvidenceStatus.NOT_AVAILABLE:
        return "not_available", False
    if phase == LogsArtifactPhase.INITIAL:
        return "provisional", False
    # COMPLETE/LATE_CHECK are scheduled only after the Webhook-side event
    # window plus ingestion grace has elapsed.  FastMCP's own coverage flag is
    # retained separately as upstream_window_complete.  In particular,
    # complete-window no_data is temporally complete but never means healthy.
    if (
        status in {LogsEvidenceStatus.SUCCESS, LogsEvidenceStatus.NO_DATA}
        and not result.missing_evidence
    ):
        return (
            "late_check"
            if phase == LogsArtifactPhase.LATE_CHECK
            else "complete",
            True,
        )
    return "partial", False


class LogsArtifactStore:
    def __init__(self, evidence_hub_root: str | Path) -> None:
        self.root = Path(evidence_hub_root)
        if self.root.exists() and self.root.is_symlink():
            raise LogsArtifactStoreError("Evidence Hub root must not be a symlink")
        self.writer = AtomicJsonWriter(
            self.root,
            directory_mode=0o700,
            file_mode=0o600,
        )
        self.index_locks_root = self.root / "_v14_logs_index_locks"

    def write_phase(
        self,
        *,
        request_id: str,
        job_id: str,
        event_index: int,
        decision: IncidentTimeDecision,
        ingestion_grace_seconds: int,
        result: LogsCollectionResult,
        include_in_analysis: bool,
        include_in_review: bool,
        include_in_rca: bool,
        include_in_card: bool,
        query_executed_at: datetime | None = None,
    ) -> tuple[str, str]:
        validate_request_id(request_id)
        self._safe_job_id(job_id)
        phase = result.phase
        base = f"requests/{request_id}/logs/{job_id}"
        rel = f"{base}/logs_evidence_{phase.value}.json"
        target = self.root / rel
        initial_rel = f"{base}/logs_evidence_initial.json"
        if target.exists():
            raise LogsArtifactStoreError(
                f"immutable phase artifact already exists: {phase.value}"
            )
        if phase != LogsArtifactPhase.INITIAL and not (
            self.root / initial_rel
        ).exists():
            raise LogsArtifactStoreError(
                "complete/late_check requires immutable initial artifact"
            )

        collection_state, window_complete = _semantic_state(result)
        evidence_ref = build_evidence_ref(
            request_id,
            "logs",
            f"{job_id}-{phase.value}",
        )
        executed = query_executed_at or _now()
        if executed.tzinfo is None or executed.utcoffset() is None:
            raise LogsArtifactStoreError("query_executed_at must be timezone-aware")
        result_json = sanitize_result_for_checkpoint(result)
        samples = list(result_json.get("representative_samples", []))

        payload = {
            "schema_version": "v14.w1.logs-artifact.v3",
            "request_id": request_id,
            "job_id": job_id,
            "event_index": event_index,
            "artifact_phase": phase.value,
            "evidence_ref": evidence_ref,
            "profile_id": result.profile_id,
            "incident_time": result.incident_time.isoformat(),
            "incident_time_audit": decision.model_dump(mode="json"),
            "query_executed_at": executed.astimezone(timezone.utc).isoformat(),
            "query_window": result.query_window.model_dump(mode="json"),
            "ingestion_grace_seconds": int(ingestion_grace_seconds),
            "evidence_status": result.status.value,
            "collection_state": collection_state,
            "window_complete": window_complete,
            "upstream_coverage_state": result.coverage.state.value,
            "upstream_window_complete": result.coverage.window_complete,
            "matched_total": result.matched_total,
            "analyzed_total": result.analyzed_total,
            "result_truncated": result.result_truncated,
            "representative_sample_count": len(samples),
            "representative_samples": samples,
            "earliest_timestamp": result_json.get("earliest_timestamp"),
            "latest_timestamp": result_json.get("latest_timestamp"),
            "time_histogram": result_json.get("time_histogram", []),
            "severity_distribution": result_json.get(
                "severity_distribution", []
            ),
            "event_code_distribution": result_json.get(
                "event_code_distribution", []
            ),
            "facility_distribution": result_json.get(
                "facility_distribution", []
            ),
            "process_distribution": result_json.get(
                "process_distribution", []
            ),
            "missing_evidence": result_json.get("missing_evidence", []),
            "warnings": result_json.get("warnings", []),
            "errors": result_json.get("errors", []),
            "reason": result.reason,
            "no_data_interpreted_as_normal": False,
            "exposure_at_capture": {
                "include_in_analysis": bool(include_in_analysis),
                "include_in_review": bool(include_in_review),
                "include_in_rca": bool(include_in_rca),
                "include_in_card": bool(include_in_card),
            },
            "lineage": {
                "initial_artifact_ref": (
                    initial_rel
                    if phase != LogsArtifactPhase.INITIAL
                    else None
                )
            },
        }
        self.writer.write_json(rel, payload)
        self._ensure_latest_pointer(
            request_id=request_id,
            job_id=job_id,
            event_index=event_index,
            artifact_rel=rel,
            artifact=payload,
        )
        with self._request_index_lock(request_id):
            self._rebuild_request_index(request_id)
        return rel, evidence_ref

    def existing_phase_refs(
        self,
        *,
        request_id: str,
        job_id: str,
        phase: LogsArtifactPhase,
    ) -> tuple[str, str] | None:
        validate_request_id(request_id)
        self._safe_job_id(job_id)
        rel = (
            f"requests/{request_id}/logs/{job_id}/"
            f"logs_evidence_{phase.value}.json"
        )
        path = self.root / rel
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file():
            raise LogsArtifactStoreError("phase artifact path invalid")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise LogsArtifactStoreError("phase artifact unreadable") from exc
        if not isinstance(value, Mapping):
            raise LogsArtifactStoreError("phase artifact root invalid")
        if (
            value.get("request_id") != request_id
            or value.get("job_id") != job_id
            or value.get("artifact_phase") != phase.value
        ):
            raise LogsArtifactStoreError("phase artifact identity mismatch")
        evidence_ref = value.get("evidence_ref")
        if not isinstance(evidence_ref, str) or not evidence_ref:
            raise LogsArtifactStoreError("phase artifact evidence_ref missing")
        event_index = value.get("event_index")
        if not isinstance(event_index, int) or event_index < 0:
            raise LogsArtifactStoreError("phase artifact event_index invalid")
        self._ensure_latest_pointer(
            request_id=request_id,
            job_id=job_id,
            event_index=event_index,
            artifact_rel=rel,
            artifact=value,
        )
        with self._request_index_lock(request_id):
            self._rebuild_request_index(request_id)
        return rel, evidence_ref

    @staticmethod
    def _phase_rank(value: str) -> int:
        return {"initial": 1, "complete": 2, "late_check": 3}.get(value, 0)

    def _ensure_latest_pointer(
        self,
        *,
        request_id: str,
        job_id: str,
        event_index: int,
        artifact_rel: str,
        artifact: Mapping[str, Any],
    ) -> None:
        phase = str(artifact.get("artifact_phase") or "")
        evidence_ref = artifact.get("evidence_ref")
        if self._phase_rank(phase) == 0:
            raise LogsArtifactStoreError("phase artifact phase invalid")
        if not isinstance(evidence_ref, str) or not evidence_ref:
            raise LogsArtifactStoreError("phase artifact evidence_ref missing")
        latest_rel = f"requests/{request_id}/logs/{job_id}/logs_evidence_latest.json"
        latest_path = self.root / latest_rel
        if latest_path.exists():
            if latest_path.is_symlink() or not latest_path.is_file():
                raise LogsArtifactStoreError("latest pointer path invalid")
            try:
                current = json.loads(latest_path.read_text(encoding="utf-8"))
            except Exception as exc:
                raise LogsArtifactStoreError("latest pointer unreadable") from exc
            if not isinstance(current, Mapping):
                raise LogsArtifactStoreError("latest pointer root invalid")
            current_phase = str(current.get("phase") or "")
            if self._phase_rank(current_phase) >= self._phase_rank(phase):
                return
        initial_rel = f"requests/{request_id}/logs/{job_id}/logs_evidence_initial.json"
        latest = {
            "schema_version": "v14.w1.logs-latest.v3",
            "request_id": request_id,
            "job_id": job_id,
            "event_index": event_index,
            "phase": phase,
            "artifact_ref": artifact_rel,
            "evidence_ref": evidence_ref,
            "initial_artifact_ref": initial_rel,
            "evidence_status": artifact.get("evidence_status"),
            "collection_state": artifact.get("collection_state"),
            "window_complete": bool(artifact.get("window_complete")),
        }
        self.writer.write_json(latest_rel, latest)

    def read_request_index(
        self,
        request_id: str,
    ) -> Mapping[str, Any] | None:
        validate_request_id(request_id)
        path = self.root / f"requests/{request_id}/logs_evidence.json"
        if not path.exists():
            return None
        if path.is_symlink():
            raise LogsArtifactStoreError(
                "request logs index must not be symlink"
            )
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise LogsArtifactStoreError("request logs index unreadable") from exc
        return value if isinstance(value, Mapping) else None

    def _rebuild_request_index(self, request_id: str) -> None:
        request_root = self.root / f"requests/{request_id}"
        logs_root = request_root / "logs"
        jobs: list[dict[str, Any]] = []
        warnings: list[str] = []
        if logs_root.exists():
            for latest_path in sorted(
                logs_root.glob("*/logs_evidence_latest.json")
            ):
                if latest_path.is_symlink() or not latest_path.is_file():
                    warnings.append("invalid_latest_path_skipped")
                    continue
                try:
                    latest = json.loads(
                        latest_path.read_text(encoding="utf-8")
                    )
                    artifact_rel = self._safe_artifact_rel(
                        request_id,
                        latest.get("artifact_ref"),
                    )
                    artifact_path = self.root / artifact_rel
                    if artifact_path.is_symlink() or not artifact_path.is_file():
                        raise ValueError("artifact path invalid")
                    artifact = json.loads(
                        artifact_path.read_text(encoding="utf-8")
                    )
                    if not isinstance(artifact, Mapping):
                        raise ValueError("artifact root invalid")
                except Exception:
                    warnings.append("invalid_logs_artifact_skipped")
                    continue
                row = {
                    key: artifact.get(key)
                    for key in (
                        "job_id",
                        "event_index",
                        "artifact_phase",
                        "evidence_ref",
                        "profile_id",
                        "incident_time",
                        "evidence_status",
                        "collection_state",
                        "window_complete",
                        "upstream_coverage_state",
                        "upstream_window_complete",
                        "matched_total",
                        "analyzed_total",
                        "result_truncated",
                        "representative_sample_count",
                        "ingestion_grace_seconds",
                        "query_executed_at",
                        "no_data_interpreted_as_normal",
                        "exposure_at_capture",
                    )
                }
                row["artifact_ref"] = artifact_rel
                jobs.append(row)

        jobs.sort(
            key=lambda item: (
                int(item.get("event_index") or 0),
                str(item.get("job_id") or ""),
            )
        )
        index = {
            "section": "logs_evidence",
            "schema_version": "v14.w1.logs-request-index.v2",
            "request_id": request_id,
            "captured_at": _now().isoformat(),
            "status": "found" if jobs else "missing",
            "data": {
                "job_count": len(jobs),
                "jobs": jobs,
            },
            "warnings": sorted(set(warnings)),
        }
        self.writer.write_json(
            f"requests/{request_id}/logs_evidence.json",
            index,
        )

    def _safe_artifact_rel(
        self,
        request_id: str,
        value: Any,
    ) -> str:
        if not isinstance(value, str) or not value:
            raise LogsArtifactStoreError("artifact_ref missing")
        pure = PurePosixPath(value)
        if pure.is_absolute() or any(
            part in {"", ".", ".."} for part in pure.parts
        ):
            raise LogsArtifactStoreError("artifact_ref path unsafe")
        prefix = PurePosixPath("requests") / request_id / "logs"
        try:
            pure.relative_to(prefix)
        except ValueError as exc:
            raise LogsArtifactStoreError(
                "artifact_ref escapes request logs root"
            ) from exc
        return pure.as_posix()

    @staticmethod
    def _safe_job_id(job_id: str) -> str:
        if len(job_id) != 32 or any(
            ch not in "0123456789abcdef" for ch in job_id
        ):
            raise LogsArtifactStoreError("unsafe job_id")
        return job_id

    @contextmanager
    def _request_index_lock(self, request_id: str) -> Iterator[None]:
        validate_request_id(request_id)
        if (
            self.index_locks_root.exists()
            and self.index_locks_root.is_symlink()
        ):
            raise LogsArtifactStoreError("index lock root is symlink")
        self.index_locks_root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.index_locks_root, 0o700)
        lock_name = f"{request_id}.lock"
        lock_path = self.index_locks_root / lock_name
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(lock_path, flags, 0o600)
        try:
            with os.fdopen(descriptor, "r+", encoding="utf-8") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                yield
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            pass
