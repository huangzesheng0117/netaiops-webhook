"""Durable W1 delayed-job state with restart-safe exactly-once semantics.

The state machine distinguishes an external call that has merely started from
one whose normalized result has already been persisted.  This allows a crash
between the successful 10002 response and downstream Evidence Hub write to
resume *downstream only* without repeating the successful query.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from pydantic import BaseModel, ConfigDict, Field, model_validator

from netaiops.v12.atomic_writer import AtomicJsonWriter
from netaiops.v12.schema_validator import validate_request_id
from .logs_contracts import (
    IncidentTimeDecision,
    LogsArtifactPhase,
    LogsCollectionRequest,
    LogsJobState,
)


class LogsJobError(RuntimeError):
    pass


class AmbiguousPhaseCallError(LogsJobError):
    pass


class RetryBudgetExhaustedError(LogsJobError):
    pass


class MutableModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PhaseCallState(MutableModel):
    # pending|started|result_persisted|succeeded|failed_retryable|
    # failed_terminal|ambiguous
    state: str = "pending"
    activation_id: str | None = None
    attempts: int = Field(default=0, ge=0)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    artifact_ref: str | None = None
    evidence_status: str | None = None
    last_error_code: str | None = None
    retry_not_before: datetime | None = None
    result_checkpoint_ref: str | None = None
    result_checkpoint_sha256: str | None = None
    query_executed_at: datetime | None = None

    @model_validator(mode="after")
    def _state_contract(self) -> "PhaseCallState":
        allowed = {
            "pending",
            "started",
            "result_persisted",
            "succeeded",
            "failed_retryable",
            "failed_terminal",
            "ambiguous",
        }
        if self.state not in allowed:
            raise ValueError("invalid phase state")
        if self.state == "result_persisted" and not self.result_checkpoint_ref:
            raise ValueError("result_persisted requires result checkpoint")
        for name in (
            "started_at", "finished_at", "retry_not_before",
            "query_executed_at",
        ):
            value = getattr(self, name)
            if value is not None and (
                value.tzinfo is None or value.utcoffset() is None
            ):
                raise ValueError(f"{name} must be timezone-aware")
        return self


class LogsJobRecord(MutableModel):
    schema_version: str = "v14.w1.logs-job.v3"
    job_id: str
    request_id: str
    event_index: int = Field(ge=0, le=9999)
    activation_id: str
    profile_id: str
    profile_reason: str
    incident_time: datetime
    incident_time_decision: IncidentTimeDecision
    collection_request: LogsCollectionRequest
    selector_fingerprint: str
    ingestion_grace_seconds: int = Field(ge=0, le=1800)
    due_at: datetime
    max_attempts_per_phase: int = Field(ge=1, le=3)
    retry_delay_seconds: int = Field(ge=1, le=1800)
    late_check_enabled: bool = False
    late_check_delay_seconds: int = Field(default=300, ge=30, le=3600)
    late_check_due_at: datetime | None = None
    job_state: LogsJobState = LogsJobState.PENDING
    created_at: datetime
    updated_at: datetime
    phases: dict[str, PhaseCallState] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _record_contract(self) -> "LogsJobRecord":
        validate_request_id(self.request_id)
        if self.schema_version != "v14.w1.logs-job.v3":
            raise ValueError("job schema_version mismatch")
        if len(self.job_id) != 32 or any(
            ch not in "0123456789abcdef" for ch in self.job_id
        ):
            raise ValueError("job_id is not a safe stable identifier")
        if not self.activation_id.strip() or len(self.activation_id) > 128:
            raise ValueError("job activation_id invalid")
        if self.profile_id != self.collection_request.profile_id:
            raise ValueError("job profile/request mismatch")
        if self.incident_time != self.collection_request.incident_time:
            raise ValueError("job incident_time/request mismatch")
        if self.selector_fingerprint != self.collection_request.selector_fingerprint():
            raise ValueError("job selector fingerprint mismatch")
        for name in ("incident_time", "due_at", "created_at", "updated_at"):
            value = getattr(self, name)
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"job {name} must be timezone-aware")
        if self.late_check_due_at is not None:
            if self.late_check_due_at.tzinfo is None or self.late_check_due_at.utcoffset() is None:
                raise ValueError("late_check_due_at must be timezone-aware")
            if self.late_check_due_at < self.due_at:
                raise ValueError("late_check_due_at precedes complete due_at")
        allowed_phases = {phase.value for phase in LogsArtifactPhase}
        unknown_phases = set(self.phases) - allowed_phases
        if unknown_phases:
            raise ValueError("job contains unknown phase state")
        return self


class PhaseClaim(MutableModel):
    execute: bool
    reused: bool = False
    in_progress: bool = False
    downstream_resume: bool = False
    activation_id: str | None = None
    artifact_ref: str | None = None
    result_checkpoint_ref: str | None = None
    query_executed_at: datetime | None = None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _finish_now(state: PhaseCallState) -> datetime:
    now = _utcnow()
    if state.started_at is not None and now < state.started_at:
        return state.started_at
    return now


def stable_job_id(
    request_id: str,
    event_index: int,
    request: LogsCollectionRequest,
) -> str:
    validate_request_id(request_id)
    material = "|".join(
        (
            "logs-job-v3",
            request_id,
            str(event_index),
            request.profile_id,
            request.incident_time.isoformat(),
            request.selector_fingerprint(),
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


class LogsJobStore:
    def __init__(
        self,
        root: str | Path,
        *,
        max_attempts_per_phase: int = 2,
        retry_delay_seconds: int = 60,
    ) -> None:
        self.root = Path(root)
        if self.root.exists() and self.root.is_symlink():
            raise LogsJobError("state root must not be a symlink")
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

        self.jobs_root = self.root / "jobs"
        self.results_root = self.root / "results"
        self.locks_root = self.root / "locks"
        for child in (self.jobs_root, self.results_root, self.locks_root):
            if child.exists() and child.is_symlink():
                raise LogsJobError(f"state child must not be symlink: {child.name}")
        self.writer = AtomicJsonWriter(
            self.jobs_root,
            directory_mode=0o700,
            file_mode=0o600,
        )
        self.result_writer = AtomicJsonWriter(
            self.results_root,
            directory_mode=0o700,
            file_mode=0o600,
        )
        self.max_attempts_per_phase = int(max_attempts_per_phase)
        self.retry_delay_seconds = int(retry_delay_seconds)
        if not 1 <= self.max_attempts_per_phase <= 3:
            raise ValueError("max_attempts_per_phase must be 1..3")
        if not 1 <= self.retry_delay_seconds <= 1800:
            raise ValueError("retry_delay_seconds must be 1..1800")

    def create_or_load(
        self,
        *,
        request_id: str,
        event_index: int,
        request: LogsCollectionRequest,
        incident_time_decision: IncidentTimeDecision,
        profile_reason: str,
        activation_id: str,
        ingestion_grace_seconds: int,
        late_check_enabled: bool = False,
        late_check_delay_seconds: int = 300,
        due_at: datetime | None = None,
    ) -> LogsJobRecord:
        validate_request_id(request_id)
        activation_id = str(activation_id or "").strip()
        if not activation_id or len(activation_id) > 128:
            raise ValueError("activation_id is required and must be <=128 chars")
        grace = int(ingestion_grace_seconds)
        if not 0 <= grace <= 1800:
            raise ValueError("ingestion_grace_seconds must be 0..1800")
        late_delay = int(late_check_delay_seconds)
        if not 30 <= late_delay <= 3600:
            raise ValueError("late_check_delay_seconds must be 30..3600")

        due = due_at or (
            request.incident_time
            + timedelta(
                minutes=request.window_after_minutes,
                seconds=grace,
            )
        )
        if due.tzinfo is None or due.utcoffset() is None:
            raise ValueError("due_at must be timezone-aware")
        due = due.astimezone(timezone.utc)
        late_due = (
            due + timedelta(seconds=late_delay)
            if late_check_enabled
            else None
        )

        job_id = stable_job_id(request_id, event_index, request)
        with self._job_lock(job_id):
            existing = self._read_optional(job_id)
            if existing is not None:
                if existing.activation_id != activation_id:
                    raise LogsJobError("job activation drift")
                if existing.collection_request.selector_fingerprint() != request.selector_fingerprint():
                    raise LogsJobError("job selector drift")
                if existing.ingestion_grace_seconds != grace:
                    raise LogsJobError("job ingestion grace drift")
                if existing.incident_time_decision != incident_time_decision:
                    raise LogsJobError("job incident-time decision drift")
                if existing.max_attempts_per_phase != self.max_attempts_per_phase:
                    raise LogsJobError("job retry-attempt policy drift")
                if existing.retry_delay_seconds != self.retry_delay_seconds:
                    raise LogsJobError("job retry-delay policy drift")
                if existing.late_check_enabled != bool(late_check_enabled):
                    raise LogsJobError("job late-check enabled drift")
                if existing.late_check_delay_seconds != late_delay:
                    raise LogsJobError("job late-check delay drift")
                return existing

            now = _utcnow()
            record = LogsJobRecord(
                job_id=job_id,
                request_id=request_id,
                event_index=event_index,
                activation_id=activation_id,
                profile_id=request.profile_id,
                profile_reason=profile_reason,
                incident_time=request.incident_time,
                incident_time_decision=incident_time_decision,
                collection_request=request,
                selector_fingerprint=request.selector_fingerprint(),
                ingestion_grace_seconds=grace,
                due_at=due,
                max_attempts_per_phase=self.max_attempts_per_phase,
                retry_delay_seconds=self.retry_delay_seconds,
                late_check_enabled=bool(late_check_enabled),
                late_check_delay_seconds=late_delay,
                late_check_due_at=late_due,
                created_at=now,
                updated_at=now,
                phases={},
            )
            self._write(record)
            return record

    def claim_phase(
        self,
        job_id: str,
        phase: LogsArtifactPhase,
        *,
        activation_id: str,
        now: datetime | None = None,
    ) -> PhaseClaim:
        if not activation_id:
            raise ValueError("activation_id is required")
        current_time = now or _utcnow()
        if current_time.tzinfo is None or current_time.utcoffset() is None:
            raise ValueError("claim time must be timezone-aware")
        with self._job_lock(job_id):
            record = self._read_required(job_id)
            key = phase.value
            current = record.phases.get(key, PhaseCallState())

            if current.state == "succeeded":
                return PhaseClaim(
                    execute=False,
                    reused=True,
                    artifact_ref=current.artifact_ref,
                )
            if current.state == "result_persisted":
                return PhaseClaim(
                    execute=False,
                    downstream_resume=True,
                    activation_id=current.activation_id,
                    result_checkpoint_ref=current.result_checkpoint_ref,
                    query_executed_at=current.query_executed_at,
                )
            if current.state == "started":
                # A successful external response is checkpointed to its own
                # atomic result file before job-state/downstream writes.  If
                # the result file exists but the job-state update failed, do
                # not wait for a service restart and never issue the query
                # again: promote this phase to downstream-only recovery.
                filename = self._result_filename(record.job_id, phase)
                checkpoint_path = self.results_root / filename
                if checkpoint_path.is_file() and not checkpoint_path.is_symlink():
                    try:
                        digest = self._sha256(checkpoint_path)
                        checkpoint = self._read_result_checkpoint(filename, digest)
                        checkpoint_time = self._checkpoint_query_time(checkpoint)
                        self._result_from_checkpoint(
                            checkpoint, expected_job_id=record.job_id, expected_phase=phase
                        )
                    except Exception:
                        # An invalid checkpoint cannot prove completion.  Keep
                        # the active call in-progress during this process; a
                        # restart reconciliation will conservatively mark it
                        # ambiguous/no-retry.
                        pass
                    else:
                        current.state = "result_persisted"
                        current.result_checkpoint_ref = filename
                        current.result_checkpoint_sha256 = digest
                        if current.query_executed_at is None:
                            current.query_executed_at = checkpoint_time
                        current.finished_at = _finish_now(current)
                        record.phases[key] = current
                        record.job_state = LogsJobState.PARTIAL
                        record.updated_at = current.finished_at
                        self._write(record)
                        return PhaseClaim(
                            execute=False,
                            downstream_resume=True,
                            activation_id=current.activation_id,
                            result_checkpoint_ref=filename,
                            query_executed_at=current.query_executed_at,
                        )
                return PhaseClaim(
                    execute=False,
                    in_progress=True,
                    activation_id=current.activation_id,
                )
            if current.state == "ambiguous":
                raise AmbiguousPhaseCallError(
                    f"phase {key} has ambiguous external-call state"
                )
            if current.state == "failed_terminal":
                raise RetryBudgetExhaustedError(
                    f"phase {key} terminal failure"
                )
            if (
                current.state == "failed_retryable"
                and current.retry_not_before
                and current.retry_not_before > current_time
            ):
                return PhaseClaim(execute=False)

            if current.attempts >= record.max_attempts_per_phase:
                current.state = "failed_terminal"
                record.phases[key] = current
                record.job_state = LogsJobState.FAILED
                record.updated_at = current_time
                self._write(record)
                raise RetryBudgetExhaustedError(
                    f"phase {key} retry budget exhausted"
                )

            current.state = "started"
            current.activation_id = activation_id
            current.attempts += 1
            current.started_at = current_time
            current.finished_at = None
            current.last_error_code = None
            current.retry_not_before = None
            current.result_checkpoint_ref = None
            current.result_checkpoint_sha256 = None
            current.query_executed_at = None
            record.phases[key] = current
            record.job_state = LogsJobState.RUNNING
            record.updated_at = current_time
            self._write(record)
            return PhaseClaim(execute=True, activation_id=activation_id)

    def checkpoint_result(
        self,
        job_id: str,
        phase: LogsArtifactPhase,
        *,
        activation_id: str,
        result_payload: Mapping[str, Any],
        query_executed_at: datetime | None,
    ) -> LogsJobRecord:
        """Persist a successful normalized external response before downstream writes."""
        with self._job_lock(job_id):
            record = self._read_required(job_id)
            current = record.phases.get(phase.value)
            if (
                current is None
                or current.state != "started"
                or current.activation_id != activation_id
            ):
                raise LogsJobError("result checkpoint does not match active claim")

            executed_at = query_executed_at or _utcnow()
            if executed_at.tzinfo is None or executed_at.utcoffset() is None:
                raise LogsJobError("query_executed_at must be timezone-aware")
            executed_at = executed_at.astimezone(timezone.utc)
            filename = self._result_filename(job_id, phase)
            checkpoint_payload = {
                "schema_version": "v14.w1.logs-result-checkpoint.v1",
                "job_id": job_id,
                "phase": phase.value,
                "query_executed_at": executed_at.isoformat(),
                "result": dict(result_payload),
            }
            target = self.result_writer.write_json(filename, checkpoint_payload)
            digest = self._sha256(target)
            current.state = "result_persisted"
            current.result_checkpoint_ref = filename
            current.result_checkpoint_sha256 = digest
            current.query_executed_at = executed_at
            current.finished_at = _finish_now(current)
            record.phases[phase.value] = current
            record.updated_at = current.finished_at
            self._write(record)
            return record

    def load_result_checkpoint(
        self,
        job_id: str,
        phase: LogsArtifactPhase,
    ) -> Mapping[str, Any]:
        with self._job_lock(job_id):
            record = self._read_required(job_id)
            state = record.phases.get(phase.value)
            if state is None or not state.result_checkpoint_ref:
                raise LogsJobError("phase result checkpoint is missing")
            checkpoint = self._read_result_checkpoint(
                state.result_checkpoint_ref,
                state.result_checkpoint_sha256,
            )
            return self._result_from_checkpoint(
                checkpoint, expected_job_id=job_id, expected_phase=phase
            )

    def finish_completed(
        self,
        job_id: str,
        phase: LogsArtifactPhase,
        *,
        activation_id: str,
        artifact_ref: str,
        evidence_status: str,
    ) -> LogsJobRecord:
        with self._job_lock(job_id):
            record = self._read_required(job_id)
            current = record.phases.get(phase.value)
            if current is None or current.activation_id != activation_id:
                raise LogsJobError("completion does not match active claim")
            if current.state not in {"started", "result_persisted"}:
                raise LogsJobError("completion phase is not resumable")

            current.state = "succeeded"
            current.finished_at = _finish_now(current)
            current.artifact_ref = artifact_ref
            current.evidence_status = evidence_status
            record.phases[phase.value] = current
            record.updated_at = current.finished_at

            if phase == LogsArtifactPhase.INITIAL:
                record.job_state = (
                    LogsJobState.PENDING
                    if evidence_status not in {"failed", "not_available"}
                    else LogsJobState.PARTIAL
                )
            elif phase == LogsArtifactPhase.COMPLETE:
                if (
                    record.late_check_enabled
                    and evidence_status in {
                        "no_data",
                        "partial",
                        "failed",
                        "not_available",
                    }
                ):
                    record.job_state = LogsJobState.PARTIAL
                else:
                    record.job_state = self._terminal_job_state(evidence_status)
            else:
                record.job_state = self._terminal_job_state(evidence_status)

            self._write(record)
            return record

    def finish_safe_retry(
        self,
        job_id: str,
        phase: LogsArtifactPhase,
        *,
        activation_id: str,
        error_code: str,
    ) -> LogsJobRecord:
        with self._job_lock(job_id):
            record = self._read_required(job_id)
            current = record.phases.get(phase.value)
            if (
                current is None
                or current.state != "started"
                or current.activation_id != activation_id
            ):
                raise LogsJobError("retry completion does not match active claim")
            current.finished_at = _finish_now(current)
            current.last_error_code = str(error_code)[:128]
            if current.attempts < record.max_attempts_per_phase:
                current.state = "failed_retryable"
                current.retry_not_before = current.finished_at + timedelta(
                    seconds=record.retry_delay_seconds
                )
                record.job_state = LogsJobState.PARTIAL
            else:
                current.state = "failed_terminal"
                record.job_state = LogsJobState.FAILED
            record.phases[phase.value] = current
            record.updated_at = current.finished_at
            self._write(record)
            return record

    def finish_terminal_without_query(
        self,
        job_id: str,
        phase: LogsArtifactPhase,
        *,
        activation_id: str,
        error_code: str,
    ) -> LogsJobRecord:
        """Record a deterministic pre-query contract failure without retrying it."""
        with self._job_lock(job_id):
            record = self._read_required(job_id)
            current = record.phases.get(phase.value)
            if (
                current is None
                or current.state != "started"
                or current.activation_id != activation_id
            ):
                raise LogsJobError("terminal completion does not match active claim")
            current.state = "failed_terminal"
            current.finished_at = _finish_now(current)
            current.last_error_code = str(error_code)[:128]
            record.phases[phase.value] = current
            record.job_state = LogsJobState.FAILED
            record.updated_at = current.finished_at
            self._write(record)
            return record

    def mark_ambiguous(
        self,
        job_id: str,
        phase: LogsArtifactPhase,
        *,
        activation_id: str,
        error_code: str,
    ) -> LogsJobRecord:
        with self._job_lock(job_id):
            record = self._read_required(job_id)
            current = record.phases.get(phase.value)
            if (
                current is None
                or current.state != "started"
                or current.activation_id != activation_id
            ):
                raise LogsJobError("ambiguous mark does not match active claim")
            current.state = "ambiguous"
            current.finished_at = _finish_now(current)
            current.last_error_code = str(error_code)[:128]
            record.phases[phase.value] = current
            record.job_state = LogsJobState.PARTIAL
            record.updated_at = current.finished_at
            self._write(record)
            return record

    def reconcile_inflight(self, *, stale_before: datetime) -> int:
        """Reconcile only states proven to predate this process start.

        A current-process concurrent worker that sees ``started`` must never
        turn it ambiguous.  For a previous-process state, a deterministic
        result checkpoint proves the external response completed and allows
        downstream-only resume; otherwise the call is ambiguous/no-retry.
        """
        if stale_before.tzinfo is None or stale_before.utcoffset() is None:
            raise ValueError("stale_before must be timezone-aware")
        changed = 0
        for path in self._job_paths():
            try:
                record = LogsJobRecord.model_validate_json(
                    path.read_text(encoding="utf-8")
                )
            except Exception as exc:
                raise LogsJobError(
                    f"job state unreadable during reconciliation: {path.name}"
                ) from exc
            if path.stem != record.job_id:
                raise LogsJobError(
                    f"job state filename identity mismatch: {path.name}"
                )
            with self._job_lock(record.job_id):
                record = self._read_required(record.job_id)
                dirty = False
                for key, state in record.phases.items():
                    if (
                        state.state != "started"
                        or state.started_at is None
                        or state.started_at >= stale_before
                    ):
                        continue
                    phase = LogsArtifactPhase(key)
                    filename = self._result_filename(record.job_id, phase)
                    checkpoint_path = self.results_root / filename
                    if checkpoint_path.is_file() and not checkpoint_path.is_symlink():
                        try:
                            digest = self._sha256(checkpoint_path)
                            checkpoint = self._read_result_checkpoint(filename, digest)
                            checkpoint_time = self._checkpoint_query_time(checkpoint)
                            self._result_from_checkpoint(
                                checkpoint, expected_job_id=record.job_id, expected_phase=phase
                            )
                        except Exception:
                            state.state = "ambiguous"
                            state.last_error_code = "result_checkpoint_invalid"
                        else:
                            state.state = "result_persisted"
                            state.result_checkpoint_ref = filename
                            state.result_checkpoint_sha256 = digest
                            if state.query_executed_at is None:
                                state.query_executed_at = checkpoint_time
                    else:
                        state.state = "ambiguous"
                        state.last_error_code = "process_restart_after_started"
                    state.finished_at = max(_utcnow(), state.started_at)
                    record.phases[key] = state
                    dirty = True
                if dirty:
                    record.job_state = LogsJobState.PARTIAL
                    record.updated_at = _utcnow()
                    self._write(record)
                    changed += 1
        return changed

    def recover_actions(
        self,
        *,
        now: datetime | None = None,
        limit: int = 16,
    ) -> list[tuple[LogsJobRecord, LogsArtifactPhase]]:
        current = now or _utcnow()
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        output: list[tuple[LogsJobRecord, LogsArtifactPhase]] = []

        for path in self._job_paths():
            if len(output) >= limit:
                break
            try:
                record = LogsJobRecord.model_validate_json(
                    path.read_text(encoding="utf-8")
                )
            except Exception as exc:
                raise LogsJobError(
                    f"job state unreadable during recovery scan: {path.name}"
                ) from exc
            if path.stem != record.job_id:
                raise LogsJobError(
                    f"job state filename identity mismatch: {path.name}"
                )

            initial = record.phases.get(LogsArtifactPhase.INITIAL.value)
            if initial is None or initial.state == "pending":
                output.append((record, LogsArtifactPhase.INITIAL))
                continue
            if initial.state == "result_persisted":
                output.append((record, LogsArtifactPhase.INITIAL))
                continue
            if initial.state == "failed_retryable":
                if (
                    initial.retry_not_before is None
                    or initial.retry_not_before <= current
                ):
                    output.append((record, LogsArtifactPhase.INITIAL))
                continue
            if initial.state != "succeeded":
                continue

            complete = record.phases.get(LogsArtifactPhase.COMPLETE.value)
            if complete is not None and complete.state == "result_persisted":
                output.append((record, LogsArtifactPhase.COMPLETE))
                continue
            if record.due_at > current:
                continue
            if complete is None or complete.state == "pending":
                output.append((record, LogsArtifactPhase.COMPLETE))
                continue
            if complete.state == "failed_retryable" and (
                complete.retry_not_before is None
                or complete.retry_not_before <= current
            ):
                output.append((record, LogsArtifactPhase.COMPLETE))
                continue
            if complete.state != "succeeded":
                continue

            if not record.late_check_enabled:
                continue
            if complete.evidence_status not in {
                "no_data",
                "partial",
                "failed",
                "not_available",
            }:
                continue
            if record.late_check_due_at is None or record.late_check_due_at > current:
                continue

            late = record.phases.get(LogsArtifactPhase.LATE_CHECK.value)
            if late is not None and late.state == "result_persisted":
                output.append((record, LogsArtifactPhase.LATE_CHECK))
                continue
            if late is None or late.state == "pending":
                output.append((record, LogsArtifactPhase.LATE_CHECK))
                continue
            if late.state == "failed_retryable" and (
                late.retry_not_before is None
                or late.retry_not_before <= current
            ):
                output.append((record, LogsArtifactPhase.LATE_CHECK))

        return output

    def load(self, job_id: str) -> LogsJobRecord:
        with self._job_lock(job_id):
            return self._read_required(job_id)

    @staticmethod
    def _terminal_job_state(evidence_status: str) -> LogsJobState:
        if evidence_status in {"success", "no_data"}:
            return LogsJobState.COMPLETE
        if evidence_status == "partial":
            return LogsJobState.PARTIAL
        return LogsJobState.FAILED

    @staticmethod
    def _validate_job_id(job_id: str) -> str:
        if len(job_id) != 32 or any(
            ch not in "0123456789abcdef" for ch in job_id
        ):
            raise LogsJobError("unsafe job_id")
        return job_id

    def _path(self, job_id: str) -> Path:
        return self.jobs_root / f"{self._validate_job_id(job_id)}.json"

    def _job_paths(self) -> list[Path]:
        return (
            sorted(self.jobs_root.glob("*.json"))
            if self.jobs_root.exists()
            else []
        )

    @staticmethod
    def _result_filename(job_id: str, phase: LogsArtifactPhase) -> str:
        LogsJobStore._validate_job_id(job_id)
        return f"{job_id}.{phase.value}.result.json"

    def _read_optional(self, job_id: str) -> LogsJobRecord | None:
        path = self._path(job_id)
        if not path.exists():
            return None
        if path.is_symlink():
            raise LogsJobError("refusing symlink job state")
        try:
            return LogsJobRecord.model_validate_json(
                path.read_text(encoding="utf-8")
            )
        except Exception as exc:
            raise LogsJobError("job state unreadable") from exc

    def _read_required(self, job_id: str) -> LogsJobRecord:
        value = self._read_optional(job_id)
        if value is None:
            raise LogsJobError("job state does not exist")
        return value

    def _write(self, record: LogsJobRecord) -> None:
        self.writer.write_json(
            f"{record.job_id}.json",
            record.model_dump(mode="json"),
        )

    def _read_result_checkpoint(
        self,
        filename: str,
        expected_sha256: str | None,
    ) -> Mapping[str, Any]:
        path = self.results_root / filename
        if path.parent != self.results_root or path.is_symlink() or not path.is_file():
            raise LogsJobError("result checkpoint path invalid")
        if expected_sha256 and self._sha256(path) != expected_sha256:
            raise LogsJobError("result checkpoint SHA mismatch")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise LogsJobError("result checkpoint unreadable") from exc
        if not isinstance(value, Mapping):
            raise LogsJobError("result checkpoint root must be object")
        return value

    @staticmethod
    def _checkpoint_query_time(checkpoint: Mapping[str, Any]) -> datetime:
        raw = checkpoint.get("query_executed_at")
        if not isinstance(raw, str):
            raise LogsJobError("result checkpoint query_executed_at missing")
        try:
            value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError as exc:
            raise LogsJobError("result checkpoint query_executed_at invalid") from exc
        if value.tzinfo is None or value.utcoffset() is None:
            raise LogsJobError("result checkpoint query_executed_at must be aware")
        return value.astimezone(timezone.utc)

    @classmethod
    def _result_from_checkpoint(
        cls,
        checkpoint: Mapping[str, Any],
        *,
        expected_job_id: str | None = None,
        expected_phase: LogsArtifactPhase | None = None,
    ) -> Mapping[str, Any]:
        if checkpoint.get("schema_version") != "v14.w1.logs-result-checkpoint.v1":
            raise LogsJobError("result checkpoint schema mismatch")
        cls._checkpoint_query_time(checkpoint)
        if expected_job_id is not None and checkpoint.get("job_id") != expected_job_id:
            raise LogsJobError("result checkpoint job_id mismatch")
        if expected_phase is not None and checkpoint.get("phase") != expected_phase.value:
            raise LogsJobError("result checkpoint phase mismatch")
        result = checkpoint.get("result")
        if not isinstance(result, Mapping):
            raise LogsJobError("result checkpoint result missing")
        return result

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @contextmanager
    def _job_lock(self, job_id: str) -> Iterator[None]:
        job_id = self._validate_job_id(job_id)
        if self.locks_root.exists() and self.locks_root.is_symlink():
            raise LogsJobError("locks root symlink")
        self.locks_root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.locks_root, 0o700)
        lock_path = self.locks_root / f"{job_id}.lock"
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(lock_path, flags, 0o600)
        try:
            with os.fdopen(fd, "r+", encoding="utf-8") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                yield
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            pass
