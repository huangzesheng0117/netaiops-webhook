"""Persistent V13-D1 Evidence Capability broker.

The broker is deliberately execution-agnostic. D1 provides deterministic
identity, file-lock serialization, atomic checkpoints, bounded retry semantics,
and v12 EvidenceEnvelope validation. D3 will connect approved Prometheus and
Netmiko execution adapters to this broker.
"""

from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Literal

from pydantic import ValidationError

from netaiops.v12.contracts import ContractNotice, EvidenceEnvelope
from netaiops.v12.schema_validator import (
    build_contract_ref,
    sanitize_sensitive_data,
    validate_request_id,
)
from netaiops.v12.status import EvidenceSource, EvidenceStatus

from .capability_contracts import (
    CapabilityCheckpoint,
    CapabilityDecision,
    CapabilityRequest,
    DeviceCapabilityRequest,
    build_capability_dedup_key,
    build_target_fingerprint,
)


Executor = Callable[[CapabilityRequest, int], EvidenceEnvelope]
FailureKind = Literal["failed", "timeout"]


class CapabilityExecutionError(RuntimeError):
    """Typed, bounded-retry execution failure raised by a D3 adapter."""

    def __init__(self, kind: FailureKind, code: str, message: str) -> None:
        if kind not in {"failed", "timeout"}:
            raise ValueError("CapabilityExecutionError kind must be failed/timeout")
        super().__init__(message)
        self.kind = kind
        self.code = str(code or "capability_execution_error")[:128]
        self.safe_message = str(message or "capability execution failed")[:512]


class EvidenceCapabilityBroker:
    """Serialize one capability identity and reuse its terminal checkpoint."""

    def __init__(
        self,
        checkpoint_root: str | Path,
        *,
        utcnow: Callable[[], datetime] | None = None,
    ) -> None:
        self.checkpoint_root = Path(checkpoint_root)
        self._utcnow = utcnow or (lambda: datetime.now(timezone.utc))
        self._ensure_root()

    def execute(
        self,
        request: CapabilityRequest,
        executor: Executor,
    ) -> CapabilityDecision:
        dedup_key = build_capability_dedup_key(request)
        request_dir = self._request_dir(request.request_id)
        checkpoint_path = request_dir / f"{dedup_key}.json"
        lock_path = request_dir / f"{dedup_key}.lock"

        with self._exclusive_lock(lock_path):
            existing = self._read_checkpoint(checkpoint_path)
            existing = self._recover_interrupted(existing, request, checkpoint_path)

            if existing is not None and existing.terminal:
                return self._decision(
                    action="reused_checkpoint",
                    checkpoint_path=checkpoint_path,
                    checkpoint=existing,
                    external_call_performed=False,
                )

            if isinstance(request, DeviceCapabilityRequest):
                if request.safety_policy_allowed is not True:
                    checkpoint = self._policy_blocked_checkpoint(request, dedup_key)
                    self._write_checkpoint(checkpoint_path, checkpoint)
                    return self._decision(
                        action="policy_blocked",
                        checkpoint_path=checkpoint_path,
                        checkpoint=checkpoint,
                        external_call_performed=False,
                    )

            previous_attempts = existing.attempts if existing is not None else 0
            if previous_attempts >= request.max_attempts:
                if existing is None:
                    raise RuntimeError("attempt budget exhausted without checkpoint")
                return self._decision(
                    action="reused_checkpoint",
                    checkpoint_path=checkpoint_path,
                    checkpoint=existing,
                    external_call_performed=False,
                )

            attempt = previous_attempts + 1
            action = "retried" if previous_attempts else "executed"
            started = existing.created_at if existing is not None else self._now()
            in_progress = CapabilityCheckpoint(
                dedup_key=dedup_key,
                request_id=request.request_id,
                source=request.source,
                family=request.family,
                capability=request.capability,
                target_fingerprint=build_target_fingerprint(request),
                plan_fingerprint=request.plan_fingerprint,
                template_fingerprint=request.template_fingerprint,
                status="in_progress",
                attempts=attempt,
                max_attempts=request.max_attempts,
                terminal=False,
                reusable=False,
                created_at=started,
                updated_at=self._now(),
            )
            self._write_checkpoint(checkpoint_path, in_progress)

            try:
                envelope = executor(request, attempt)
                envelope = EvidenceEnvelope.model_validate(envelope)
                self._validate_envelope(request, envelope)
                checkpoint = self._checkpoint_from_envelope(
                    request=request,
                    dedup_key=dedup_key,
                    attempt=attempt,
                    created_at=started,
                    envelope=envelope,
                )
            except CapabilityExecutionError as exc:
                checkpoint = self._failure_checkpoint(
                    request=request,
                    dedup_key=dedup_key,
                    attempt=attempt,
                    created_at=started,
                    status=exc.kind,
                    code=exc.code,
                    message=exc.safe_message,
                )
            except (ValidationError, ValueError) as exc:
                checkpoint = self._failure_checkpoint(
                    request=request,
                    dedup_key=dedup_key,
                    attempt=attempt,
                    created_at=started,
                    status="failed",
                    code="capability_envelope_invalid",
                    message=f"Capability EvidenceEnvelope validation failed: {type(exc).__name__}",
                )
            except Exception as exc:
                checkpoint = self._failure_checkpoint(
                    request=request,
                    dedup_key=dedup_key,
                    attempt=attempt,
                    created_at=started,
                    status="failed",
                    code="capability_executor_exception",
                    message=f"Capability executor raised {type(exc).__name__}",
                )

            self._write_checkpoint(checkpoint_path, checkpoint)
            return self._decision(
                action=action,
                checkpoint_path=checkpoint_path,
                checkpoint=checkpoint,
                external_call_performed=True,
            )

    def get_checkpoint(self, request: CapabilityRequest) -> CapabilityCheckpoint | None:
        dedup_key = build_capability_dedup_key(request)
        path = self._request_dir(request.request_id) / f"{dedup_key}.json"
        return self._read_checkpoint(path)

    def _checkpoint_from_envelope(
        self,
        *,
        request: CapabilityRequest,
        dedup_key: str,
        attempt: int,
        created_at: datetime,
        envelope: EvidenceEnvelope,
    ) -> CapabilityCheckpoint:
        status_map = {
            EvidenceStatus.SUCCESS: "success",
            EvidenceStatus.PARTIAL: "partial",
            EvidenceStatus.NO_DATA: "no_data",
            EvidenceStatus.NOT_AVAILABLE: "not_available",
            EvidenceStatus.FAILED: "failed",
        }
        if envelope.status not in status_map:
            raise ValueError("executor may not return skipped EvidenceEnvelope")
        status = status_map[envelope.status]
        terminal = status in {"success", "partial", "no_data", "not_available"}
        if status == "failed" and attempt >= request.max_attempts:
            terminal = True
        return CapabilityCheckpoint(
            dedup_key=dedup_key,
            request_id=request.request_id,
            source=request.source,
            family=request.family,
            capability=request.capability,
            target_fingerprint=build_target_fingerprint(request),
            plan_fingerprint=request.plan_fingerprint,
            template_fingerprint=request.template_fingerprint,
            status=status,
            attempts=attempt,
            max_attempts=request.max_attempts,
            terminal=terminal,
            reusable=terminal,
            envelope=envelope,
            created_at=created_at,
            updated_at=self._now(),
        )

    def _failure_checkpoint(
        self,
        *,
        request: CapabilityRequest,
        dedup_key: str,
        attempt: int,
        created_at: datetime,
        status: FailureKind,
        code: str,
        message: str,
    ) -> CapabilityCheckpoint:
        notice = ContractNotice(
            code=code,
            message=message,
            stage=f"v13_{request.source}_capability",
            retryable=attempt < request.max_attempts,
            details={"attempt": attempt, "max_attempts": request.max_attempts},
        )
        envelope = EvidenceEnvelope(
            schema_version="v12.1",
            request_id=request.request_id,
            source=EvidenceSource(request.source),
            evidence_kind="evidence",
            status=EvidenceStatus.FAILED,
            summary="Evidence capability execution failed.",
            facts={
                "capability": request.capability,
                "attempt": attempt,
                "max_attempts": request.max_attempts,
                "failure_kind": status,
            },
            scope={"family": request.family, "target": request.target},
            errors=[notice],
            collected_at=self._now(),
        )
        terminal = attempt >= request.max_attempts
        return CapabilityCheckpoint(
            dedup_key=dedup_key,
            request_id=request.request_id,
            source=request.source,
            family=request.family,
            capability=request.capability,
            target_fingerprint=build_target_fingerprint(request),
            plan_fingerprint=request.plan_fingerprint,
            template_fingerprint=request.template_fingerprint,
            status=status,
            attempts=attempt,
            max_attempts=request.max_attempts,
            terminal=terminal,
            reusable=terminal,
            envelope=envelope,
            last_error=notice,
            created_at=created_at,
            updated_at=self._now(),
        )

    def _policy_blocked_checkpoint(
        self,
        request: DeviceCapabilityRequest,
        dedup_key: str,
    ) -> CapabilityCheckpoint:
        now = self._now()
        notice = ContractNotice(
            code="device_safety_policy_blocked",
            message="Device capability was blocked before execution by Safety Policy.",
            stage="v13_device_capability",
            retryable=False,
            details={"policy_reasons": list(request.safety_policy_reasons)},
        )
        envelope = EvidenceEnvelope(
            schema_version="v12.1",
            request_id=request.request_id,
            source=EvidenceSource.DEVICE,
            evidence_kind="evidence",
            status=EvidenceStatus.SKIPPED,
            summary="Device capability was blocked by Safety Policy.",
            facts={
                "capability": request.capability,
                "external_call_performed": False,
                "write_command_executed": False,
            },
            scope={"family": request.family, "target": request.target},
            warnings=[notice],
            collected_at=now,
            reason="policy_blocked",
        )
        return CapabilityCheckpoint(
            dedup_key=dedup_key,
            request_id=request.request_id,
            source=request.source,
            family=request.family,
            capability=request.capability,
            target_fingerprint=build_target_fingerprint(request),
            plan_fingerprint=request.plan_fingerprint,
            template_fingerprint=request.template_fingerprint,
            status="policy_blocked",
            attempts=0,
            max_attempts=request.max_attempts,
            terminal=True,
            reusable=True,
            envelope=envelope,
            last_error=notice,
            created_at=now,
            updated_at=now,
        )

    def _recover_interrupted(
        self,
        checkpoint: CapabilityCheckpoint | None,
        request: CapabilityRequest,
        checkpoint_path: Path,
    ) -> CapabilityCheckpoint | None:
        if checkpoint is None or checkpoint.status != "in_progress":
            return checkpoint
        recovered = self._failure_checkpoint(
            request=request,
            dedup_key=checkpoint.dedup_key,
            attempt=checkpoint.attempts,
            created_at=checkpoint.created_at,
            status="failed",
            code="capability_interrupted_in_progress",
            message="Previous capability attempt ended before a terminal checkpoint was written.",
        )
        self._write_checkpoint(checkpoint_path, recovered)
        return recovered

    @staticmethod
    def _validate_envelope(
        request: CapabilityRequest,
        envelope: EvidenceEnvelope,
    ) -> None:
        if envelope.request_id != request.request_id:
            raise ValueError("EvidenceEnvelope request_id does not match capability request")
        if str(envelope.source) != request.source:
            raise ValueError("EvidenceEnvelope source does not match capability request")
        if envelope.status == EvidenceStatus.SKIPPED:
            raise ValueError("policy_blocked must be decided before executor invocation")

    def _decision(
        self,
        *,
        action: str,
        checkpoint_path: Path,
        checkpoint: CapabilityCheckpoint,
        external_call_performed: bool,
    ) -> CapabilityDecision:
        checkpoint_ref = build_contract_ref(
            "artifact",
            checkpoint.request_id,
            "capability_checkpoint",
            f"cp-{checkpoint.dedup_key[:24]}",
        )
        return CapabilityDecision(
            action=action,
            dedup_key=checkpoint.dedup_key,
            checkpoint_ref=checkpoint_ref,
            external_call_performed=external_call_performed,
            checkpoint=checkpoint,
        )

    def _request_dir(self, request_id: str) -> Path:
        validate_request_id(request_id)
        path = self.checkpoint_root / request_id
        if path.exists() and path.is_symlink():
            raise RuntimeError("checkpoint request directory must not be a symlink")
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _ensure_root(self) -> None:
        if self.checkpoint_root.exists() and self.checkpoint_root.is_symlink():
            raise RuntimeError("checkpoint root must not be a symlink")
        created = not self.checkpoint_root.exists()
        self.checkpoint_root.mkdir(parents=True, exist_ok=True)
        if created:
            os.chmod(self.checkpoint_root, 0o700)

    @contextmanager
    def _exclusive_lock(self, lock_path: Path) -> Iterator[None]:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            with os.fdopen(fd, "a+", encoding="utf-8", closefd=False) as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            os.close(fd)

    @staticmethod
    def _read_checkpoint(path: Path) -> CapabilityCheckpoint | None:
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("checkpoint must be a regular file")
        payload = json.loads(path.read_text(encoding="utf-8"))
        return CapabilityCheckpoint.model_validate(payload)

    @staticmethod
    def _write_checkpoint(path: Path, checkpoint: CapabilityCheckpoint) -> None:
        payload = sanitize_sensitive_data(checkpoint.model_dump(mode="json"))
        raw = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        ) + "\n"
        tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        fd = os.open(str(tmp), flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", closefd=False) as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
            dir_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            if tmp.exists():
                tmp.unlink()

    def _now(self) -> datetime:
        value = self._utcnow()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("utcnow provider must return a timezone-aware datetime")
        return value
