"""Metrics/Device unique upper owner wrappers for V13-D3."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from netaiops.v12.contracts import EvidenceEnvelope

from .capability_broker import EvidenceCapabilityBroker, Executor
from .capability_contracts import (
    CapabilityDecision,
    DeviceCapabilityRequest,
    MetricsCapabilityRequest,
    build_capability_dedup_key,
)
from .evidence_owner_contracts import D3OwnerOutcome, EvidenceOwnerRecord, LegacyCallFenceRecord
from .legacy_call_fence import LegacyCallFence


class EvidenceOwnerError(RuntimeError):
    pass


class _BaseOwner:
    source: str
    owner_name: str

    def __init__(
        self,
        *,
        broker: EvidenceCapabilityBroker,
        fence: LegacyCallFence,
        utcnow: Callable[[], datetime] | None = None,
    ) -> None:
        self.broker = broker
        self.fence = fence
        self._utcnow = utcnow or (lambda: datetime.now(timezone.utc))

    def _execute(self, request, executor: Executor) -> D3OwnerOutcome:
        if request.source != self.source:
            raise EvidenceOwnerError("capability source does not match owner")
        # Fence the legacy caller immediately before the broker invokes the
        # real executor.  This closes the concurrent window in which the old
        # Sidecar/Runner could otherwise issue the same source call while the
        # new owner is in progress.  The conservative attempted=True marker is
        # intentional: after this boundary legacy must never retry ambiguously.
        dedup_key = build_capability_dedup_key(request)

        def fenced_executor(inner_request, attempt: int):
            self.fence.record(
                LegacyCallFenceRecord(
                    request_id=request.request_id,
                    family=request.family,
                    source=self.source,
                    dedup_key=dedup_key,
                    owner=self.owner_name,
                    active=True,
                    external_call_already_attempted=True,
                    recorded_at=self._now(),
                )
            )
            return executor(inner_request, attempt)

        decision = self.broker.execute(request, fenced_executor)
        checkpoint = decision.checkpoint
        if checkpoint.envelope is None:
            raise EvidenceOwnerError("owner decision has no EvidenceEnvelope")
        owner_record = EvidenceOwnerRecord(
            request_id=request.request_id,
            family=request.family,
            source=self.source,
            owner=self.owner_name,
            capability=request.capability,
            dedup_key=decision.dedup_key,
            checkpoint_ref=decision.checkpoint_ref,
            decision_action=decision.action,
            evidence_status=checkpoint.envelope.status,
            external_call_performed=decision.external_call_performed,
            legacy_active_call_allowed=False,
            arbitrary_query_or_command_generated=False,
            write_command_executed=False,
            completed_at=self._now(),
        )
        fence_record = LegacyCallFenceRecord(
            request_id=request.request_id,
            family=request.family,
            source=self.source,
            dedup_key=decision.dedup_key,
            owner=self.owner_name,
            active=True,
            external_call_already_attempted=bool(
                decision.external_call_performed or checkpoint.attempts > 0
            ),
            recorded_at=self._now(),
        )
        self.fence.record(fence_record)
        return D3OwnerOutcome(
            owner_record=owner_record,
            fence_record=fence_record,
            capability_decision=decision,
        )

    def _now(self) -> datetime:
        value = self._utcnow()
        if value.tzinfo is None or value.utcoffset() is None:
            raise EvidenceOwnerError("utcnow must be timezone-aware")
        return value


class MetricsEvidenceOwner(_BaseOwner):
    source = "metrics"
    owner_name = "metrics_agent"

    def execute(self, request: MetricsCapabilityRequest, executor: Executor) -> D3OwnerOutcome:
        return self._execute(request, executor)


class DeviceEvidenceOwner(_BaseOwner):
    source = "device"
    owner_name = "device_agent"

    def execute(self, request: DeviceCapabilityRequest, executor: Executor) -> D3OwnerOutcome:
        return self._execute(request, executor)
