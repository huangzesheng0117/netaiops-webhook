"""V13-D2 single Triage classification owner.

The production implementation reuses the existing v12 ``TriageAgent``.  A
small pre-normalized adapter prevents a second Normalizer pass, so the D2 path
is exactly:

    Normalized Event -> existing TriageAgent -> canonical UnifiedAlertEvent

The existing TriageAgent remains the only component that calls the Family
Registry in this D2 path.  No LLM/MCP/device/notification side effect is
introduced, and Primary activation remains false.
"""

from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Mapping

from netaiops.v12.agents.triage_agent import TriageAgent
from netaiops.v12.contracts import UnifiedAlertEvent
from netaiops.v12.execution_context import AgentInvocation
from netaiops.v12.schema_validator import (
    build_contract_ref,
    sanitize_sensitive_data,
    validate_request_id,
)
from netaiops.v12.state_machine import OrchestrationState
from netaiops.v12.status import AgentName, AgentStatus

from .triage_contracts import (
    MIGRATED_FAMILIES,
    TriageOwnershipRecord,
    stable_fingerprint,
)


TriageRunner = Callable[
    [str, str, Mapping[str, Any], datetime],
    Awaitable[tuple[AgentStatus, Mapping[str, Any], tuple[str, ...]]],
]


class TriageOwnerError(ValueError):
    """Raised when an already normalized event cannot be owned safely."""


class _PreNormalizedAdapter:
    """Adapter accepted by v12 TriageAgent that returns exactly one input event."""

    def __init__(self, event: Mapping[str, Any]) -> None:
        self.event = deepcopy(dict(event))

    def select_event(
        self,
        source: str,
        payload: Mapping[str, Any],
        *,
        event_index: int = 0,
    ) -> dict[str, Any]:
        if event_index != 0:
            raise ValueError("D2 pre-normalized adapter supports only event_index=0")
        return deepcopy(self.event)


class TriageOwner:
    """D2 wrapper that makes the existing TriageAgent the sole family owner."""

    def __init__(
        self,
        *,
        triage_runner: TriageRunner | None = None,
        utcnow: Callable[[], datetime] | None = None,
    ) -> None:
        self._runner = triage_runner or self._run_v12_triage
        self._utcnow = utcnow or (lambda: datetime.now(timezone.utc))

    def classify_normalized(
        self,
        *,
        request_id: str,
        source: str,
        normalized_event: Mapping[str, Any],
        mode: str = "build_only",
    ) -> TriageOwnershipRecord:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(
                self.classify_normalized_async(
                    request_id=request_id,
                    source=source,
                    normalized_event=normalized_event,
                    mode=mode,
                )
            )
        raise TriageOwnerError(
            "classify_normalized cannot run inside an active event loop; use classify_normalized_async"
        )

    async def classify_normalized_async(
        self,
        *,
        request_id: str,
        source: str,
        normalized_event: Mapping[str, Any],
        mode: str = "build_only",
    ) -> TriageOwnershipRecord:
        request_id = validate_request_id(request_id)
        normalized_source = str(source or "").strip().lower()
        if normalized_source not in {"alertmanager", "elastic", "replay"}:
            raise TriageOwnerError(f"unsupported normalized source: {normalized_source}")
        if mode not in {"build_only", "store_only", "shadow"}:
            raise TriageOwnerError(f"unsupported D2 mode: {mode}")
        if not isinstance(normalized_event, Mapping) or not normalized_event:
            raise TriageOwnerError("normalized_event must be a non-empty mapping")

        event = sanitize_sensitive_data(dict(normalized_event))
        if not isinstance(event, dict) or not event:
            raise TriageOwnerError("normalized_event was empty after sanitization")
        now = self._aware_now()

        status, output, output_refs = await self._runner(
            request_id,
            normalized_source,
            event,
            now,
        )
        if status not in {AgentStatus.SUCCESS, AgentStatus.PARTIAL}:
            raise TriageOwnerError(f"v12 TriageAgent did not produce usable output: {status}")
        raw_family_result = output.get("family_result") if isinstance(output, Mapping) else None
        family_result = sanitize_sensitive_data(dict(raw_family_result)) if isinstance(raw_family_result, Mapping) else {}
        raw_unified = output.get("unified_event") if isinstance(output, Mapping) else None
        if not isinstance(raw_unified, Mapping):
            raise TriageOwnerError("v12 TriageAgent output missing unified_event")
        unified = UnifiedAlertEvent.model_validate(raw_unified)
        if unified.request_id != request_id:
            raise TriageOwnerError("v12 TriageAgent request_id mismatch")

        family = str(unified.family or "generic_network_readonly").strip()
        attributes = dict(unified.alert_object.attributes)
        confidence = str(attributes.get("family_confidence") or "low").strip().lower()
        if confidence not in {"high", "medium", "low"}:
            confidence = "low"
        migrated = family in MIGRATED_FAMILIES
        routing_action = "controlled_orchestrator" if migrated else "fallback_legacy"
        fallback_reason = None if migrated else (
            "generic_or_unknown_family"
            if family == "generic_network_readonly"
            else "family_not_migrated_in_v13_d2"
        )
        triage_output_ref = (
            str(output_refs[0])
            if output_refs
            else build_contract_ref(
                "event",
                request_id,
                "unified_alert",
                unified.event_id,
            )
        )

        return TriageOwnershipRecord(
            request_id=request_id,
            source=normalized_source,
            mode=mode,
            normalized_event_fingerprint=stable_fingerprint(event),
            triage_output_ref=triage_output_ref,
            unified_event=unified,
            family=family,
            family_confidence=confidence,
            match_source=str(attributes.get("match_source") or ""),
            match_reason=str(attributes.get("match_reason") or ""),
            target_kind=unified.alert_object.kind,
            target_scope=dict(attributes.get("target_scope") or {}),
            auto_execute_allowed=bool(attributes.get("auto_execute_allowed", False)),
            family_result=(
                family_result
                if family_result
                else {
                    "family": family,
                    "family_confidence": confidence,
                    "match_source": str(attributes.get("match_source") or ""),
                    "match_reason": str(attributes.get("match_reason") or ""),
                    "target_kind": unified.alert_object.kind,
                    "auto_execute_allowed": bool(attributes.get("auto_execute_allowed", False)),
                    "target_scope": dict(attributes.get("target_scope") or {}),
                }
            ),
            migrated_family=migrated,
            routing_action=routing_action,
            fallback_reason=fallback_reason,
            classified_at=now,
        )

    async def _run_v12_triage(
        self,
        request_id: str,
        source: str,
        event: Mapping[str, Any],
        received_at: datetime,
    ) -> tuple[AgentStatus, Mapping[str, Any], tuple[str, ...]]:
        adapter = _PreNormalizedAdapter(event)
        agent = TriageAgent(
            source=source,
            payload={"_v13_pre_normalized": True},
            event_index=0,
            received_at=received_at,
            adapter=adapter,
        )
        invocation = AgentInvocation(
            request_id=request_id,
            agent_name=AgentName.TRIAGE,
            orchestration_state=OrchestrationState.TRIAGE,
            prior_output_refs=(),
            prior_outputs={},
        )
        outcome = await agent.run(invocation)
        if outcome.external_calls:
            raise TriageOwnerError("v12 TriageAgent unexpectedly reported external calls")
        return outcome.status, outcome.output, outcome.output_refs

    @staticmethod
    def record_ref(record: TriageOwnershipRecord) -> str:
        return build_contract_ref(
            "agent",
            record.request_id,
            "triage_owner",
            record.normalized_event_fingerprint[:24],
        )

    def _aware_now(self) -> datetime:
        value = self._utcnow()
        if value.tzinfo is None or value.utcoffset() is None:
            raise TriageOwnerError("utcnow provider must return timezone-aware datetime")
        return value
