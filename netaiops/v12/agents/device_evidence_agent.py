"""Deterministic v12 Device Evidence Agent.

Batch G only reuses existing execution results. It does not call Netmiko MCP,
does not generate CLI, does not execute write commands, and does not bypass the
existing Safety Policy.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Mapping

from pydantic import ValidationError

from ..adapters.device_evidence_adapter import (
    DeviceEvidenceAdapter,
    DeviceEvidenceAdapterError,
)
from ..contracts import ContractNotice, EvidenceEnvelope, EvidencePlan
from ..execution_context import AgentInvocation, AgentOutcome
from ..schema_validator import build_contract_ref
from ..status import AgentName, AgentStatus, EvidenceSource, EvidenceStatus


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _notice(
    code: str,
    message: str,
    *,
    details: Mapping[str, Any] | None = None,
) -> ContractNotice:
    return ContractNotice(
        code=code,
        message=message,
        stage="device_evidence",
        retryable=False,
        details=dict(details or {}),
    )


class DeviceEvidenceAgent:
    """Wrap existing readonly device evidence without another MCP call."""

    def __init__(
        self,
        *,
        adapter: DeviceEvidenceAdapter | None = None,
        utcnow: Any | None = None,
    ) -> None:
        self.adapter = adapter or DeviceEvidenceAdapter()
        self._utcnow = utcnow or (lambda: datetime.now(timezone.utc))

    async def run(self, invocation: AgentInvocation) -> AgentOutcome:
        if invocation.agent_name != AgentName.DEVICE_EVIDENCE:
            return self._failed(
                invocation.request_id,
                "device_agent_name_mismatch",
                "DeviceEvidenceAgent can only run as device_evidence",
            )

        planner_output = _mapping(
            invocation.prior_outputs.get(AgentName.STATIC_PLANNER.value)
        )
        raw_plan = planner_output.get("evidence_plan")
        if not isinstance(raw_plan, Mapping):
            return self._failed(
                invocation.request_id,
                "device_evidence_plan_missing",
                "Static Planner output did not contain evidence_plan",
            )
        try:
            plan = EvidencePlan.model_validate(raw_plan)
        except ValidationError as exc:
            return self._failed(
                invocation.request_id,
                "device_evidence_plan_invalid",
                "EvidencePlan failed contract validation",
                details={"issue_count": len(exc.errors())},
            )
        if plan.request_id != invocation.request_id:
            return self._failed(
                invocation.request_id,
                "device_evidence_request_id_mismatch",
                "EvidencePlan request_id did not match invocation",
            )

        device_source = next(
            (
                source
                for source in plan.sources
                if source.source == EvidenceSource.DEVICE
            ),
            None,
        )
        if device_source is None:
            return self._failed(
                invocation.request_id,
                "device_source_plan_missing",
                "EvidencePlan did not contain the fixed device source",
            )
        constraints = dict(device_source.constraints)
        if constraints.get("readonly_only") is not True:
            return self._failed(
                invocation.request_id,
                "device_readonly_policy_rejected",
                "Device Evidence requires readonly_only=true",
            )
        if constraints.get("command_generation_allowed") is not False:
            return self._failed(
                invocation.request_id,
                "device_command_generation_policy_rejected",
                "Batch G requires command_generation_allowed=false",
            )
        if constraints.get("safety_policy_allowed") is not True:
            return self._skipped(
                invocation.request_id,
                "device_safety_policy_not_allowed",
                required=device_source.required,
                reasons=constraints.get("safety_policy_reasons", []),
            )

        try:
            normalized = self.adapter.load_existing(invocation.request_id)
        except DeviceEvidenceAdapterError as exc:
            return self._failed(
                invocation.request_id,
                "device_existing_artifact_invalid",
                "Existing device execution artifact could not be normalized",
                details={"exception_type": type(exc).__name__},
            )
        if normalized is None:
            reason = (
                "existing_device_execution_not_found"
                if device_source.required
                else "device_optional_existing_execution_not_found"
            )
            return self._not_available(
                invocation.request_id,
                reason,
                required=device_source.required,
            )

        envelope = EvidenceEnvelope(
            schema_version="v12.1",
            request_id=invocation.request_id,
            source=EvidenceSource.DEVICE,
            evidence_kind="evidence",
            status=normalized.status,
            summary=normalized.summary,
            facts=dict(normalized.facts),
            scope={
                **dict(normalized.scope),
                "required": device_source.required,
            },
            errors=list(normalized.errors),
            warnings=list(normalized.warnings),
            evidence_refs=list(normalized.evidence_refs),
            collected_at=normalized.collected_at,
            reason=normalized.reason,
        )
        envelope_ref = self._envelope_ref(
            invocation.request_id,
            normalized.source_artifact_ref,
        )
        agent_status = {
            EvidenceStatus.SUCCESS: AgentStatus.SUCCESS,
            EvidenceStatus.PARTIAL: AgentStatus.PARTIAL,
            EvidenceStatus.NO_DATA: AgentStatus.PARTIAL,
            EvidenceStatus.FAILED: AgentStatus.FAILED,
            EvidenceStatus.SKIPPED: AgentStatus.SKIPPED,
            EvidenceStatus.NOT_AVAILABLE: AgentStatus.NOT_AVAILABLE,
        }[envelope.status]
        return AgentOutcome(
            status=agent_status,
            output_refs=(envelope_ref, *normalized.evidence_refs),
            output={
                "device_evidence": envelope.model_dump(mode="json"),
                "source_artifact_ref": normalized.source_artifact_ref,
                "reuse_existing_execution": True,
                "netmiko_mcp_called": False,
                "command_generation_performed": False,
                "write_command_executed": False,
                "raw_output_forwarded": False,
                "safety_policy_bypassed": False,
            },
            warnings=normalized.warnings,
            errors=normalized.errors,
            external_calls=(),
        )

    def _not_available(
        self,
        request_id: str,
        reason: str,
        *,
        required: bool,
    ) -> AgentOutcome:
        notice = _notice(
            "device_existing_evidence_not_available",
            "No existing device execution artifact was available",
            details={"required": required, "reason": reason},
        )
        envelope = self._terminal_envelope(
            request_id=request_id,
            status=EvidenceStatus.NOT_AVAILABLE,
            summary="Existing device evidence was not available.",
            reason=reason,
            warnings=[notice],
            scope={"required": required},
        )
        return AgentOutcome(
            status=AgentStatus.NOT_AVAILABLE,
            output_refs=(self._envelope_ref(request_id, reason),),
            output=self._terminal_output(envelope),
            warnings=(notice,),
            external_calls=(),
        )

    def _skipped(
        self,
        request_id: str,
        reason: str,
        *,
        required: bool,
        reasons: Any,
    ) -> AgentOutcome:
        notice = _notice(
            "device_safety_policy_blocked",
            "Device evidence reuse was skipped by the frozen Safety Policy",
            details={
                "required": required,
                "reason": reason,
                "policy_reasons": list(reasons or []),
            },
        )
        envelope = self._terminal_envelope(
            request_id=request_id,
            status=EvidenceStatus.SKIPPED,
            summary="Device evidence was skipped by Safety Policy.",
            reason=reason,
            warnings=[notice],
            scope={"required": required},
        )
        return AgentOutcome(
            status=AgentStatus.SKIPPED,
            output_refs=(self._envelope_ref(request_id, reason),),
            output=self._terminal_output(envelope),
            warnings=(notice,),
            external_calls=(),
        )

    def _failed(
        self,
        request_id: str,
        code: str,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> AgentOutcome:
        notice = _notice(code, message, details=details)
        envelope = self._terminal_envelope(
            request_id=request_id,
            status=EvidenceStatus.FAILED,
            summary=message,
            errors=[notice],
        )
        return AgentOutcome(
            status=AgentStatus.FAILED,
            output_refs=(self._envelope_ref(request_id, code),),
            output=self._terminal_output(envelope),
            errors=(notice,),
            external_calls=(),
        )

    def _terminal_envelope(
        self,
        *,
        request_id: str,
        status: EvidenceStatus,
        summary: str,
        reason: str | None = None,
        warnings: list[ContractNotice] | None = None,
        errors: list[ContractNotice] | None = None,
        scope: Mapping[str, Any] | None = None,
    ) -> EvidenceEnvelope:
        return EvidenceEnvelope(
            schema_version="v12.1",
            request_id=request_id,
            source=EvidenceSource.DEVICE,
            evidence_kind="evidence",
            status=status,
            summary=summary,
            facts={
                "reuse_existing_execution": True,
                "netmiko_mcp_called": False,
                "command_generation_performed": False,
                "write_command_executed": False,
                "raw_output_forwarded": False,
            },
            scope=dict(scope or {}),
            warnings=list(warnings or []),
            errors=list(errors or []),
            collected_at=self._aware_now(),
            reason=reason,
        )

    @staticmethod
    def _terminal_output(envelope: EvidenceEnvelope) -> dict[str, Any]:
        return {
            "device_evidence": envelope.model_dump(mode="json"),
            "reuse_existing_execution": True,
            "netmiko_mcp_called": False,
            "command_generation_performed": False,
            "write_command_executed": False,
            "raw_output_forwarded": False,
            "safety_policy_bypassed": False,
        }

    def _envelope_ref(self, request_id: str, seed: str) -> str:
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
        return build_contract_ref(
            "artifact",
            request_id,
            "device_envelope",
            f"device-{digest}",
        )

    def _aware_now(self) -> datetime:
        value = self._utcnow()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("utcnow provider must return a timezone-aware datetime")
        return value
