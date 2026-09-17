"""Deterministic v12 Logs Evidence placeholder Agent.

Batch H freezes the v12 Logs Evidence contract. The Agent never connects to
FastMCP, OPS ES API, or Elasticsearch and always returns not_available for a
valid frozen EvidencePlan.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Mapping

from pydantic import ValidationError

from ..contracts import ContractNotice, EvidenceEnvelope, EvidencePlan
from ..execution_context import AgentInvocation, AgentOutcome
from ..schema_validator import build_contract_ref
from ..status import AgentName, AgentStatus, EvidenceSource, EvidenceStatus


LOGS_PLACEHOLDER_REASON = "logs_evidence_not_approved"


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
        stage="logs_evidence",
        retryable=False,
        details=dict(details or {}),
    )


class LogsEvidenceAgent:
    """Return the frozen v12 Logs Evidence placeholder contract."""

    def __init__(self, *, utcnow: Any | None = None) -> None:
        self._utcnow = utcnow or (lambda: datetime.now(timezone.utc))

    async def run(self, invocation: AgentInvocation) -> AgentOutcome:
        if invocation.agent_name != AgentName.LOGS_EVIDENCE:
            return self._failed(
                "logs_agent_name_mismatch",
                "LogsEvidenceAgent can only run as logs_evidence",
            )

        planner_output = _mapping(
            invocation.prior_outputs.get(AgentName.STATIC_PLANNER.value)
        )
        raw_plan = planner_output.get("evidence_plan")
        if not isinstance(raw_plan, Mapping):
            return self._failed(
                "logs_evidence_plan_missing",
                "Static Planner output did not contain evidence_plan",
            )

        try:
            plan = EvidencePlan.model_validate(raw_plan)
        except ValidationError as exc:
            return self._failed(
                "logs_evidence_plan_invalid",
                "EvidencePlan failed contract validation",
                details={"issue_count": len(exc.errors())},
            )

        if plan.request_id != invocation.request_id:
            return self._failed(
                "logs_evidence_request_id_mismatch",
                "EvidencePlan request_id did not match invocation",
            )

        source_plan = next(
            (
                source
                for source in plan.sources
                if source.source == EvidenceSource.LOGS
            ),
            None,
        )
        if source_plan is None:
            return self._failed(
                "logs_source_plan_missing",
                "EvidencePlan did not contain the fixed logs source",
            )

        # W1/R1 may expose a persisted v14 Logs artifact, but only after the
        # frozen EvidencePlan has already been validated for this request and
        # contains the Logs source.  A malformed/missing plan must never be
        # bypassed merely because an artifact happens to exist on disk.
        try:
            from netaiops.v14.logs_evidence_adapter import build_v12_logs_envelope
            from netaiops.v14.runtime_config import load_runtime_settings
            settings = load_runtime_settings()
            active_envelope = build_v12_logs_envelope(
                request_id=invocation.request_id,
                project_root="/opt/netaiops-webhook",
                settings=settings,
            )
        except Exception as exc:
            return self._failed(
                "v14_logs_adapter_failed",
                "v14 persisted Logs Evidence could not be loaded safely",
                details={"exception_type": type(exc).__name__},
            )
        if active_envelope is not None:
            agent_status = AgentStatus.SUCCESS
            if active_envelope.status in {
                EvidenceStatus.PARTIAL,
                EvidenceStatus.NO_DATA,
                EvidenceStatus.FAILED,
            }:
                # The Agent successfully produced/reused a deterministic Logs
                # contract even when the evidence itself is weak/failed.
                # Keep the optional evidence failure for Judge semantics
                # rather than aborting the whole Orchestrator as an Agent bug.
                agent_status = AgentStatus.PARTIAL
            elif active_envelope.status == EvidenceStatus.NOT_AVAILABLE:
                agent_status = AgentStatus.NOT_AVAILABLE
            envelope_ref = self._active_envelope_ref(
                invocation.request_id,
                active_envelope.evidence_refs,
            )
            return AgentOutcome(
                status=agent_status,
                output_refs=(envelope_ref,),
                output={
                    "logs_evidence": active_envelope.model_dump(mode="json"),
                    "placeholder": False,
                    "reused_v14_persisted_artifact": True,
                    "fastmcp_called": False,
                    "ops_es_api_called": False,
                    "elasticsearch_called": False,
                    "dsl_generation_performed": False,
                    "no_data_interpreted_as_normal": False,
                },
                warnings=tuple(active_envelope.warnings),
                external_calls=(),
            )

        constraints = dict(source_plan.constraints)
        drift = self._constraint_drift(
            required=source_plan.required,
            max_items=source_plan.max_items,
            constraints=constraints,
        )
        if drift:
            return self._failed(
                "logs_placeholder_contract_drift",
                "Logs placeholder constraints did not match the frozen v12 contract",
                details={"drift": drift},
            )

        notice = _notice(
            "logs_evidence_not_approved",
            "Logs Evidence is intentionally unavailable in v12.",
            details={
                "reason": LOGS_PLACEHOLDER_REASON,
                "activation_version": "v14",
            },
        )
        envelope = EvidenceEnvelope(
            schema_version="v12.1",
            request_id=invocation.request_id,
            source=EvidenceSource.LOGS,
            evidence_kind="evidence",
            status=EvidenceStatus.NOT_AVAILABLE,
            summary="Logs Evidence is not approved for v12 execution.",
            facts={
                "placeholder": True,
                "enabled": False,
                "fastmcp_called": False,
                "ops_es_api_called": False,
                "elasticsearch_called": False,
                "dsl_generation_performed": False,
                "no_data_interpreted_as_normal": False,
            },
            scope={
                "required": False,
                "max_items": 0,
                "capability_ids": list(source_plan.capability_ids),
            },
            warnings=[notice],
            evidence_refs=[],
            collected_at=self._aware_now(),
            reason=LOGS_PLACEHOLDER_REASON,
        )
        envelope_ref = self._envelope_ref(invocation.request_id)

        return AgentOutcome(
            status=AgentStatus.NOT_AVAILABLE,
            output_refs=(envelope_ref,),
            output={
                "logs_evidence": envelope.model_dump(mode="json"),
                "placeholder": True,
                "fastmcp_called": False,
                "ops_es_api_called": False,
                "elasticsearch_called": False,
                "dsl_generation_performed": False,
                "no_data_interpreted_as_normal": False,
            },
            warnings=(notice,),
            external_calls=(),
        )

    @staticmethod
    def _constraint_drift(
        *,
        required: bool,
        max_items: int,
        constraints: Mapping[str, Any],
    ) -> list[str]:
        drift: list[str] = []
        if required:
            drift.append("required_must_be_false")
        if max_items != 0:
            drift.append("max_items_must_be_zero")
        if constraints.get("enabled") is not False:
            drift.append("enabled_must_be_false")
        if constraints.get("reason") != LOGS_PLACEHOLDER_REASON:
            drift.append("reason_mismatch")
        if constraints.get("dsl_generation_allowed") is not False:
            drift.append("dsl_generation_allowed_must_be_false")
        return drift

    def _failed(
        self,
        code: str,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> AgentOutcome:
        notice = _notice(code, message, details=details)
        return AgentOutcome(
            status=AgentStatus.FAILED,
            errors=(notice,),
            external_calls=(),
        )

    @staticmethod
    def _active_envelope_ref(request_id: str, evidence_refs: list[str]) -> str:
        seed = "|".join(sorted(evidence_refs)) or "v14-logs-persisted"
        identifier = "logs-v14-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
        return build_contract_ref(
            "artifact", request_id, "logs_envelope", identifier
        )

    @staticmethod
    def _envelope_ref(request_id: str) -> str:
        identifier = "logs-placeholder-" + hashlib.sha256(
            LOGS_PLACEHOLDER_REASON.encode("utf-8")
        ).hexdigest()[:16]
        return build_contract_ref(
            "artifact",
            request_id,
            "logs_envelope",
            identifier,
        )

    def _aware_now(self) -> datetime:
        value = self._utcnow()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("utcnow provider must return a timezone-aware datetime")
        return value
