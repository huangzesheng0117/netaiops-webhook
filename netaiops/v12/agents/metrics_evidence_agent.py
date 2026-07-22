"""Deterministic v12 Metrics Evidence Agent.

Batch F only reuses the current request's existing Prometheus evidence artifact.
It never calls Prometheus MCP and never generates PromQL.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Mapping

from pydantic import ValidationError

from ..adapters.prometheus_evidence_adapter import (
    PrometheusEvidenceAdapter,
    PrometheusEvidenceAdapterError,
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
        stage="metrics_evidence",
        retryable=False,
        details=dict(details or {}),
    )


class MetricsEvidenceAgent:
    """Wrap existing Prometheus evidence without issuing another query."""

    def __init__(
        self,
        *,
        adapter: PrometheusEvidenceAdapter | None = None,
        utcnow: Any | None = None,
    ) -> None:
        self.adapter = adapter or PrometheusEvidenceAdapter()
        self._utcnow = utcnow or (lambda: datetime.now(timezone.utc))

    async def run(self, invocation: AgentInvocation) -> AgentOutcome:
        if invocation.agent_name != AgentName.METRICS_EVIDENCE:
            return self._failed(
                invocation.request_id,
                "metrics_agent_name_mismatch",
                "MetricsEvidenceAgent can only run as metrics_evidence",
            )

        planner_output = _mapping(
            invocation.prior_outputs.get(AgentName.STATIC_PLANNER.value)
        )
        raw_plan = planner_output.get("evidence_plan")
        if not isinstance(raw_plan, Mapping):
            return self._failed(
                invocation.request_id,
                "metrics_evidence_plan_missing",
                "Static Planner output did not contain evidence_plan",
            )

        try:
            plan = EvidencePlan.model_validate(raw_plan)
        except ValidationError as exc:
            return self._failed(
                invocation.request_id,
                "metrics_evidence_plan_invalid",
                "EvidencePlan failed contract validation",
                details={"issue_count": len(exc.errors())},
            )
        if plan.request_id != invocation.request_id:
            return self._failed(
                invocation.request_id,
                "metrics_evidence_request_id_mismatch",
                "EvidencePlan request_id did not match invocation",
            )

        metrics_source = next(
            (
                source
                for source in plan.sources
                if source.source == EvidenceSource.METRICS
            ),
            None,
        )
        if metrics_source is None:
            return self._failed(
                invocation.request_id,
                "metrics_source_plan_missing",
                "EvidencePlan did not contain the fixed metrics source",
            )

        constraints = dict(metrics_source.constraints)
        if constraints.get("reuse_existing_evidence") is not True:
            return self._failed(
                invocation.request_id,
                "metrics_reuse_policy_rejected",
                "Batch F requires reuse_existing_evidence=true",
            )
        if constraints.get("promql_generation_allowed") is not False:
            return self._failed(
                invocation.request_id,
                "metrics_promql_policy_rejected",
                "Batch F requires promql_generation_allowed=false",
            )

        try:
            normalized = self.adapter.load_existing(invocation.request_id)
        except PrometheusEvidenceAdapterError as exc:
            return self._failed(
                invocation.request_id,
                "metrics_existing_artifact_invalid",
                "Existing Prometheus evidence could not be normalized",
                details={"exception_type": type(exc).__name__},
            )

        if normalized is None:
            reason = (
                "existing_prometheus_evidence_not_found"
                if metrics_source.required
                else "metrics_optional_existing_evidence_not_found"
            )
            return self._not_available(
                invocation.request_id,
                reason,
                required=metrics_source.required,
            )

        envelope = EvidenceEnvelope(
            schema_version="v12.1",
            request_id=invocation.request_id,
            source=EvidenceSource.METRICS,
            evidence_kind="evidence",
            status=normalized.status,
            summary=normalized.summary,
            facts=dict(normalized.facts),
            scope=dict(normalized.scope),
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
            EvidenceStatus.NOT_AVAILABLE: AgentStatus.NOT_AVAILABLE,
            EvidenceStatus.SKIPPED: AgentStatus.SKIPPED,
        }[envelope.status]

        return AgentOutcome(
            status=agent_status,
            output_refs=(envelope_ref, *normalized.evidence_refs),
            output={
                "metrics_evidence": envelope.model_dump(mode="json"),
                "source_artifact_ref": normalized.source_artifact_ref,
                "reuse_existing_evidence": True,
                "prometheus_mcp_called": False,
                "promql_generation_performed": False,
                "query_logic_changed": False,
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
        now = self._aware_now()
        notice = _notice(
            "metrics_existing_evidence_not_available",
            "No existing Prometheus evidence artifact was available",
            details={"required": required, "reason": reason},
        )
        envelope = EvidenceEnvelope(
            schema_version="v12.1",
            request_id=request_id,
            source=EvidenceSource.METRICS,
            evidence_kind="evidence",
            status=EvidenceStatus.NOT_AVAILABLE,
            summary="Existing Prometheus evidence was not available.",
            facts={
                "reuse_existing_evidence": True,
                "prometheus_mcp_called": False,
                "promql_generation_performed": False,
            },
            scope={"required": required},
            warnings=[notice],
            collected_at=now,
            reason=reason,
        )
        envelope_ref = self._envelope_ref(request_id, reason)
        return AgentOutcome(
            status=AgentStatus.NOT_AVAILABLE,
            output_refs=(envelope_ref,),
            output={
                "metrics_evidence": envelope.model_dump(mode="json"),
                "reuse_existing_evidence": True,
                "prometheus_mcp_called": False,
                "promql_generation_performed": False,
                "query_logic_changed": False,
            },
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
        now = self._aware_now()
        notice = _notice(code, message, details=details)
        envelope = EvidenceEnvelope(
            schema_version="v12.1",
            request_id=request_id,
            source=EvidenceSource.METRICS,
            evidence_kind="evidence",
            status=EvidenceStatus.FAILED,
            summary=message,
            facts={
                "reuse_existing_evidence": True,
                "prometheus_mcp_called": False,
                "promql_generation_performed": False,
            },
            scope={},
            errors=[notice],
            collected_at=now,
        )
        envelope_ref = self._envelope_ref(request_id, code)
        return AgentOutcome(
            status=AgentStatus.FAILED,
            output_refs=(envelope_ref,),
            output={
                "metrics_evidence": envelope.model_dump(mode="json"),
                "reuse_existing_evidence": True,
                "prometheus_mcp_called": False,
                "promql_generation_performed": False,
                "query_logic_changed": False,
            },
            errors=(notice,),
            external_calls=(),
        )

    def _envelope_ref(self, request_id: str, seed: str) -> str:
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
        return build_contract_ref(
            "artifact",
            request_id,
            "metrics_envelope",
            f"metrics-{digest}",
        )

    def _aware_now(self) -> datetime:
        value = self._utcnow()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("utcnow provider must return a timezone-aware datetime")
        return value
