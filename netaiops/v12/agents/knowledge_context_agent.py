"""Deterministic v12 Knowledge Context placeholder Agent.

Batch H freezes the v12 Knowledge Context contract. The Agent never reads a
knowledge base, never calls an LLM, and always returns not_available for a valid
frozen EvidencePlan.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Mapping

from pydantic import ValidationError

from ..contracts import ContextEnvelope, ContractNotice, EvidencePlan
from ..execution_context import AgentInvocation, AgentOutcome
from ..schema_validator import build_contract_ref
from ..status import AgentName, AgentStatus, EvidenceSource, EvidenceStatus


KNOWLEDGE_PLACEHOLDER_REASON = "local_knowledge_base_not_built"


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
        stage="knowledge_context",
        retryable=False,
        details=dict(details or {}),
    )


class KnowledgeContextAgent:
    """Return the frozen v12 Knowledge Context placeholder contract."""

    def __init__(self, *, utcnow: Any | None = None) -> None:
        self._utcnow = utcnow or (lambda: datetime.now(timezone.utc))

    async def run(self, invocation: AgentInvocation) -> AgentOutcome:
        if invocation.agent_name != AgentName.KNOWLEDGE_CONTEXT:
            return self._failed(
                "knowledge_agent_name_mismatch",
                "KnowledgeContextAgent can only run as knowledge_context",
            )

        planner_output = _mapping(
            invocation.prior_outputs.get(AgentName.STATIC_PLANNER.value)
        )
        raw_plan = planner_output.get("evidence_plan")
        if not isinstance(raw_plan, Mapping):
            return self._failed(
                "knowledge_context_plan_missing",
                "Static Planner output did not contain evidence_plan",
            )

        try:
            plan = EvidencePlan.model_validate(raw_plan)
        except ValidationError as exc:
            return self._failed(
                "knowledge_context_plan_invalid",
                "EvidencePlan failed contract validation",
                details={"issue_count": len(exc.errors())},
            )

        if plan.request_id != invocation.request_id:
            return self._failed(
                "knowledge_context_request_id_mismatch",
                "EvidencePlan request_id did not match invocation",
            )

        source_plan = next(
            (
                source
                for source in plan.sources
                if source.source == EvidenceSource.KNOWLEDGE
            ),
            None,
        )
        if source_plan is None:
            return self._failed(
                "knowledge_source_plan_missing",
                "EvidencePlan did not contain the fixed knowledge source",
            )

        constraints = dict(source_plan.constraints)
        drift = self._constraint_drift(
            required=source_plan.required,
            max_items=source_plan.max_items,
            constraints=constraints,
        )
        if drift:
            return self._failed(
                "knowledge_placeholder_contract_drift",
                "Knowledge placeholder constraints did not match the frozen v12 contract",
                details={"drift": drift},
            )

        notice = _notice(
            "local_knowledge_base_not_built",
            "Knowledge Context is intentionally unavailable in v12.",
            details={
                "reason": KNOWLEDGE_PLACEHOLDER_REASON,
                "activation_version": "v15",
            },
        )
        envelope = ContextEnvelope(
            schema_version="v12.1",
            request_id=invocation.request_id,
            source="knowledge",
            evidence_kind="context",
            status=EvidenceStatus.NOT_AVAILABLE,
            reason=KNOWLEDGE_PLACEHOLDER_REASON,
            context_facts=[],
            source_refs=[],
            as_of=None,
            collected_at=self._aware_now(),
        )
        envelope_ref = self._envelope_ref(invocation.request_id)

        return AgentOutcome(
            status=AgentStatus.NOT_AVAILABLE,
            output_refs=(envelope_ref,),
            output={
                "knowledge_context": envelope.model_dump(mode="json"),
                "placeholder": True,
                "local_knowledge_base_read": False,
                "glm_called": False,
                "network_called": False,
                "context_substituted_for_realtime_evidence": False,
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
        if constraints.get("reason") != KNOWLEDGE_PLACEHOLDER_REASON:
            drift.append("reason_mismatch")
        if constraints.get("evidence_kind") != "context":
            drift.append("evidence_kind_must_be_context")
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
    def _envelope_ref(request_id: str) -> str:
        identifier = "knowledge-placeholder-" + hashlib.sha256(
            KNOWLEDGE_PLACEHOLDER_REASON.encode("utf-8")
        ).hexdigest()[:16]
        return build_contract_ref(
            "context",
            request_id,
            "knowledge_context",
            identifier,
        )

    def _aware_now(self) -> datetime:
        value = self._utcnow()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("utcnow provider must return a timezone-aware datetime")
        return value
