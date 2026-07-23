"""Deterministic v12 Evidence Judge Agent."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Mapping

from pydantic import ValidationError

from ..contracts import (
    ContextEnvelope,
    ContractNotice,
    EvidenceBundle,
    EvidenceCollection,
    EvidenceEnvelope,
    EvidencePlan,
)
from ..execution_context import AgentInvocation, AgentOutcome
from ..judge_rules import (
    RULES_VERSION,
    evaluate_evidence,
    judge_missing_references,
)
from ..schema_validator import build_contract_ref, parse_contract_ref
from ..status import (
    AgentName,
    AgentStatus,
    EvidenceBundleStatus,
    EvidenceSource,
    EvidenceStatus,
    JudgeStatus,
)


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
        stage="evidence_judge",
        retryable=False,
        details=dict(details or {}),
    )


class EvidenceJudgeAgent:
    """Judge evidence quality without Tool, MCP, LLM, or follow-up queries."""

    async def run(self, invocation: AgentInvocation) -> AgentOutcome:
        if invocation.agent_name != AgentName.EVIDENCE_JUDGE:
            return self._failed(
                "judge_agent_name_mismatch",
                "EvidenceJudgeAgent can only run as evidence_judge",
            )

        raw_plan = _mapping(
            invocation.prior_outputs.get(
                AgentName.STATIC_PLANNER.value
            )
        ).get("evidence_plan")
        if not isinstance(raw_plan, Mapping):
            return self._failed(
                "judge_evidence_plan_missing",
                "Static Planner output did not contain evidence_plan",
            )

        try:
            plan = EvidencePlan.model_validate(raw_plan)
        except ValidationError as exc:
            return self._failed(
                "judge_evidence_plan_invalid",
                "EvidencePlan failed contract validation",
                details={"issue_count": len(exc.errors())},
            )

        if plan.request_id != invocation.request_id:
            return self._failed(
                "judge_plan_request_id_mismatch",
                "EvidencePlan request_id did not match invocation",
            )

        try:
            raw_bundle, bundle_source = self._raw_bundle(
                invocation,
                plan,
            )
        except (ValueError, ValidationError) as exc:
            return self._failed(
                "judge_bundle_derivation_failed",
                "EvidenceBundle could not be derived from prior outputs",
                details={"exception_type": type(exc).__name__},
            )

        missing_ref_result = judge_missing_references(
            plan,
            raw_bundle,
        )
        if missing_ref_result is not None:
            return self._success_outcome(
                missing_ref_result,
                bundle_source=bundle_source,
            )

        try:
            bundle = EvidenceBundle.model_validate(raw_bundle)
        except ValidationError as exc:
            return self._failed(
                "judge_evidence_bundle_invalid",
                "EvidenceBundle failed contract validation",
                details={"issue_count": len(exc.errors())},
            )

        if bundle.request_id != invocation.request_id:
            return self._failed(
                "judge_bundle_request_id_mismatch",
                "EvidenceBundle request_id did not match invocation",
            )

        try:
            judge_result = evaluate_evidence(plan, bundle)
        except ValueError as exc:
            return self._failed(
                "judge_rule_evaluation_failed",
                "Deterministic judge rules rejected the bundle",
                details={"exception_type": type(exc).__name__},
            )

        return self._success_outcome(
            judge_result,
            bundle_source=bundle_source,
        )

    def _raw_bundle(
        self,
        invocation: AgentInvocation,
        plan: EvidencePlan,
    ) -> tuple[Mapping[str, Any], str]:
        direct = invocation.prior_outputs.get("evidence_bundle")
        if isinstance(direct, Mapping):
            candidate = direct.get("evidence_bundle")
            if isinstance(candidate, Mapping):
                return candidate, "prior_evidence_bundle"

        metrics = self._contract_payload(
            invocation,
            AgentName.METRICS_EVIDENCE,
            "metrics_evidence",
        )
        device = self._contract_payload(
            invocation,
            AgentName.DEVICE_EVIDENCE,
            "device_evidence",
        )
        logs = self._contract_payload(
            invocation,
            AgentName.LOGS_EVIDENCE,
            "logs_evidence",
        )
        knowledge = self._contract_payload(
            invocation,
            AgentName.KNOWLEDGE_CONTEXT,
            "knowledge_context",
        )

        metrics_model = EvidenceEnvelope.model_validate(metrics)
        device_model = EvidenceEnvelope.model_validate(device)
        logs_model = EvidenceEnvelope.model_validate(logs)
        knowledge_model = ContextEnvelope.model_validate(knowledge)

        event_ref = self._unique_ref(
            invocation.prior_output_refs,
            "event",
        )
        plan_ref = self._unique_ref(
            invocation.prior_output_refs,
            "plan",
        )
        evidence = EvidenceCollection(
            metrics=metrics_model,
            device=device_model,
            logs=logs_model,
            knowledge=knowledge_model,
        )
        built_at = max(
            metrics_model.collected_at,
            device_model.collected_at,
            logs_model.collected_at,
            knowledge_model.collected_at,
        )
        bundle = EvidenceBundle(
            schema_version="v12.1",
            request_id=invocation.request_id,
            event_ref=event_ref,
            plan_ref=plan_ref,
            evidence=evidence,
            bundle_status=self._bundle_status(plan, evidence),
            built_at=built_at,
        )
        return (
            bundle.model_dump(mode="json"),
            "derived_from_agent_outputs",
        )

    @staticmethod
    def _contract_payload(
        invocation: AgentInvocation,
        agent_name: AgentName,
        key: str,
    ) -> Mapping[str, Any]:
        output = invocation.prior_outputs.get(agent_name.value)
        if not isinstance(output, Mapping):
            raise ValueError(f"missing Agent output: {agent_name.value}")
        value = output.get(key)
        if not isinstance(value, Mapping):
            raise ValueError(f"missing output contract: {key}")
        return value

    @staticmethod
    def _unique_ref(
        references: tuple[str, ...],
        scheme: str,
    ) -> str:
        matches: list[str] = []
        for reference in references:
            parsed = parse_contract_ref(reference)
            if parsed["scheme"] == scheme:
                matches.append(reference)
        if len(matches) != 1:
            raise ValueError(
                f"expected exactly one {scheme} reference"
            )
        return matches[0]

    @staticmethod
    def _bundle_status(
        plan: EvidencePlan,
        evidence: EvidenceCollection,
    ) -> EvidenceBundleStatus:
        required = {
            item.source: item.required for item in plan.sources
        }
        envelopes = {
            EvidenceSource.METRICS: evidence.metrics,
            EvidenceSource.DEVICE: evidence.device,
            EvidenceSource.LOGS: evidence.logs,
            EvidenceSource.KNOWLEDGE: evidence.knowledge,
        }
        unavailable = {
            EvidenceStatus.FAILED,
            EvidenceStatus.SKIPPED,
            EvidenceStatus.NOT_AVAILABLE,
        }
        for source, envelope in envelopes.items():
            if (
                required.get(source, False)
                and envelope.status in unavailable
            ):
                return EvidenceBundleStatus.INSUFFICIENT
        if any(
            envelope.status != EvidenceStatus.SUCCESS
            for envelope in envelopes.values()
        ):
            return EvidenceBundleStatus.PARTIAL
        return EvidenceBundleStatus.COMPLETE

    def _success_outcome(
        self,
        judge_result: Any,
        *,
        bundle_source: str,
    ) -> AgentOutcome:
        output_ref = self._output_ref(
            judge_result.request_id,
            judge_result.status,
        )
        agent_status = (
            AgentStatus.SUCCESS
            if judge_result.status == JudgeStatus.READY
            else AgentStatus.PARTIAL
        )
        return AgentOutcome(
            status=agent_status,
            output_refs=(output_ref,),
            output={
                "judge_result": judge_result.model_dump(mode="json"),
                "rules_version": RULES_VERSION,
                "bundle_source": bundle_source,
                "llm_called": False,
                "mcp_called": False,
                "tool_called": False,
                "automatic_followup_queries": False,
            },
            external_calls=(),
        )

    @staticmethod
    def _output_ref(
        request_id: str,
        status: JudgeStatus,
    ) -> str:
        seed = f"{RULES_VERSION}:{status.value}"
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
        return build_contract_ref(
            "artifact",
            request_id,
            "judge_result",
            f"judge-{digest}",
        )

    @staticmethod
    def _failed(
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
