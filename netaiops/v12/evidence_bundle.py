"""Build one deterministic EvidenceBundle from v12 Orchestrator outputs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from pydantic import ValidationError

from .contracts import (
    ContextEnvelope,
    EvidenceBundle,
    EvidenceCollection,
    EvidenceEnvelope,
    EvidencePlan,
    UnifiedAlertEvent,
)
from .execution_context import OrchestrationResult
from .schema_validator import parse_contract_ref
from .status import (
    AgentName,
    EvidenceBundleStatus,
    EvidenceSource,
    EvidenceStatus,
)


class EvidenceBundleBuildError(ValueError):
    """Raised when Orchestrator outputs cannot form a valid bundle."""


@dataclass(frozen=True, slots=True)
class BundleArtifacts:
    unified_event: UnifiedAlertEvent
    evidence_plan: EvidencePlan
    evidence_bundle: EvidenceBundle


class EvidenceBundleBuilder:
    """Convert completed evidence-agent outputs into frozen v12 contracts."""

    def __init__(self, *, utcnow: Any | None = None) -> None:
        self._utcnow = utcnow or (lambda: datetime.now(timezone.utc))

    def build(self, result: OrchestrationResult) -> BundleArtifacts:
        request_id = result.request_id
        outputs = result.outputs

        unified = self._model(
            UnifiedAlertEvent,
            self._nested(outputs, AgentName.TRIAGE, "unified_event"),
            "unified_event",
        )
        plan = self._model(
            EvidencePlan,
            self._nested(outputs, AgentName.STATIC_PLANNER, "evidence_plan"),
            "evidence_plan",
        )
        metrics = self._model(
            EvidenceEnvelope,
            self._nested(
                outputs,
                AgentName.METRICS_EVIDENCE,
                "metrics_evidence",
            ),
            "metrics_evidence",
        )
        device = self._model(
            EvidenceEnvelope,
            self._nested(
                outputs,
                AgentName.DEVICE_EVIDENCE,
                "device_evidence",
            ),
            "device_evidence",
        )
        logs = self._model(
            EvidenceEnvelope,
            self._nested(
                outputs,
                AgentName.LOGS_EVIDENCE,
                "logs_evidence",
            ),
            "logs_evidence",
        )
        knowledge = self._model(
            ContextEnvelope,
            self._nested(
                outputs,
                AgentName.KNOWLEDGE_CONTEXT,
                "knowledge_context",
            ),
            "knowledge_context",
        )

        request_ids = {
            request_id,
            unified.request_id,
            plan.request_id,
            metrics.request_id,
            device.request_id,
            logs.request_id,
            knowledge.request_id,
        }
        if request_ids != {request_id}:
            raise EvidenceBundleBuildError(
                "bundle input request_id values are inconsistent"
            )

        event_ref = self._agent_ref(
            result,
            AgentName.TRIAGE,
            "event",
        )
        plan_ref = self._agent_ref(
            result,
            AgentName.STATIC_PLANNER,
            "plan",
        )

        evidence = EvidenceCollection(
            metrics=metrics,
            device=device,
            logs=logs,
            knowledge=knowledge,
        )
        bundle = EvidenceBundle(
            schema_version="v12.1",
            request_id=request_id,
            event_ref=event_ref,
            plan_ref=plan_ref,
            evidence=evidence,
            bundle_status=self._bundle_status(plan, evidence),
            built_at=self._aware_now(),
        )
        return BundleArtifacts(
            unified_event=unified,
            evidence_plan=plan,
            evidence_bundle=bundle,
        )

    @staticmethod
    def _nested(
        outputs: Mapping[str, Mapping[str, Any]],
        agent_name: AgentName,
        key: str,
    ) -> Mapping[str, Any]:
        agent_output = outputs.get(agent_name.value)
        if not isinstance(agent_output, Mapping):
            raise EvidenceBundleBuildError(
                f"missing Agent output: {agent_name.value}"
            )
        value = agent_output.get(key)
        if not isinstance(value, Mapping):
            raise EvidenceBundleBuildError(
                f"missing output contract: {key}"
            )
        return value

    @staticmethod
    def _model(model_type: Any, payload: Mapping[str, Any], label: str) -> Any:
        try:
            return model_type.model_validate(payload)
        except ValidationError as exc:
            raise EvidenceBundleBuildError(
                f"{label} failed contract validation"
            ) from exc

    @staticmethod
    def _agent_ref(
        result: OrchestrationResult,
        agent_name: AgentName,
        scheme: str,
    ) -> str:
        matches: list[str] = []
        for run in result.agent_runs:
            if run.agent_name != agent_name:
                continue
            for reference in run.outputs_ref:
                parsed = parse_contract_ref(reference)
                if parsed["request_id"] != result.request_id:
                    raise EvidenceBundleBuildError(
                        "Agent output reference request_id mismatch"
                    )
                if parsed["scheme"] == scheme:
                    matches.append(reference)
        if len(matches) != 1:
            raise EvidenceBundleBuildError(
                f"expected one {scheme} reference from {agent_name.value}"
            )
        return matches[0]

    @staticmethod
    def _bundle_status(
        plan: EvidencePlan,
        evidence: EvidenceCollection,
    ) -> EvidenceBundleStatus:
        required = {
            source.source: source.required
            for source in plan.sources
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
            if required.get(source, False) and envelope.status in unavailable:
                return EvidenceBundleStatus.INSUFFICIENT
        if any(
            envelope.status != EvidenceStatus.SUCCESS
            for envelope in envelopes.values()
        ):
            return EvidenceBundleStatus.PARTIAL
        return EvidenceBundleStatus.COMPLETE

    def _aware_now(self) -> datetime:
        value = self._utcnow()
        if value.tzinfo is None or value.utcoffset() is None:
            raise EvidenceBundleBuildError(
                "utcnow provider must return a timezone-aware datetime"
            )
        return value
