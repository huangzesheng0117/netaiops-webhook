from __future__ import annotations

import copy
import json
import unittest
from datetime import datetime, timezone
from types import MappingProxyType

from netaiops.v12.contracts import (
    AgentRunRecord,
    AlertObject,
    ContextEnvelope,
    DeviceIdentity,
    EvidenceEnvelope,
    EvidencePlan,
    EvidenceSourcePlan,
    UnifiedAlertEvent,
)
from netaiops.v12.evidence_bundle import (
    EvidenceBundleBuildError,
    EvidenceBundleBuilder,
)
from netaiops.v12.execution_context import OrchestrationResult
from netaiops.v12.schema_validator import stable_json_dumps
from netaiops.v12.state_machine import OrchestrationState
from netaiops.v12.status import (
    AgentName,
    AgentStatus,
    AlertLifecycleStatus,
    AlertSource,
    EvidenceBundleStatus,
    EvidenceSource,
    EvidenceStatus,
)


REQUEST_ID = "req-batch-i-001"
NOW = datetime(2026, 7, 23, 1, 0, tzinfo=timezone.utc)


def event_payload(request_id: str = REQUEST_ID) -> dict:
    return UnifiedAlertEvent(
        schema_version="v12.1",
        request_id=request_id,
        event_id="evt-batch-i",
        source=AlertSource.ALERTMANAGER,
        alert_status=AlertLifecycleStatus.FIRING,
        alert_name="InterfaceDown",
        occurred_at=NOW,
        received_at=NOW,
        device=DeviceIdentity(name="SW01", ip="10.0.0.1"),
        alert_object=AlertObject(kind="interface", name="Ethernet1/1"),
        labels={"severity": "critical"},
        annotations={"summary": "interface down"},
        family="interface_status_or_flap",
        event_key="event:test",
    ).model_dump(mode="json")


def plan_payload(
    request_id: str = REQUEST_ID,
    *,
    metrics_required: bool = True,
    device_required: bool = True,
) -> dict:
    return EvidencePlan(
        schema_version="v12.1",
        request_id=request_id,
        plan_ref=f"plan://{request_id}/evidence_plan/plan-i",
        planner_mode="deterministic",
        family="interface_status_or_flap",
        selected_playbook="cisco_interface_status",
        sources=[
            EvidenceSourcePlan(
                source=EvidenceSource.METRICS,
                required=metrics_required,
                constraints={"reuse_existing_evidence": True},
            ),
            EvidenceSourcePlan(
                source=EvidenceSource.DEVICE,
                required=device_required,
                constraints={"readonly_only": True},
            ),
            EvidenceSourcePlan(
                source=EvidenceSource.LOGS,
                required=False,
                constraints={"enabled": False},
                max_items=0,
            ),
            EvidenceSourcePlan(
                source=EvidenceSource.KNOWLEDGE,
                required=False,
                constraints={"enabled": False, "evidence_kind": "context"},
                max_items=0,
            ),
        ],
        readonly_only=True,
        created_at=NOW,
    ).model_dump(mode="json")


def evidence_payload(
    source: EvidenceSource,
    status: EvidenceStatus,
    *,
    request_id: str = REQUEST_ID,
    required: bool = False,
) -> dict:
    references = []
    reason = None
    if status in {EvidenceStatus.SUCCESS, EvidenceStatus.PARTIAL}:
        references = [
            f"evidence://{request_id}/{source.value}/{source.value}-1"
        ]
    if status == EvidenceStatus.NOT_AVAILABLE:
        reason = f"{source.value}_not_available"
    return EvidenceEnvelope(
        schema_version="v12.1",
        request_id=request_id,
        source=source,
        evidence_kind="evidence",
        status=status,
        summary=f"{source.value} evidence",
        facts={"value": 1},
        scope={"required": required},
        evidence_refs=references,
        collected_at=NOW,
        reason=reason,
    ).model_dump(mode="json")


def knowledge_payload(
    status: EvidenceStatus = EvidenceStatus.NOT_AVAILABLE,
    *,
    request_id: str = REQUEST_ID,
) -> dict:
    source_refs = []
    as_of = None
    if status == EvidenceStatus.SUCCESS:
        source_refs = [
            f"context://{request_id}/knowledge_source/source-1"
        ]
        as_of = NOW
    return ContextEnvelope(
        schema_version="v12.1",
        request_id=request_id,
        source="knowledge",
        evidence_kind="context",
        status=status,
        reason=(
            "local_knowledge_base_not_built"
            if status == EvidenceStatus.NOT_AVAILABLE
            else None
        ),
        context_facts=[],
        source_refs=source_refs,
        as_of=as_of,
        collected_at=NOW,
    ).model_dump(mode="json")


def run_record(
    agent: AgentName,
    status: AgentStatus,
    refs: list[str] | None = None,
    *,
    request_id: str = REQUEST_ID,
) -> AgentRunRecord:
    return AgentRunRecord(
        schema_version="v12.1",
        request_id=request_id,
        agent_name=agent,
        status=status,
        started_at=NOW,
        finished_at=NOW,
        duration_ms=1,
        outputs_ref=refs or [],
    )


def result_fixture(
    *,
    metrics_status: EvidenceStatus = EvidenceStatus.SUCCESS,
    device_status: EvidenceStatus = EvidenceStatus.SUCCESS,
    logs_status: EvidenceStatus = EvidenceStatus.NOT_AVAILABLE,
    knowledge_status: EvidenceStatus = EvidenceStatus.NOT_AVAILABLE,
    metrics_required: bool = True,
    device_required: bool = True,
) -> OrchestrationResult:
    outputs = {
        AgentName.TRIAGE.value: {
            "unified_event": event_payload(),
        },
        AgentName.STATIC_PLANNER.value: {
            "evidence_plan": plan_payload(
                metrics_required=metrics_required,
                device_required=device_required,
            ),
        },
        AgentName.METRICS_EVIDENCE.value: {
            "metrics_evidence": evidence_payload(
                EvidenceSource.METRICS,
                metrics_status,
                required=metrics_required,
            )
        },
        AgentName.DEVICE_EVIDENCE.value: {
            "device_evidence": evidence_payload(
                EvidenceSource.DEVICE,
                device_status,
                required=device_required,
            )
        },
        AgentName.LOGS_EVIDENCE.value: {
            "logs_evidence": evidence_payload(
                EvidenceSource.LOGS,
                logs_status,
            )
        },
        AgentName.KNOWLEDGE_CONTEXT.value: {
            "knowledge_context": knowledge_payload(
                knowledge_status,
            )
        },
    }
    runs = (
        run_record(
            AgentName.TRIAGE,
            AgentStatus.SUCCESS,
            [f"event://{REQUEST_ID}/unified_alert/evt-batch-i"],
        ),
        run_record(
            AgentName.STATIC_PLANNER,
            AgentStatus.SUCCESS,
            [f"plan://{REQUEST_ID}/evidence_plan/plan-i"],
        ),
        run_record(AgentName.METRICS_EVIDENCE, AgentStatus.SUCCESS),
        run_record(AgentName.DEVICE_EVIDENCE, AgentStatus.SUCCESS),
        run_record(AgentName.LOGS_EVIDENCE, AgentStatus.NOT_AVAILABLE),
        run_record(AgentName.KNOWLEDGE_CONTEXT, AgentStatus.NOT_AVAILABLE),
    )
    return OrchestrationResult(
        request_id=REQUEST_ID,
        final_state=OrchestrationState.EVIDENCE_COLLECTION,
        state_history=(
            OrchestrationState.INITIALIZED,
            OrchestrationState.TRIAGE,
            OrchestrationState.PLANNING,
            OrchestrationState.EVIDENCE_COLLECTION,
        ),
        agent_runs=runs,
        outputs=MappingProxyType(
            {
                key: MappingProxyType(value)
                for key, value in outputs.items()
            }
        ),
        fallback_to_legacy=False,
        stop_reason=None,
        elapsed_ms=10,
    )


class EvidenceBundleTests(unittest.TestCase):
    def builder(self) -> EvidenceBundleBuilder:
        return EvidenceBundleBuilder(utcnow=lambda: NOW)

    def test_valid_bundle_builds(self) -> None:
        artifacts = self.builder().build(result_fixture())
        self.assertEqual(artifacts.evidence_bundle.request_id, REQUEST_ID)

    def test_event_and_plan_are_retained(self) -> None:
        artifacts = self.builder().build(result_fixture())
        self.assertEqual(artifacts.unified_event.event_id, "evt-batch-i")
        self.assertEqual(
            artifacts.evidence_plan.plan_ref,
            f"plan://{REQUEST_ID}/evidence_plan/plan-i",
        )

    def test_optional_placeholders_make_bundle_partial(self) -> None:
        bundle = self.builder().build(result_fixture()).evidence_bundle
        self.assertEqual(bundle.bundle_status, EvidenceBundleStatus.PARTIAL)

    def test_all_sources_success_make_bundle_complete(self) -> None:
        bundle = self.builder().build(
            result_fixture(
                logs_status=EvidenceStatus.SUCCESS,
                knowledge_status=EvidenceStatus.SUCCESS,
            )
        ).evidence_bundle
        self.assertEqual(bundle.bundle_status, EvidenceBundleStatus.COMPLETE)

    def test_required_metrics_failure_is_insufficient(self) -> None:
        bundle = self.builder().build(
            result_fixture(metrics_status=EvidenceStatus.FAILED)
        ).evidence_bundle
        self.assertEqual(
            bundle.bundle_status,
            EvidenceBundleStatus.INSUFFICIENT,
        )

    def test_optional_metrics_failure_is_partial(self) -> None:
        bundle = self.builder().build(
            result_fixture(
                metrics_status=EvidenceStatus.FAILED,
                metrics_required=False,
            )
        ).evidence_bundle
        self.assertEqual(bundle.bundle_status, EvidenceBundleStatus.PARTIAL)

    def test_required_device_not_available_is_insufficient(self) -> None:
        bundle = self.builder().build(
            result_fixture(
                device_status=EvidenceStatus.NOT_AVAILABLE,
            )
        ).evidence_bundle
        self.assertEqual(
            bundle.bundle_status,
            EvidenceBundleStatus.INSUFFICIENT,
        )

    def test_missing_triage_output_fails(self) -> None:
        result = result_fixture()
        outputs = dict(result.outputs)
        outputs.pop(AgentName.TRIAGE.value)
        broken = OrchestrationResult(
            request_id=result.request_id,
            final_state=result.final_state,
            state_history=result.state_history,
            agent_runs=result.agent_runs,
            outputs=outputs,
            fallback_to_legacy=result.fallback_to_legacy,
            stop_reason=result.stop_reason,
            elapsed_ms=result.elapsed_ms,
        )
        with self.assertRaises(EvidenceBundleBuildError):
            self.builder().build(broken)

    def test_missing_metrics_contract_fails(self) -> None:
        result = result_fixture()
        outputs = {key: dict(value) for key, value in result.outputs.items()}
        outputs[AgentName.METRICS_EVIDENCE.value] = {}
        broken = OrchestrationResult(
            request_id=result.request_id,
            final_state=result.final_state,
            state_history=result.state_history,
            agent_runs=result.agent_runs,
            outputs=outputs,
            fallback_to_legacy=False,
            stop_reason=None,
            elapsed_ms=10,
        )
        with self.assertRaises(EvidenceBundleBuildError):
            self.builder().build(broken)

    def test_request_id_mismatch_fails(self) -> None:
        result = result_fixture()
        outputs = {key: copy.deepcopy(dict(value)) for key, value in result.outputs.items()}
        outputs[AgentName.DEVICE_EVIDENCE.value]["device_evidence"] = evidence_payload(
            EvidenceSource.DEVICE,
            EvidenceStatus.SUCCESS,
            request_id="req-other",
        )
        broken = OrchestrationResult(
            request_id=result.request_id,
            final_state=result.final_state,
            state_history=result.state_history,
            agent_runs=result.agent_runs,
            outputs=outputs,
            fallback_to_legacy=False,
            stop_reason=None,
            elapsed_ms=10,
        )
        with self.assertRaises(EvidenceBundleBuildError):
            self.builder().build(broken)

    def test_missing_event_ref_fails(self) -> None:
        result = result_fixture()
        runs = list(result.agent_runs)
        runs[0] = run_record(AgentName.TRIAGE, AgentStatus.SUCCESS)
        broken = OrchestrationResult(
            request_id=result.request_id,
            final_state=result.final_state,
            state_history=result.state_history,
            agent_runs=tuple(runs),
            outputs=result.outputs,
            fallback_to_legacy=False,
            stop_reason=None,
            elapsed_ms=10,
        )
        with self.assertRaises(EvidenceBundleBuildError):
            self.builder().build(broken)

    def test_duplicate_plan_ref_fails(self) -> None:
        result = result_fixture()
        runs = list(result.agent_runs)
        runs[1] = run_record(
            AgentName.STATIC_PLANNER,
            AgentStatus.SUCCESS,
            [
                f"plan://{REQUEST_ID}/evidence_plan/plan-i",
                f"plan://{REQUEST_ID}/evidence_plan/plan-i-2",
            ],
        )
        broken = OrchestrationResult(
            request_id=result.request_id,
            final_state=result.final_state,
            state_history=result.state_history,
            agent_runs=tuple(runs),
            outputs=result.outputs,
            fallback_to_legacy=False,
            stop_reason=None,
            elapsed_ms=10,
        )
        with self.assertRaises(EvidenceBundleBuildError):
            self.builder().build(broken)

    def test_refs_are_parseable_by_contract(self) -> None:
        bundle = self.builder().build(result_fixture()).evidence_bundle
        self.assertTrue(bundle.event_ref.startswith("event://"))
        self.assertTrue(bundle.plan_ref.startswith("plan://"))

    def test_source_contracts_are_fixed(self) -> None:
        bundle = self.builder().build(result_fixture()).evidence_bundle
        self.assertEqual(bundle.evidence.metrics.source, EvidenceSource.METRICS)
        self.assertEqual(bundle.evidence.device.source, EvidenceSource.DEVICE)
        self.assertEqual(bundle.evidence.logs.source, EvidenceSource.LOGS)
        self.assertEqual(bundle.evidence.knowledge.source, "knowledge")

    def test_stable_serialization(self) -> None:
        first = self.builder().build(result_fixture()).evidence_bundle
        second = self.builder().build(result_fixture()).evidence_bundle
        self.assertEqual(stable_json_dumps(first), stable_json_dumps(second))

    def test_built_at_requires_timezone(self) -> None:
        builder = EvidenceBundleBuilder(
            utcnow=lambda: datetime(2026, 7, 23, 1, 0)
        )
        with self.assertRaises(EvidenceBundleBuildError):
            builder.build(result_fixture())

    def test_bundle_contains_no_agent_raw_outputs(self) -> None:
        bundle = self.builder().build(result_fixture()).evidence_bundle
        serialized = json.dumps(
            bundle.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
        )
        self.assertNotIn("raw_output", serialized)
        self.assertNotIn("full_device_output", serialized)


if __name__ == "__main__":
    unittest.main()
