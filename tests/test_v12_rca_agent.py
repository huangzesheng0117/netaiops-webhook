from __future__ import annotations

import asyncio
import inspect
import json
import socket
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from netaiops.v12.agent_registry import (
    AgentFailurePolicy,
    AgentSpec,
)
from netaiops.v12.agents.rca_agent import (
    DEFAULT_PROMPT_PATH,
    PROMPT_VERSION,
    RCAAgent,
)
from netaiops.v12.contracts import (
    AlertObject,
    ContextEnvelope,
    DeviceIdentity,
    EvidenceBundle,
    EvidenceCollection,
    EvidenceEnvelope,
    EvidenceJudgeResult,
    RCACandidate,
    RCAResult,
    UnifiedAlertEvent,
)
from netaiops.v12.execution_context import AgentInvocation
from netaiops.v12.state_machine import OrchestrationState
from netaiops.v12.status import (
    AgentName,
    AgentStatus,
    AlertLifecycleStatus,
    AlertSource,
    EvidenceBundleStatus,
    EvidenceSource,
    EvidenceStatus,
    JudgeStatus,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = PROJECT_ROOT / "tests/fixtures/v12/rca"
REQUEST_ID = "req-batch-k-001"
NOW = datetime(2026, 7, 23, 5, 0, tzinfo=timezone.utc)

METRICS_REF = (
    f"evidence://{REQUEST_ID}/metrics/metrics-k-1"
)
DEVICE_REF = (
    f"evidence://{REQUEST_ID}/device/device-k-1"
)
LOGS_REF = (
    f"evidence://{REQUEST_ID}/logs/logs-k-1"
)
EVENT_REF = (
    f"event://{REQUEST_ID}/unified_alert/evt-k"
)
BUNDLE_REF = (
    f"artifact://{REQUEST_ID}/evidence_bundle/bundle-k"
)
JUDGE_REF = (
    f"artifact://{REQUEST_ID}/judge_result/judge-k"
)


def fixture(name: str):
    return json.loads(
        (FIXTURE_ROOT / name).read_text(encoding="utf-8")
    )


def event_payload() -> dict:
    return UnifiedAlertEvent(
        schema_version="v12.1",
        request_id=REQUEST_ID,
        event_id="evt-k",
        source=AlertSource.ALERTMANAGER,
        alert_status=AlertLifecycleStatus.FIRING,
        alert_name="InterfaceDown",
        occurred_at=NOW,
        received_at=NOW,
        device=DeviceIdentity(
            name="SW01",
            ip="10.0.0.1",
            vendor="cisco",
        ),
        alert_object=AlertObject(
            kind="interface",
            name="Ethernet1/1",
        ),
        labels={"severity": "critical"},
        annotations={"summary": "interface down"},
        family="interface_status_or_flap",
        event_key="event:k",
    ).model_dump(mode="json")


def evidence(
    source: EvidenceSource,
    status: EvidenceStatus,
    reference: str | None,
    *,
    facts: dict | None = None,
) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        schema_version="v12.1",
        request_id=REQUEST_ID,
        source=source,
        evidence_kind="evidence",
        status=status,
        summary=f"{source.value} evidence",
        facts=facts or {"observed_state": "down"},
        scope={
            "device_ip": "10.0.0.1",
            "interface": "Ethernet1/1",
        },
        evidence_refs=[reference] if reference else [],
        collected_at=NOW,
        reason=(
            f"{source.value}_not_available"
            if status == EvidenceStatus.NOT_AVAILABLE
            else None
        ),
    )


def bundle_payload(*, ready: bool = False) -> dict:
    logs_status = (
        EvidenceStatus.SUCCESS
        if ready
        else EvidenceStatus.NOT_AVAILABLE
    )
    knowledge_status = (
        EvidenceStatus.SUCCESS
        if ready
        else EvidenceStatus.NOT_AVAILABLE
    )
    knowledge = ContextEnvelope(
        schema_version="v12.1",
        request_id=REQUEST_ID,
        source="knowledge",
        evidence_kind="context",
        status=knowledge_status,
        reason=(
            None
            if ready
            else "local_knowledge_base_not_built"
        ),
        context_facts=[],
        source_refs=(
            [
                f"context://{REQUEST_ID}/"
                "knowledge_context/context-k"
            ]
            if ready
            else []
        ),
        as_of=NOW if ready else None,
        collected_at=NOW,
    )
    return EvidenceBundle(
        schema_version="v12.1",
        request_id=REQUEST_ID,
        event_ref=EVENT_REF,
        plan_ref=f"plan://{REQUEST_ID}/evidence_plan/plan-k",
        evidence=EvidenceCollection(
            metrics=evidence(
                EvidenceSource.METRICS,
                EvidenceStatus.SUCCESS,
                METRICS_REF,
                facts={
                    "observed_state": "down",
                    "raw_output": "sensitive-metric-payload",
                },
            ),
            device=evidence(
                EvidenceSource.DEVICE,
                EvidenceStatus.SUCCESS,
                DEVICE_REF,
            ),
            logs=evidence(
                EvidenceSource.LOGS,
                logs_status,
                LOGS_REF if ready else None,
                facts=(
                    {"event": "link down"}
                    if ready
                    else {}
                ),
            ),
            knowledge=knowledge,
        ),
        bundle_status=(
            EvidenceBundleStatus.COMPLETE
            if ready
            else EvidenceBundleStatus.PARTIAL
        ),
        built_at=NOW,
    ).model_dump(mode="json")


def judge_payload(
    *,
    ready: bool = False,
    status: JudgeStatus | None = None,
) -> dict:
    status = status or (
        JudgeStatus.READY
        if ready
        else JudgeStatus.PARTIAL
    )
    rca_allowed = status in {
        JudgeStatus.READY,
        JudgeStatus.PARTIAL,
    }
    refs = (
        [METRICS_REF, DEVICE_REF, LOGS_REF]
        if ready
        else [METRICS_REF, DEVICE_REF]
    )
    return EvidenceJudgeResult(
        schema_version="v12.1",
        request_id=REQUEST_ID,
        status=status,
        required_sources=[
            EvidenceSource.METRICS,
            EvidenceSource.DEVICE,
        ],
        missing_required_sources=[],
        missing_optional_sources=(
            []
            if ready
            else [
                EvidenceSource.LOGS,
                EvidenceSource.KNOWLEDGE,
            ]
        ),
        conflicts=[],
        rca_allowed=rca_allowed,
        confidence_cap=(
            1.0
            if ready
            else 0.85
            if rca_allowed
            else 0.0
        ),
        evidence_refs=refs,
        judged_at=NOW,
    ).model_dump(mode="json")


def invocation(
    *,
    ready: bool = False,
    judge_status: JudgeStatus | None = None,
    agent_name: AgentName = AgentName.RCA,
) -> AgentInvocation:
    return AgentInvocation(
        request_id=REQUEST_ID,
        agent_name=agent_name,
        orchestration_state=OrchestrationState.RCA,
        prior_output_refs=(
            EVENT_REF,
            BUNDLE_REF,
            JUDGE_REF,
            METRICS_REF,
            DEVICE_REF,
            *( (LOGS_REF,) if ready else () ),
        ),
        prior_outputs={
            AgentName.TRIAGE.value: {
                "unified_event": event_payload()
            },
            "evidence_bundle": {
                "evidence_bundle": bundle_payload(
                    ready=ready
                )
            },
            AgentName.EVIDENCE_JUDGE.value: {
                "judge_result": judge_payload(
                    ready=ready,
                    status=judge_status,
                )
            },
        },
    )


class FixtureMockClient:
    provider = "mock-glm-5.2"

    def __init__(
        self,
        response,
        *,
        error: Exception | None = None,
    ) -> None:
        self.response = response
        self.error = error
        self.calls = 0
        self.prompts: list[str] = []

    async def generate(self, prompt: str):
        self.calls += 1
        self.prompts.append(prompt)
        if self.error is not None:
            raise self.error
        return self.response


class ProductionNamedClient(FixtureMockClient):
    provider = "glm-5.2"


class SyncClient:
    provider = "mock-glm-5.2"

    def generate(self, prompt: str):
        return fixture("valid_partial.json")


class RCAAgentTests(unittest.TestCase):
    fixture_names = (
        "valid_partial.json",
        "valid_ready.json",
        "unknown_ref.json",
        "confidence_over_cap.json",
        "missing_uncertainties.json",
        "missing_inherited_evidence.json",
        "logs_normal_claim.json",
        "command_claim.json",
        "knowledge_realtime_claim.json",
        "overlap_refs.json",
        "duplicate_statements.json",
        "unknown_field.json",
    )

    def agent(
        self,
        *,
        enabled: bool = True,
        response=None,
        client=None,
    ) -> tuple[RCAAgent, object | None]:
        if client is None and response is not None:
            client = FixtureMockClient(response)
        return (
            RCAAgent(
                enabled=enabled,
                client=client,
                utcnow=lambda: NOW,
            ),
            client,
        )

    def run_agent(self, agent: RCAAgent, value: AgentInvocation):
        return asyncio.run(agent.run(value))

    def test_fixture_set_is_complete(self) -> None:
        names = tuple(
            path.name
            for path in sorted(FIXTURE_ROOT.glob("*.json"))
        )
        self.assertEqual(names, tuple(sorted(self.fixture_names)))

    def test_default_disabled_returns_skipped(self) -> None:
        outcome = self.run_agent(
            RCAAgent(utcnow=lambda: NOW),
            invocation(),
        )
        self.assertEqual(outcome.status, AgentStatus.SKIPPED)

    def test_disabled_does_not_call_mock(self) -> None:
        client = FixtureMockClient(fixture("valid_partial.json"))
        outcome = self.run_agent(
            RCAAgent(
                enabled=False,
                client=client,
                utcnow=lambda: NOW,
            ),
            invocation(),
        )
        self.assertEqual(outcome.status, AgentStatus.SKIPPED)
        self.assertEqual(client.calls, 0)

    def test_disabled_result_has_no_candidates(self) -> None:
        outcome = self.run_agent(
            RCAAgent(utcnow=lambda: NOW),
            invocation(),
        )
        result = RCAResult.model_validate(
            outcome.output["rca_result"]
        )
        self.assertEqual(result.candidates, [])
        self.assertIsNone(result.provider)

    def test_disabled_inherits_judge_missing_evidence(self) -> None:
        outcome = self.run_agent(
            RCAAgent(utcnow=lambda: NOW),
            invocation(),
        )
        result = RCAResult.model_validate(
            outcome.output["rca_result"]
        )
        self.assertEqual(
            result.missing_evidence,
            ["logs", "knowledge"],
        )

    def test_insufficient_judge_skips_mock(self) -> None:
        client = FixtureMockClient(fixture("valid_partial.json"))
        agent, _ = self.agent(client=client)
        outcome = self.run_agent(
            agent,
            invocation(judge_status=JudgeStatus.INSUFFICIENT),
        )
        self.assertEqual(outcome.status, AgentStatus.SKIPPED)
        self.assertEqual(client.calls, 0)

    def test_blocked_judge_skips_mock(self) -> None:
        client = FixtureMockClient(fixture("valid_partial.json"))
        agent, _ = self.agent(client=client)
        outcome = self.run_agent(
            agent,
            invocation(judge_status=JudgeStatus.BLOCKED),
        )
        self.assertEqual(outcome.status, AgentStatus.SKIPPED)
        self.assertEqual(client.calls, 0)

    def test_valid_partial_response(self) -> None:
        agent, client = self.agent(
            response=fixture("valid_partial.json")
        )
        outcome = self.run_agent(agent, invocation())
        result = RCAResult.model_validate(
            outcome.output["rca_result"]
        )
        self.assertEqual(outcome.status, AgentStatus.PARTIAL)
        self.assertEqual(result.status, AgentStatus.PARTIAL)
        self.assertEqual(client.calls, 1)

    def test_valid_ready_response(self) -> None:
        agent, _ = self.agent(
            response=fixture("valid_ready.json")
        )
        outcome = self.run_agent(agent, invocation(ready=True))
        result = RCAResult.model_validate(
            outcome.output["rca_result"]
        )
        self.assertEqual(outcome.status, AgentStatus.SUCCESS)
        self.assertEqual(result.status, AgentStatus.SUCCESS)

    def test_provider_is_mock_glm(self) -> None:
        agent, _ = self.agent(
            response=fixture("valid_partial.json")
        )
        outcome = self.run_agent(agent, invocation())
        result = RCAResult.model_validate(
            outcome.output["rca_result"]
        )
        self.assertEqual(result.provider, "mock-glm-5.2")

    def test_candidate_supporting_refs_are_retained(self) -> None:
        agent, _ = self.agent(
            response=fixture("valid_partial.json")
        )
        result = RCAResult.model_validate(
            self.run_agent(agent, invocation()).output["rca_result"]
        )
        self.assertEqual(
            result.candidates[0].supporting_evidence_refs,
            [METRICS_REF, DEVICE_REF],
        )

    def test_top_level_missing_evidence_inherits_judge(self) -> None:
        agent, _ = self.agent(
            response=fixture("valid_partial.json")
        )
        result = RCAResult.model_validate(
            self.run_agent(agent, invocation()).output["rca_result"]
        )
        self.assertEqual(
            result.missing_evidence,
            ["logs", "knowledge"],
        )

    def test_candidate_missing_evidence_inherits_judge(self) -> None:
        agent, _ = self.agent(
            response=fixture("valid_partial.json")
        )
        result = RCAResult.model_validate(
            self.run_agent(agent, invocation()).output["rca_result"]
        )
        self.assertEqual(
            result.candidates[0].missing_evidence,
            ["logs", "knowledge"],
        )

    def test_unknown_ref_is_rejected(self) -> None:
        agent, _ = self.agent(
            response=fixture("unknown_ref.json")
        )
        self.assertEqual(
            self.run_agent(agent, invocation()).status,
            AgentStatus.FAILED,
        )

    def test_confidence_over_cap_is_rejected(self) -> None:
        agent, _ = self.agent(
            response=fixture("confidence_over_cap.json")
        )
        self.assertEqual(
            self.run_agent(agent, invocation()).status,
            AgentStatus.FAILED,
        )

    def test_confidence_equal_cap_is_allowed(self) -> None:
        payload = fixture("valid_partial.json")
        payload["candidates"][0]["confidence"] = 0.85
        agent, _ = self.agent(response=payload)
        self.assertEqual(
            self.run_agent(agent, invocation()).status,
            AgentStatus.PARTIAL,
        )

    def test_missing_uncertainties_is_rejected(self) -> None:
        agent, _ = self.agent(
            response=fixture("missing_uncertainties.json")
        )
        self.assertEqual(
            self.run_agent(agent, invocation()).status,
            AgentStatus.FAILED,
        )

    def test_missing_inherited_evidence_is_rejected(self) -> None:
        agent, _ = self.agent(
            response=fixture("missing_inherited_evidence.json")
        )
        self.assertEqual(
            self.run_agent(agent, invocation()).status,
            AgentStatus.FAILED,
        )

    def test_logs_normal_claim_is_rejected(self) -> None:
        agent, _ = self.agent(
            response=fixture("logs_normal_claim.json")
        )
        self.assertEqual(
            self.run_agent(agent, invocation()).status,
            AgentStatus.FAILED,
        )

    def test_command_output_claim_is_rejected(self) -> None:
        agent, _ = self.agent(
            response=fixture("command_claim.json")
        )
        self.assertEqual(
            self.run_agent(agent, invocation()).status,
            AgentStatus.FAILED,
        )

    def test_knowledge_realtime_claim_is_rejected(self) -> None:
        agent, _ = self.agent(
            response=fixture("knowledge_realtime_claim.json")
        )
        self.assertEqual(
            self.run_agent(agent, invocation()).status,
            AgentStatus.FAILED,
        )

    def test_overlapping_refs_are_rejected(self) -> None:
        agent, _ = self.agent(
            response=fixture("overlap_refs.json")
        )
        self.assertEqual(
            self.run_agent(agent, invocation()).status,
            AgentStatus.FAILED,
        )

    def test_duplicate_statements_are_rejected(self) -> None:
        agent, _ = self.agent(
            response=fixture("duplicate_statements.json")
        )
        self.assertEqual(
            self.run_agent(agent, invocation()).status,
            AgentStatus.FAILED,
        )

    def test_unknown_candidate_field_is_rejected(self) -> None:
        agent, _ = self.agent(
            response=fixture("unknown_field.json")
        )
        self.assertEqual(
            self.run_agent(agent, invocation()).status,
            AgentStatus.FAILED,
        )

    def test_more_than_three_candidates_is_rejected(self) -> None:
        payload = fixture("valid_partial.json")
        payload["candidates"] = payload["candidates"] * 4
        agent, _ = self.agent(response=payload)
        self.assertEqual(
            self.run_agent(agent, invocation()).status,
            AgentStatus.FAILED,
        )

    def test_invalid_json_is_rejected(self) -> None:
        agent, _ = self.agent(response="{not-json")
        self.assertEqual(
            self.run_agent(agent, invocation()).status,
            AgentStatus.FAILED,
        )

    def test_json_array_root_is_rejected(self) -> None:
        agent, _ = self.agent(response="[]")
        self.assertEqual(
            self.run_agent(agent, invocation()).status,
            AgentStatus.FAILED,
        )

    def test_mock_exception_returns_failed(self) -> None:
        client = FixtureMockClient(
            None,
            error=RuntimeError("mock failure"),
        )
        agent, _ = self.agent(client=client)
        outcome = self.run_agent(agent, invocation())
        self.assertEqual(outcome.status, AgentStatus.FAILED)
        self.assertEqual(client.calls, 1)

    def test_missing_client_returns_failed(self) -> None:
        outcome = self.run_agent(
            RCAAgent(enabled=True, utcnow=lambda: NOW),
            invocation(),
        )
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_production_provider_is_forbidden(self) -> None:
        client = ProductionNamedClient(
            fixture("valid_partial.json")
        )
        agent, _ = self.agent(client=client)
        outcome = self.run_agent(agent, invocation())
        self.assertEqual(outcome.status, AgentStatus.FAILED)
        self.assertEqual(client.calls, 0)

    def test_sync_client_is_rejected(self) -> None:
        agent, _ = self.agent(client=SyncClient())
        outcome = self.run_agent(agent, invocation())
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_wrong_agent_name_fails(self) -> None:
        agent, _ = self.agent(
            response=fixture("valid_partial.json")
        )
        outcome = self.run_agent(
            agent,
            invocation(agent_name=AgentName.EVIDENCE_JUDGE),
        )
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_missing_event_fails(self) -> None:
        value = invocation()
        prior = dict(value.prior_outputs)
        prior.pop(AgentName.TRIAGE.value)
        broken = AgentInvocation(
            request_id=value.request_id,
            agent_name=value.agent_name,
            orchestration_state=value.orchestration_state,
            prior_output_refs=value.prior_output_refs,
            prior_outputs=prior,
        )
        agent, _ = self.agent(
            response=fixture("valid_partial.json")
        )
        self.assertEqual(
            self.run_agent(agent, broken).status,
            AgentStatus.FAILED,
        )

    def test_missing_bundle_fails(self) -> None:
        value = invocation()
        prior = dict(value.prior_outputs)
        prior.pop("evidence_bundle")
        broken = AgentInvocation(
            request_id=value.request_id,
            agent_name=value.agent_name,
            orchestration_state=value.orchestration_state,
            prior_output_refs=value.prior_output_refs,
            prior_outputs=prior,
        )
        agent, _ = self.agent(
            response=fixture("valid_partial.json")
        )
        self.assertEqual(
            self.run_agent(agent, broken).status,
            AgentStatus.FAILED,
        )

    def test_missing_judge_fails(self) -> None:
        value = invocation()
        prior = dict(value.prior_outputs)
        prior.pop(AgentName.EVIDENCE_JUDGE.value)
        broken = AgentInvocation(
            request_id=value.request_id,
            agent_name=value.agent_name,
            orchestration_state=value.orchestration_state,
            prior_output_refs=value.prior_output_refs,
            prior_outputs=prior,
        )
        agent, _ = self.agent(
            response=fixture("valid_partial.json")
        )
        self.assertEqual(
            self.run_agent(agent, broken).status,
            AgentStatus.FAILED,
        )

    def test_request_id_mismatch_fails(self) -> None:
        value = invocation()
        prior = json.loads(json.dumps(dict(value.prior_outputs)))
        prior["evidence_bundle"]["evidence_bundle"][
            "request_id"
        ] = "req-other"
        broken = AgentInvocation(
            request_id=value.request_id,
            agent_name=value.agent_name,
            orchestration_state=value.orchestration_state,
            prior_output_refs=value.prior_output_refs,
            prior_outputs=prior,
        )
        agent, _ = self.agent(
            response=fixture("valid_partial.json")
        )
        self.assertEqual(
            self.run_agent(agent, broken).status,
            AgentStatus.FAILED,
        )

    def test_missing_bundle_ref_fails(self) -> None:
        value = invocation()
        refs = tuple(
            ref for ref in value.prior_output_refs
            if ref != BUNDLE_REF
        )
        broken = AgentInvocation(
            request_id=value.request_id,
            agent_name=value.agent_name,
            orchestration_state=value.orchestration_state,
            prior_output_refs=refs,
            prior_outputs=value.prior_outputs,
        )
        agent, _ = self.agent(
            response=fixture("valid_partial.json")
        )
        self.assertEqual(
            self.run_agent(agent, broken).status,
            AgentStatus.FAILED,
        )

    def test_missing_judge_ref_fails(self) -> None:
        value = invocation()
        refs = tuple(
            ref for ref in value.prior_output_refs
            if ref != JUDGE_REF
        )
        broken = AgentInvocation(
            request_id=value.request_id,
            agent_name=value.agent_name,
            orchestration_state=value.orchestration_state,
            prior_output_refs=refs,
            prior_outputs=value.prior_outputs,
        )
        agent, _ = self.agent(
            response=fixture("valid_partial.json")
        )
        self.assertEqual(
            self.run_agent(agent, broken).status,
            AgentStatus.FAILED,
        )

    def test_duplicate_bundle_ref_fails(self) -> None:
        value = invocation()
        broken = AgentInvocation(
            request_id=value.request_id,
            agent_name=value.agent_name,
            orchestration_state=value.orchestration_state,
            prior_output_refs=(
                *value.prior_output_refs,
                (
                    f"artifact://{REQUEST_ID}/"
                    "evidence_bundle/bundle-k-2"
                ),
            ),
            prior_outputs=value.prior_outputs,
        )
        agent, _ = self.agent(
            response=fixture("valid_partial.json")
        )
        self.assertEqual(
            self.run_agent(agent, broken).status,
            AgentStatus.FAILED,
        )

    def test_output_ref_is_stable(self) -> None:
        first_agent, _ = self.agent(
            response=fixture("valid_partial.json")
        )
        second_agent, _ = self.agent(
            response=fixture("valid_partial.json")
        )
        first = self.run_agent(
            first_agent,
            invocation(),
        ).output_refs
        second = self.run_agent(
            second_agent,
            invocation(),
        ).output_refs
        self.assertEqual(first, second)

    def test_external_calls_are_empty(self) -> None:
        agent, _ = self.agent(
            response=fixture("valid_partial.json")
        )
        outcome = self.run_agent(agent, invocation())
        self.assertEqual(outcome.external_calls, ())

    def test_output_flags_forbid_production_calls(self) -> None:
        agent, _ = self.agent(
            response=fixture("valid_partial.json")
        )
        output = self.run_agent(agent, invocation()).output
        self.assertTrue(output["mock_glm_called"])
        self.assertFalse(output["production_glm_called"])
        self.assertFalse(output["mcp_called"])
        self.assertFalse(output["tool_called"])
        self.assertFalse(output["automatic_followup_queries"])

    def test_prompt_contains_allowed_refs_and_cap(self) -> None:
        agent, client = self.agent(
            response=fixture("valid_partial.json")
        )
        self.run_agent(agent, invocation())
        prompt = client.prompts[0]
        self.assertIn(METRICS_REF, prompt)
        self.assertIn(DEVICE_REF, prompt)
        self.assertIn("0.85", prompt)

    def test_prompt_redacts_raw_output_value(self) -> None:
        agent, client = self.agent(
            response=fixture("valid_partial.json")
        )
        self.run_agent(agent, invocation())
        prompt = client.prompts[0]
        self.assertNotIn("sensitive-metric-payload", prompt)
        self.assertIn("[OMITTED]", prompt)

    def test_prompt_template_has_all_frozen_tokens(self) -> None:
        text = DEFAULT_PROMPT_PATH.read_text(encoding="utf-8")
        for token in (
            "{{prompt_version}}",
            "{{event_json}}",
            "{{bundle_json}}",
            "{{judge_json}}",
            "{{allowed_evidence_refs_json}}",
            "{{inherited_missing_evidence_json}}",
            "{{confidence_cap}}",
        ):
            self.assertEqual(text.count(token), 1)

    def test_agent_does_not_create_network_socket(self) -> None:
        agent, _ = self.agent(
            response=fixture("valid_partial.json")
        )
        value = invocation()
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            with mock.patch.object(
                socket,
                "socket",
                side_effect=AssertionError("network forbidden"),
            ):
                outcome = loop.run_until_complete(
                    agent.run(value)
                )
        finally:
            asyncio.set_event_loop(None)
            loop.close()
        self.assertEqual(outcome.status, AgentStatus.PARTIAL)

    def test_async_registry_protocol(self) -> None:
        agent = RCAAgent(utcnow=lambda: NOW)
        self.assertTrue(inspect.iscoroutinefunction(agent.run))
        spec = AgentSpec(
            name=AgentName.RCA,
            agent=agent,
            required=False,
            failure_policy=AgentFailurePolicy.CONTINUE,
        )
        self.assertEqual(spec.retry_limit, 0)

    def test_result_is_json_serializable(self) -> None:
        agent, _ = self.agent(
            response=fixture("valid_partial.json")
        )
        result = RCAResult.model_validate(
            self.run_agent(agent, invocation()).output["rca_result"]
        )
        serialized = json.dumps(
            result.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
        )
        self.assertIn("supporting_evidence_refs", serialized)

    def test_production_modules_have_no_external_clients(self) -> None:
        paths = (
            PROJECT_ROOT / "netaiops/v12/rca_validator.py",
            PROJECT_ROOT / "netaiops/v12/agents/rca_agent.py",
        )
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in paths
        ).lower()
        for token in (
            "import requests",
            "import httpx",
            "import socket",
            "import subprocess",
            "fastmcp(",
            "elasticsearch(",
            "prometheusbridge",
            "execute_commands(",
            "openai(",
        ):
            self.assertNotIn(token, text)

    def test_no_free_loop_or_followup(self) -> None:
        paths = (
            PROJECT_ROOT / "netaiops/v12/rca_validator.py",
            PROJECT_ROOT / "netaiops/v12/agents/rca_agent.py",
        )
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in paths
        )
        for token in (
            "while True",
            "followup_query(",
            "supplement_evidence(",
            "retry(",
        ):
            self.assertNotIn(token, text)


if __name__ == "__main__":
    unittest.main()
