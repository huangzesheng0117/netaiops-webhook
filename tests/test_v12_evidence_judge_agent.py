from __future__ import annotations

import asyncio
import copy
import json
import socket
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from netaiops.v12.agents.evidence_judge_agent import (
    EvidenceJudgeAgent,
)
from netaiops.v12.contracts import (
    ContextEnvelope,
    EvidenceBundle,
    EvidenceCollection,
    EvidenceEnvelope,
    EvidenceJudgeResult,
    EvidencePlan,
    EvidenceSourcePlan,
)
from netaiops.v12.execution_context import AgentInvocation
from netaiops.v12.judge_rules import (
    RULES_VERSION,
    evaluate_evidence,
)
from netaiops.v12.schema_validator import stable_json_dumps
from netaiops.v12.state_machine import OrchestrationState
from netaiops.v12.status import (
    AgentName,
    AgentStatus,
    EvidenceBundleStatus,
    EvidenceSource,
    EvidenceStatus,
    JudgeStatus,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = PROJECT_ROOT / "tests/fixtures/v12/judge"
REQUEST_ID = "req-batch-j-001"
NOW = datetime(2026, 7, 23, 3, 0, tzinfo=timezone.utc)


def _status(value: str) -> EvidenceStatus:
    return EvidenceStatus(value)


def _source(value: str) -> EvidenceSource:
    return EvidenceSource(value)


def scenario(name: str) -> dict:
    return json.loads(
        (FIXTURE_ROOT / name).read_text(encoding="utf-8")
    )


def plan_payload(spec: dict, *, request_id: str = REQUEST_ID) -> dict:
    required = {_source(value) for value in spec.get("required", [])}
    sources = []
    for source in (
        EvidenceSource.METRICS,
        EvidenceSource.DEVICE,
        EvidenceSource.LOGS,
        EvidenceSource.KNOWLEDGE,
    ):
        constraints = {"enabled": True}
        if source == EvidenceSource.LOGS:
            constraints = {
                "enabled": False,
                "reason": "logs_evidence_not_approved",
                "dsl_generation_allowed": False,
            }
        elif source == EvidenceSource.KNOWLEDGE:
            constraints = {
                "enabled": False,
                "reason": "local_knowledge_base_not_built",
                "evidence_kind": "context",
            }
        sources.append(
            EvidenceSourcePlan(
                source=source,
                required=source in required,
                constraints=constraints,
                max_items=0 if source in {
                    EvidenceSource.LOGS,
                    EvidenceSource.KNOWLEDGE,
                } else 1,
            )
        )
    return EvidencePlan(
        schema_version="v12.1",
        request_id=request_id,
        plan_ref=f"plan://{request_id}/evidence_plan/plan-j",
        planner_mode="deterministic",
        family="interface_status_or_flap",
        selected_playbook="cisco_interface_status",
        sources=sources,
        readonly_only=True,
        created_at=NOW,
    ).model_dump(mode="json")


def evidence_payload(
    source: EvidenceSource,
    status: EvidenceStatus,
    *,
    offset_minutes: int = 0,
    state: str | None = None,
    scope: dict | None = None,
    request_id: str = REQUEST_ID,
) -> dict:
    refs = []
    reason = None
    if status in {EvidenceStatus.SUCCESS, EvidenceStatus.PARTIAL}:
        refs = [
            f"evidence://{request_id}/{source.value}/{source.value}-j-1"
        ]
    if status == EvidenceStatus.NOT_AVAILABLE:
        reason = f"{source.value}_not_available"
    facts = {"sample": 1}
    if state:
        facts["observed_state"] = state
    return EvidenceEnvelope(
        schema_version="v12.1",
        request_id=request_id,
        source=source,
        evidence_kind="evidence",
        status=status,
        summary=f"{source.value} evidence",
        facts=facts,
        scope=scope or {
            "device_ip": "10.0.0.1",
            "interface": "Ethernet1/1",
        },
        evidence_refs=refs,
        collected_at=NOW + timedelta(minutes=offset_minutes),
        reason=reason,
    ).model_dump(mode="json")


def knowledge_payload(
    status: EvidenceStatus,
    *,
    offset_minutes: int = 0,
    request_id: str = REQUEST_ID,
) -> dict:
    success = status == EvidenceStatus.SUCCESS
    return ContextEnvelope(
        schema_version="v12.1",
        request_id=request_id,
        source="knowledge",
        evidence_kind="context",
        status=status,
        reason=(
            None
            if success
            else "local_knowledge_base_not_built"
        ),
        context_facts=[],
        source_refs=(
            [f"context://{request_id}/knowledge_context/context-j-1"]
            if success
            else []
        ),
        as_of=NOW if success else None,
        collected_at=NOW + timedelta(minutes=offset_minutes),
    ).model_dump(mode="json")


def bundle_payload(
    spec: dict,
    *,
    request_id: str = REQUEST_ID,
) -> dict:
    statuses = spec["statuses"]
    states = spec.get("states", {})
    scopes = spec.get("scopes", {})
    offsets = spec.get("collected_offset_minutes", {})

    metrics = evidence_payload(
        EvidenceSource.METRICS,
        _status(statuses["metrics"]),
        offset_minutes=int(offsets.get("metrics", 0)),
        state=states.get("metrics"),
        scope=scopes.get("metrics"),
        request_id=request_id,
    )
    device = evidence_payload(
        EvidenceSource.DEVICE,
        _status(statuses["device"]),
        offset_minutes=int(offsets.get("device", 0)),
        state=states.get("device"),
        scope=scopes.get("device"),
        request_id=request_id,
    )
    logs = evidence_payload(
        EvidenceSource.LOGS,
        _status(statuses["logs"]),
        offset_minutes=int(offsets.get("logs", 0)),
        state=states.get("logs"),
        scope=scopes.get("logs"),
        request_id=request_id,
    )
    knowledge = knowledge_payload(
        _status(statuses["knowledge"]),
        offset_minutes=int(offsets.get("knowledge", 0)),
        request_id=request_id,
    )

    remove_refs = set(spec.get("remove_refs", []))
    for source_name, payload in (
        ("metrics", metrics),
        ("device", device),
        ("logs", logs),
    ):
        if source_name in remove_refs:
            payload["evidence_refs"] = []
    if "knowledge" in remove_refs:
        knowledge["source_refs"] = []

    required = set(spec.get("required", []))
    unavailable = {
        EvidenceStatus.FAILED.value,
        EvidenceStatus.SKIPPED.value,
        EvidenceStatus.NOT_AVAILABLE.value,
    }
    if any(
        statuses[source] in unavailable
        for source in required
    ):
        bundle_status = EvidenceBundleStatus.INSUFFICIENT
    elif any(value != "success" for value in statuses.values()):
        bundle_status = EvidenceBundleStatus.PARTIAL
    else:
        bundle_status = EvidenceBundleStatus.COMPLETE

    return {
        "schema_version": "v12.1",
        "request_id": request_id,
        "event_ref": f"event://{request_id}/unified_alert/evt-j",
        "plan_ref": f"plan://{request_id}/evidence_plan/plan-j",
        "evidence": {
            "metrics": metrics,
            "device": device,
            "logs": logs,
            "knowledge": knowledge,
        },
        "bundle_status": bundle_status.value,
        "built_at": NOW.isoformat(),
    }


def direct_invocation(
    spec: dict,
    *,
    request_id: str = REQUEST_ID,
    agent_name: AgentName = AgentName.EVIDENCE_JUDGE,
) -> AgentInvocation:
    return AgentInvocation(
        request_id=request_id,
        agent_name=agent_name,
        orchestration_state=OrchestrationState.EVIDENCE_JUDGING,
        prior_output_refs=(
            f"event://{request_id}/unified_alert/evt-j",
            f"plan://{request_id}/evidence_plan/plan-j",
        ),
        prior_outputs={
            AgentName.STATIC_PLANNER.value: {
                "evidence_plan": plan_payload(
                    spec,
                    request_id=request_id,
                )
            },
            "evidence_bundle": {
                "evidence_bundle": bundle_payload(
                    spec,
                    request_id=request_id,
                )
            },
        },
    )


def derived_invocation(spec: dict) -> AgentInvocation:
    raw_bundle = bundle_payload(spec)
    evidence = raw_bundle["evidence"]
    return AgentInvocation(
        request_id=REQUEST_ID,
        agent_name=AgentName.EVIDENCE_JUDGE,
        orchestration_state=OrchestrationState.EVIDENCE_JUDGING,
        prior_output_refs=(
            f"event://{REQUEST_ID}/unified_alert/evt-j",
            f"plan://{REQUEST_ID}/evidence_plan/plan-j",
        ),
        prior_outputs={
            AgentName.STATIC_PLANNER.value: {
                "evidence_plan": plan_payload(spec)
            },
            AgentName.METRICS_EVIDENCE.value: {
                "metrics_evidence": evidence["metrics"]
            },
            AgentName.DEVICE_EVIDENCE.value: {
                "device_evidence": evidence["device"]
            },
            AgentName.LOGS_EVIDENCE.value: {
                "logs_evidence": evidence["logs"]
            },
            AgentName.KNOWLEDGE_CONTEXT.value: {
                "knowledge_context": evidence["knowledge"]
            },
        },
    )


class EvidenceJudgeAgentTests(unittest.TestCase):
    fixture_names = (
        "ready_all_success.json",
        "optional_not_available.json",
        "metrics_no_data_device_success.json",
        "metrics_success_device_failed.json",
        "required_logs_failed.json",
        "metrics_device_state_conflict.json",
        "metrics_device_scope_conflict.json",
        "missing_required_evidence_ref.json",
        "stale_required_metrics.json",
        "all_evidence_missing.json",
    )

    def run_agent(self, invocation: AgentInvocation):
        return asyncio.run(EvidenceJudgeAgent().run(invocation))

    def test_fixture_rule_matrix(self) -> None:
        for name in self.fixture_names:
            with self.subTest(name=name):
                spec = scenario(name)
                outcome = self.run_agent(direct_invocation(spec))
                result = EvidenceJudgeResult.model_validate(
                    outcome.output["judge_result"]
                )
                self.assertEqual(
                    result.status.value,
                    spec["expected_status"],
                )
                self.assertEqual(
                    result.rca_allowed,
                    spec["expected_rca_allowed"],
                )
                self.assertEqual(
                    result.confidence_cap,
                    spec["expected_confidence_cap"],
                )
                self.assertEqual(
                    [item.value for item in result.missing_required_sources],
                    spec.get("expected_missing_required", []),
                )
                self.assertEqual(
                    [item.value for item in result.missing_optional_sources],
                    spec.get("expected_missing_optional", []),
                )
                self.assertEqual(
                    len(result.conflicts),
                    spec.get("expected_conflicts", 0),
                )

    def test_ready_maps_to_agent_success(self) -> None:
        outcome = self.run_agent(
            direct_invocation(scenario("ready_all_success.json"))
        )
        self.assertEqual(outcome.status, AgentStatus.SUCCESS)

    def test_partial_maps_to_agent_partial(self) -> None:
        outcome = self.run_agent(
            direct_invocation(scenario("optional_not_available.json"))
        )
        self.assertEqual(outcome.status, AgentStatus.PARTIAL)

    def test_insufficient_maps_to_agent_partial(self) -> None:
        outcome = self.run_agent(
            direct_invocation(
                scenario("metrics_success_device_failed.json")
            )
        )
        self.assertEqual(outcome.status, AgentStatus.PARTIAL)

    def test_blocked_maps_to_agent_partial(self) -> None:
        outcome = self.run_agent(
            direct_invocation(
                scenario("metrics_device_state_conflict.json")
            )
        )
        self.assertEqual(outcome.status, AgentStatus.PARTIAL)

    def test_direct_bundle_source(self) -> None:
        outcome = self.run_agent(
            direct_invocation(scenario("ready_all_success.json"))
        )
        self.assertEqual(
            outcome.output["bundle_source"],
            "prior_evidence_bundle",
        )

    def test_derived_bundle_source(self) -> None:
        outcome = self.run_agent(
            derived_invocation(
                scenario("optional_not_available.json")
            )
        )
        self.assertEqual(
            outcome.output["bundle_source"],
            "derived_from_agent_outputs",
        )

    def test_derived_bundle_result_matches_direct(self) -> None:
        spec = scenario("optional_not_available.json")
        direct = self.run_agent(direct_invocation(spec))
        derived = self.run_agent(derived_invocation(spec))
        self.assertEqual(
            stable_json_dumps(direct.output["judge_result"]),
            stable_json_dumps(derived.output["judge_result"]),
        )

    def test_same_input_has_identical_result(self) -> None:
        invocation = direct_invocation(
            scenario("optional_not_available.json")
        )
        first = self.run_agent(invocation)
        second = self.run_agent(invocation)
        self.assertEqual(
            stable_json_dumps(first.output["judge_result"]),
            stable_json_dumps(second.output["judge_result"]),
        )

    def test_judged_at_is_input_derived(self) -> None:
        outcome = self.run_agent(
            direct_invocation(scenario("ready_all_success.json"))
        )
        result = EvidenceJudgeResult.model_validate(
            outcome.output["judge_result"]
        )
        self.assertEqual(result.judged_at, NOW)

    def test_optional_unavailable_does_not_block_rca(self) -> None:
        result = EvidenceJudgeResult.model_validate(
            self.run_agent(
                direct_invocation(
                    scenario("optional_not_available.json")
                )
            ).output["judge_result"]
        )
        self.assertTrue(result.rca_allowed)
        self.assertEqual(result.status, JudgeStatus.PARTIAL)

    def test_required_no_data_reduces_confidence(self) -> None:
        result = EvidenceJudgeResult.model_validate(
            self.run_agent(
                direct_invocation(
                    scenario("metrics_no_data_device_success.json")
                )
            ).output["judge_result"]
        )
        self.assertEqual(result.confidence_cap, 0.65)
        self.assertTrue(result.rca_allowed)

    def test_failed_required_source_disallows_rca(self) -> None:
        result = EvidenceJudgeResult.model_validate(
            self.run_agent(
                direct_invocation(
                    scenario("metrics_success_device_failed.json")
                )
            ).output["judge_result"]
        )
        self.assertFalse(result.rca_allowed)
        self.assertEqual(result.status, JudgeStatus.INSUFFICIENT)

    def test_conflict_contains_two_evidence_refs(self) -> None:
        result = EvidenceJudgeResult.model_validate(
            self.run_agent(
                direct_invocation(
                    scenario("metrics_device_state_conflict.json")
                )
            ).output["judge_result"]
        )
        self.assertEqual(len(result.conflicts), 1)
        self.assertEqual(
            len(result.conflicts[0].evidence_refs),
            2,
        )
        self.assertEqual(result.conflicts[0].severity, "high")

    def test_missing_success_ref_is_judged_not_crashed(self) -> None:
        outcome = self.run_agent(
            direct_invocation(
                scenario("missing_required_evidence_ref.json")
            )
        )
        result = EvidenceJudgeResult.model_validate(
            outcome.output["judge_result"]
        )
        self.assertEqual(result.status, JudgeStatus.INSUFFICIENT)
        self.assertEqual(
            result.missing_required_sources,
            [EvidenceSource.METRICS],
        )

    def test_stale_required_source_is_insufficient(self) -> None:
        result = EvidenceJudgeResult.model_validate(
            self.run_agent(
                direct_invocation(
                    scenario("stale_required_metrics.json")
                )
            ).output["judge_result"]
        )
        self.assertEqual(result.status, JudgeStatus.INSUFFICIENT)

    def test_all_missing_is_insufficient(self) -> None:
        result = EvidenceJudgeResult.model_validate(
            self.run_agent(
                direct_invocation(
                    scenario("all_evidence_missing.json")
                )
            ).output["judge_result"]
        )
        self.assertFalse(result.rca_allowed)
        self.assertEqual(result.confidence_cap, 0.0)

    def test_evidence_refs_are_unique_and_sorted(self) -> None:
        result = EvidenceJudgeResult.model_validate(
            self.run_agent(
                direct_invocation(
                    scenario("ready_all_success.json")
                )
            ).output["judge_result"]
        )
        self.assertEqual(
            result.evidence_refs,
            sorted(set(result.evidence_refs)),
        )

    def test_rules_version_is_frozen(self) -> None:
        outcome = self.run_agent(
            direct_invocation(scenario("ready_all_success.json"))
        )
        self.assertEqual(outcome.output["rules_version"], RULES_VERSION)

    def test_output_flags_are_offline(self) -> None:
        output = self.run_agent(
            direct_invocation(scenario("ready_all_success.json"))
        ).output
        self.assertFalse(output["llm_called"])
        self.assertFalse(output["mcp_called"])
        self.assertFalse(output["tool_called"])
        self.assertFalse(output["automatic_followup_queries"])

    def test_external_calls_are_empty(self) -> None:
        outcome = self.run_agent(
            direct_invocation(scenario("ready_all_success.json"))
        )
        self.assertEqual(outcome.external_calls, ())

    def test_output_ref_is_stable(self) -> None:
        invocation = direct_invocation(
            scenario("optional_not_available.json")
        )
        first = self.run_agent(invocation).output_refs
        second = self.run_agent(invocation).output_refs
        self.assertEqual(first, second)
        self.assertTrue(
            first[0].startswith(
                f"artifact://{REQUEST_ID}/judge_result/"
            )
        )

    def test_wrong_agent_name_fails(self) -> None:
        outcome = self.run_agent(
            direct_invocation(
                scenario("ready_all_success.json"),
                agent_name=AgentName.RCA,
            )
        )
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_missing_plan_fails(self) -> None:
        invocation = direct_invocation(
            scenario("ready_all_success.json")
        )
        prior = dict(invocation.prior_outputs)
        prior.pop(AgentName.STATIC_PLANNER.value)
        broken = AgentInvocation(
            request_id=invocation.request_id,
            agent_name=invocation.agent_name,
            orchestration_state=invocation.orchestration_state,
            prior_output_refs=invocation.prior_output_refs,
            prior_outputs=prior,
        )
        self.assertEqual(
            self.run_agent(broken).status,
            AgentStatus.FAILED,
        )

    def test_invalid_plan_fails(self) -> None:
        invocation = direct_invocation(
            scenario("ready_all_success.json")
        )
        prior = dict(invocation.prior_outputs)
        prior[AgentName.STATIC_PLANNER.value] = {
            "evidence_plan": {"schema_version": "v12.1"}
        }
        broken = AgentInvocation(
            request_id=invocation.request_id,
            agent_name=invocation.agent_name,
            orchestration_state=invocation.orchestration_state,
            prior_output_refs=invocation.prior_output_refs,
            prior_outputs=prior,
        )
        self.assertEqual(
            self.run_agent(broken).status,
            AgentStatus.FAILED,
        )

    def test_plan_request_mismatch_fails(self) -> None:
        spec = scenario("ready_all_success.json")
        invocation = direct_invocation(spec)
        prior = dict(invocation.prior_outputs)
        prior[AgentName.STATIC_PLANNER.value] = {
            "evidence_plan": plan_payload(
                spec,
                request_id="req-other",
            )
        }
        broken = AgentInvocation(
            request_id=REQUEST_ID,
            agent_name=AgentName.EVIDENCE_JUDGE,
            orchestration_state=OrchestrationState.EVIDENCE_JUDGING,
            prior_output_refs=invocation.prior_output_refs,
            prior_outputs=prior,
        )
        self.assertEqual(
            self.run_agent(broken).status,
            AgentStatus.FAILED,
        )

    def test_bundle_request_mismatch_fails(self) -> None:
        spec = scenario("ready_all_success.json")
        invocation = direct_invocation(spec)
        prior = copy.deepcopy(dict(invocation.prior_outputs))
        raw = prior["evidence_bundle"]["evidence_bundle"]
        raw["request_id"] = "req-other"
        broken = AgentInvocation(
            request_id=REQUEST_ID,
            agent_name=AgentName.EVIDENCE_JUDGE,
            orchestration_state=OrchestrationState.EVIDENCE_JUDGING,
            prior_output_refs=invocation.prior_output_refs,
            prior_outputs=prior,
        )
        self.assertEqual(
            self.run_agent(broken).status,
            AgentStatus.FAILED,
        )

    def test_missing_derived_source_fails(self) -> None:
        invocation = derived_invocation(
            scenario("ready_all_success.json")
        )
        prior = dict(invocation.prior_outputs)
        prior.pop(AgentName.DEVICE_EVIDENCE.value)
        broken = AgentInvocation(
            request_id=REQUEST_ID,
            agent_name=AgentName.EVIDENCE_JUDGE,
            orchestration_state=OrchestrationState.EVIDENCE_JUDGING,
            prior_output_refs=invocation.prior_output_refs,
            prior_outputs=prior,
        )
        self.assertEqual(
            self.run_agent(broken).status,
            AgentStatus.FAILED,
        )

    def test_missing_event_ref_for_derived_bundle_fails(self) -> None:
        invocation = derived_invocation(
            scenario("ready_all_success.json")
        )
        broken = AgentInvocation(
            request_id=REQUEST_ID,
            agent_name=AgentName.EVIDENCE_JUDGE,
            orchestration_state=OrchestrationState.EVIDENCE_JUDGING,
            prior_output_refs=(
                f"plan://{REQUEST_ID}/evidence_plan/plan-j",
            ),
            prior_outputs=invocation.prior_outputs,
        )
        self.assertEqual(
            self.run_agent(broken).status,
            AgentStatus.FAILED,
        )

    def test_duplicate_plan_ref_for_derived_bundle_fails(self) -> None:
        invocation = derived_invocation(
            scenario("ready_all_success.json")
        )
        broken = AgentInvocation(
            request_id=REQUEST_ID,
            agent_name=AgentName.EVIDENCE_JUDGE,
            orchestration_state=OrchestrationState.EVIDENCE_JUDGING,
            prior_output_refs=(
                f"event://{REQUEST_ID}/unified_alert/evt-j",
                f"plan://{REQUEST_ID}/evidence_plan/plan-j",
                f"plan://{REQUEST_ID}/evidence_plan/plan-j-2",
            ),
            prior_outputs=invocation.prior_outputs,
        )
        self.assertEqual(
            self.run_agent(broken).status,
            AgentStatus.FAILED,
        )

    def test_agent_does_not_create_network_socket(self) -> None:
        agent = EvidenceJudgeAgent()
        invocation = direct_invocation(
            scenario("ready_all_success.json")
        )
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            with mock.patch.object(
                socket,
                "socket",
                side_effect=AssertionError("network forbidden"),
            ):
                outcome = loop.run_until_complete(
                    agent.run(invocation)
                )
        finally:
            asyncio.set_event_loop(None)
            loop.close()
        self.assertEqual(outcome.status, AgentStatus.SUCCESS)

    def test_production_modules_have_no_external_clients(self) -> None:
        paths = (
            PROJECT_ROOT / "netaiops/v12/judge_rules.py",
            PROJECT_ROOT / "netaiops/v12/agents/evidence_judge_agent.py",
        )
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in paths
        )
        for token in (
            "import requests",
            "import httpx",
            "import socket",
            "import subprocess",
            "fastmcp(",
            "elasticsearch(",
            "prometheusbridge",
            "execute_commands(",
            "glm",
        ):
            self.assertNotIn(token, text.lower())

    def test_no_automatic_followup_or_free_loop(self) -> None:
        paths = (
            PROJECT_ROOT / "netaiops/v12/judge_rules.py",
            PROJECT_ROOT / "netaiops/v12/agents/evidence_judge_agent.py",
        )
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in paths
        )
        for token in (
            "while True",
            "retry(",
            "followup_query(",
            "supplement_evidence(",
        ):
            self.assertNotIn(token, text)

    def test_direct_rules_function_is_contract_valid(self) -> None:
        spec = scenario("optional_not_available.json")
        plan = EvidencePlan.model_validate(plan_payload(spec))
        bundle = EvidenceBundle.model_validate(bundle_payload(spec))
        result = evaluate_evidence(plan, bundle)
        self.assertIsInstance(result, EvidenceJudgeResult)
        self.assertEqual(result.status, JudgeStatus.PARTIAL)


if __name__ == "__main__":
    unittest.main()
