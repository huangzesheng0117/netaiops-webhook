from __future__ import annotations

import asyncio
import builtins
import inspect
import json
import socket
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from netaiops.v12.agent_registry import AgentFailurePolicy, AgentSpec
from netaiops.v12.agents.knowledge_context_agent import (
    KNOWLEDGE_PLACEHOLDER_REASON,
    KnowledgeContextAgent,
)
from netaiops.v12.agents.logs_evidence_agent import (
    LOGS_PLACEHOLDER_REASON,
    LogsEvidenceAgent,
)
from netaiops.v12.contracts import (
    ContextEnvelope,
    EvidenceEnvelope,
    EvidencePlan,
    EvidenceSourcePlan,
)
from netaiops.v12.execution_context import AgentInvocation
from netaiops.v12.state_machine import OrchestrationState
from netaiops.v12.status import (
    AgentName,
    AgentStatus,
    EvidenceSource,
    EvidenceStatus,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REQUEST_ID = "req-batch-h-001"
NOW = datetime(2026, 7, 22, 4, 0, tzinfo=timezone.utc)


def evidence_plan(
    *,
    request_id: str = REQUEST_ID,
    include_logs: bool = True,
    include_knowledge: bool = True,
    logs_required: bool = False,
    logs_max_items: int = 0,
    logs_enabled: bool = False,
    logs_reason: str = LOGS_PLACEHOLDER_REASON,
    logs_dsl_allowed: bool = False,
    knowledge_required: bool = False,
    knowledge_max_items: int = 0,
    knowledge_enabled: bool = False,
    knowledge_reason: str = KNOWLEDGE_PLACEHOLDER_REASON,
    knowledge_kind: str = "context",
) -> dict:
    sources = [
        EvidenceSourcePlan(
            source=EvidenceSource.METRICS,
            required=False,
            constraints={
                "reuse_existing_evidence": True,
                "promql_generation_allowed": False,
            },
            max_items=1,
        ),
        EvidenceSourcePlan(
            source=EvidenceSource.DEVICE,
            required=False,
            constraints={
                "readonly_only": True,
                "command_generation_allowed": False,
                "safety_policy_allowed": True,
            },
            max_items=1,
        ),
    ]
    if include_logs:
        sources.append(
            EvidenceSourcePlan(
                source=EvidenceSource.LOGS,
                required=logs_required,
                capability_ids=["query_elastic_logs"],
                constraints={
                    "enabled": logs_enabled,
                    "reason": logs_reason,
                    "dsl_generation_allowed": logs_dsl_allowed,
                },
                max_items=logs_max_items,
            )
        )
    if include_knowledge:
        sources.append(
            EvidenceSourcePlan(
                source=EvidenceSource.KNOWLEDGE,
                required=knowledge_required,
                constraints={
                    "enabled": knowledge_enabled,
                    "reason": knowledge_reason,
                    "evidence_kind": knowledge_kind,
                },
                max_items=knowledge_max_items,
            )
        )
    return EvidencePlan(
        schema_version="v12.1",
        request_id=request_id,
        plan_ref=f"plan://{request_id}/evidence_plan/plan-h",
        planner_mode="deterministic",
        family="interface_status_or_flap",
        selected_playbook="cisco_interface_status",
        sources=sources,
        readonly_only=True,
        created_at=NOW,
    ).model_dump(mode="json")


def invocation(
    agent_name: AgentName,
    *,
    plan: dict | None = None,
    request_id: str = REQUEST_ID,
) -> AgentInvocation:
    prior_outputs = {}
    if plan is not None:
        prior_outputs[AgentName.STATIC_PLANNER.value] = {
            "evidence_plan": plan,
        }
    return AgentInvocation(
        request_id=request_id,
        agent_name=agent_name,
        orchestration_state=OrchestrationState.EVIDENCE_COLLECTION,
        prior_output_refs=(),
        prior_outputs=prior_outputs,
    )


def run_agent(agent, agent_name: AgentName, *, plan: dict | None = None):
    return asyncio.run(
        agent.run(
            invocation(
                agent_name,
                plan=plan if plan is not None else evidence_plan(),
            )
        )
    )


class PlaceholderAgentTests(unittest.TestCase):
    def logs_agent(self) -> LogsEvidenceAgent:
        return LogsEvidenceAgent(utcnow=lambda: NOW)

    def knowledge_agent(self) -> KnowledgeContextAgent:
        return KnowledgeContextAgent(utcnow=lambda: NOW)

    def test_logs_contract_is_frozen_not_available(self) -> None:
        outcome = run_agent(self.logs_agent(), AgentName.LOGS_EVIDENCE)
        envelope = EvidenceEnvelope.model_validate(
            outcome.output["logs_evidence"]
        )
        self.assertEqual(outcome.status, AgentStatus.NOT_AVAILABLE)
        self.assertEqual(envelope.status, EvidenceStatus.NOT_AVAILABLE)
        self.assertEqual(envelope.source, EvidenceSource.LOGS)
        self.assertEqual(envelope.evidence_kind, "evidence")
        self.assertEqual(envelope.reason, LOGS_PLACEHOLDER_REASON)
        self.assertEqual(envelope.evidence_refs, [])

    def test_logs_external_call_flags_are_false(self) -> None:
        outcome = run_agent(self.logs_agent(), AgentName.LOGS_EVIDENCE)
        output = outcome.output
        self.assertFalse(output["fastmcp_called"])
        self.assertFalse(output["ops_es_api_called"])
        self.assertFalse(output["elasticsearch_called"])
        self.assertFalse(output["dsl_generation_performed"])
        self.assertFalse(output["no_data_interpreted_as_normal"])
        self.assertEqual(outcome.external_calls, ())

    def test_logs_output_ref_is_stable(self) -> None:
        first = run_agent(
            self.logs_agent(), AgentName.LOGS_EVIDENCE
        ).output_refs
        second = run_agent(
            self.logs_agent(), AgentName.LOGS_EVIDENCE
        ).output_refs
        self.assertEqual(first, second)
        self.assertTrue(first[0].startswith(f"artifact://{REQUEST_ID}/"))

    def test_logs_invalid_invocations_fail(self) -> None:
        scenarios = [
            invocation(AgentName.KNOWLEDGE_CONTEXT, plan=evidence_plan()),
            invocation(AgentName.LOGS_EVIDENCE, plan=None),
            invocation(
                AgentName.LOGS_EVIDENCE,
                plan={"schema_version": "v12.1"},
            ),
            invocation(
                AgentName.LOGS_EVIDENCE,
                plan=evidence_plan(request_id="req-other-plan"),
            ),
            invocation(
                AgentName.LOGS_EVIDENCE,
                plan=evidence_plan(include_logs=False),
            ),
        ]
        for item in scenarios:
            with self.subTest(agent_name=item.agent_name):
                outcome = asyncio.run(self.logs_agent().run(item))
                self.assertEqual(outcome.status, AgentStatus.FAILED)
                self.assertTrue(outcome.errors)

    def test_logs_contract_drift_fails(self) -> None:
        plans = [
            evidence_plan(logs_enabled=True),
            evidence_plan(logs_reason="wrong_reason"),
            evidence_plan(logs_dsl_allowed=True),
            evidence_plan(logs_required=True),
            evidence_plan(logs_max_items=1),
        ]
        for plan in plans:
            with self.subTest(plan=plan):
                outcome = run_agent(
                    self.logs_agent(),
                    AgentName.LOGS_EVIDENCE,
                    plan=plan,
                )
                self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_knowledge_contract_is_frozen_not_available(self) -> None:
        outcome = run_agent(
            self.knowledge_agent(), AgentName.KNOWLEDGE_CONTEXT
        )
        envelope = ContextEnvelope.model_validate(
            outcome.output["knowledge_context"]
        )
        self.assertEqual(outcome.status, AgentStatus.NOT_AVAILABLE)
        self.assertEqual(envelope.status, EvidenceStatus.NOT_AVAILABLE)
        self.assertEqual(envelope.source, "knowledge")
        self.assertEqual(envelope.evidence_kind, "context")
        self.assertEqual(envelope.reason, KNOWLEDGE_PLACEHOLDER_REASON)

    def test_knowledge_context_fields_remain_empty(self) -> None:
        outcome = run_agent(
            self.knowledge_agent(), AgentName.KNOWLEDGE_CONTEXT
        )
        envelope = ContextEnvelope.model_validate(
            outcome.output["knowledge_context"]
        )
        self.assertEqual(envelope.context_facts, [])
        self.assertEqual(envelope.source_refs, [])
        self.assertIsNone(envelope.as_of)

    def test_knowledge_external_call_flags_are_false(self) -> None:
        outcome = run_agent(
            self.knowledge_agent(), AgentName.KNOWLEDGE_CONTEXT
        )
        output = outcome.output
        self.assertFalse(output["local_knowledge_base_read"])
        self.assertFalse(output["glm_called"])
        self.assertFalse(output["network_called"])
        self.assertFalse(
            output["context_substituted_for_realtime_evidence"]
        )
        self.assertEqual(outcome.external_calls, ())

    def test_knowledge_output_ref_is_stable(self) -> None:
        first = run_agent(
            self.knowledge_agent(), AgentName.KNOWLEDGE_CONTEXT
        ).output_refs
        second = run_agent(
            self.knowledge_agent(), AgentName.KNOWLEDGE_CONTEXT
        ).output_refs
        self.assertEqual(first, second)
        self.assertTrue(first[0].startswith(f"context://{REQUEST_ID}/"))

    def test_knowledge_invalid_invocations_fail(self) -> None:
        scenarios = [
            invocation(AgentName.LOGS_EVIDENCE, plan=evidence_plan()),
            invocation(AgentName.KNOWLEDGE_CONTEXT, plan=None),
            invocation(
                AgentName.KNOWLEDGE_CONTEXT,
                plan={"schema_version": "v12.1"},
            ),
            invocation(
                AgentName.KNOWLEDGE_CONTEXT,
                plan=evidence_plan(request_id="req-other-plan"),
            ),
            invocation(
                AgentName.KNOWLEDGE_CONTEXT,
                plan=evidence_plan(include_knowledge=False),
            ),
        ]
        for item in scenarios:
            with self.subTest(agent_name=item.agent_name):
                outcome = asyncio.run(self.knowledge_agent().run(item))
                self.assertEqual(outcome.status, AgentStatus.FAILED)
                self.assertTrue(outcome.errors)

    def test_knowledge_contract_drift_fails(self) -> None:
        plans = [
            evidence_plan(knowledge_enabled=True),
            evidence_plan(knowledge_reason="wrong_reason"),
            evidence_plan(knowledge_kind="evidence"),
            evidence_plan(knowledge_required=True),
            evidence_plan(knowledge_max_items=1),
        ]
        for plan in plans:
            with self.subTest(plan=plan):
                outcome = run_agent(
                    self.knowledge_agent(),
                    AgentName.KNOWLEDGE_CONTEXT,
                    plan=plan,
                )
                self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_outputs_are_stably_json_serializable(self) -> None:
        logs = run_agent(self.logs_agent(), AgentName.LOGS_EVIDENCE)
        knowledge = run_agent(
            self.knowledge_agent(), AgentName.KNOWLEDGE_CONTEXT
        )
        logs_json = json.dumps(
            dict(logs.output), ensure_ascii=False, sort_keys=True
        )
        knowledge_json = json.dumps(
            dict(knowledge.output), ensure_ascii=False, sort_keys=True
        )
        self.assertIn(LOGS_PLACEHOLDER_REASON, logs_json)
        self.assertIn(KNOWLEDGE_PLACEHOLDER_REASON, knowledge_json)

    def test_agents_do_not_create_network_sockets(self) -> None:
        logs_agent = self.logs_agent()
        knowledge_agent = self.knowledge_agent()
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            with mock.patch.object(
                socket,
                "socket",
                side_effect=AssertionError("network forbidden"),
            ):
                logs = loop.run_until_complete(
                    logs_agent.run(
                        invocation(
                            AgentName.LOGS_EVIDENCE,
                            plan=evidence_plan(),
                        )
                    )
                )
                knowledge = loop.run_until_complete(
                    knowledge_agent.run(
                        invocation(
                            AgentName.KNOWLEDGE_CONTEXT,
                            plan=evidence_plan(),
                        )
                    )
                )
        finally:
            asyncio.set_event_loop(None)
            loop.close()
        self.assertEqual(logs.status, AgentStatus.NOT_AVAILABLE)
        self.assertEqual(knowledge.status, AgentStatus.NOT_AVAILABLE)

    def test_knowledge_agent_reads_no_files(self) -> None:
        agent = self.knowledge_agent()
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            with mock.patch.object(
                builtins,
                "open",
                side_effect=AssertionError("file read forbidden"),
            ):
                outcome = loop.run_until_complete(
                    agent.run(
                        invocation(
                            AgentName.KNOWLEDGE_CONTEXT,
                            plan=evidence_plan(),
                        )
                    )
                )
        finally:
            asyncio.set_event_loop(None)
            loop.close()
        self.assertEqual(outcome.status, AgentStatus.NOT_AVAILABLE)

    def test_production_modules_have_no_external_client_imports(self) -> None:
        paths = [
            PROJECT_ROOT / "netaiops/v12/agents/logs_evidence_agent.py",
            PROJECT_ROOT / "netaiops/v12/agents/knowledge_context_agent.py",
        ]
        text = chr(10).join(
            path.read_text(encoding="utf-8") for path in paths
        )
        forbidden = (
            "import requests",
            "import httpx",
            "import socket",
            "import subprocess",
            "from pathlib import",
            "search_logs(",
            "Elasticsearch(",
            "FastMCP(",
            "open(",
        )
        for token in forbidden:
            self.assertNotIn(token, text)

    def test_not_available_is_not_interpreted_as_normal(self) -> None:
        outcome = run_agent(self.logs_agent(), AgentName.LOGS_EVIDENCE)
        envelope = EvidenceEnvelope.model_validate(
            outcome.output["logs_evidence"]
        )
        serialized = json.dumps(
            envelope.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
        ).lower()
        self.assertEqual(envelope.status, EvidenceStatus.NOT_AVAILABLE)
        self.assertNotEqual(envelope.status, EvidenceStatus.SUCCESS)
        self.assertNotIn('"normal": true', serialized)
        self.assertFalse(envelope.facts["no_data_interpreted_as_normal"])

    def test_agents_implement_async_registry_protocol(self) -> None:
        logs = LogsEvidenceAgent(utcnow=lambda: NOW)
        knowledge = KnowledgeContextAgent(utcnow=lambda: NOW)
        self.assertTrue(inspect.iscoroutinefunction(logs.run))
        self.assertTrue(inspect.iscoroutinefunction(knowledge.run))
        logs_spec = AgentSpec(
            name=AgentName.LOGS_EVIDENCE,
            agent=logs,
            required=False,
            failure_policy=AgentFailurePolicy.CONTINUE,
        )
        knowledge_spec = AgentSpec(
            name=AgentName.KNOWLEDGE_CONTEXT,
            agent=knowledge,
            required=False,
            failure_policy=AgentFailurePolicy.CONTINUE,
        )
        self.assertEqual(logs_spec.retry_limit, 0)
        self.assertEqual(knowledge_spec.retry_limit, 0)

    def test_collected_times_are_timezone_aware(self) -> None:
        logs = EvidenceEnvelope.model_validate(
            run_agent(
                self.logs_agent(), AgentName.LOGS_EVIDENCE
            ).output["logs_evidence"]
        )
        knowledge = ContextEnvelope.model_validate(
            run_agent(
                self.knowledge_agent(), AgentName.KNOWLEDGE_CONTEXT
            ).output["knowledge_context"]
        )
        self.assertIsNotNone(logs.collected_at.utcoffset())
        self.assertIsNotNone(knowledge.collected_at.utcoffset())


if __name__ == "__main__":
    unittest.main()
