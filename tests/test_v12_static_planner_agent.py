from __future__ import annotations

import asyncio
import json
import unittest
from pathlib import Path
from types import MappingProxyType
from typing import Any
from unittest.mock import patch

from netaiops.v12.adapters.playbook_adapter import (
    PlaybookAdapter,
    PlaybookResolution,
)
from netaiops.v12.adapters.skill_adapter import (
    SkillAdapter,
    SkillResolution,
)
from netaiops.v12.agents.static_planner_agent import (
    StaticPlannerAgent,
    _capability_groups,
    _legacy_event,
)
from netaiops.v12.contracts import EvidencePlan, UnifiedAlertEvent
from netaiops.v12.execution_context import AgentInvocation, AgentOutcome
from netaiops.v12.state_machine import OrchestrationState
from netaiops.v12.status import (
    AgentName,
    AgentStatus,
    EvidenceSource,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = PROJECT_ROOT / "tests/fixtures/v12/plans"
EXPECTED_FIXTURES = {
    "cisco_interface_status.json",
    "cisco_interface_utilization.json",
    "cisco_traffic_anomaly.json",
    "cisco_hardware.json",
    "cisco_bgp_neighbor.json",
    "f5_pool_member.json",
    "fortigate_cpu.json",
    "dci_traffic_drop.json",
    "generic_no_assets.json",
}


def load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))


def invocation_for(payload: dict[str, Any]) -> AgentInvocation:
    event = payload["unified_event"]
    return AgentInvocation(
        request_id=event["request_id"],
        agent_name=AgentName.STATIC_PLANNER,
        orchestration_state=OrchestrationState.PLANNING,
        prior_output_refs=(
            f"event://{event['request_id']}/unified_alert/{event['event_id']}",
        ),
        prior_outputs={
            AgentName.TRIAGE.value: MappingProxyType(
                {
                    "unified_event": event,
                    "event_key": event["event_key"],
                    "correlation_hints": event["correlation_hints"],
                    "aggregation_performed": False,
                }
            )
        },
    )


def run_fixture(
    name: str,
    *,
    agent: StaticPlannerAgent | None = None,
) -> tuple[dict[str, Any], AgentOutcome]:
    payload = load_fixture(name)
    outcome = asyncio.run(
        (agent or StaticPlannerAgent()).run(invocation_for(payload))
    )
    return payload, outcome


class FakeSkillAdapter:
    def __init__(self, *, matched: bool = True) -> None:
        self.matched = matched
        self.calls: list[str] = []

    def resolve(self, family: str) -> SkillResolution:
        self.calls.append(family)
        return SkillResolution(
            matched=self.matched,
            family=family,
            skill_name="fake-skill" if self.matched else None,
            stage="v9" if self.matched else None,
            schema_generation="current" if self.matched else None,
            risk_level="readonly" if self.matched else None,
            validation_verdict="pass" if self.matched else "not_found",
            required_facts=("device_state",) if self.matched else (),
            preferred_facts=("metric_window",) if self.matched else (),
            manual_review_conditions=(),
            warnings=() if self.matched else ("skill_not_found",),
        )


class FakePlaybookAdapter:
    def __init__(
        self,
        *,
        matched: bool = True,
        readonly_only: bool = True,
        policy_allowed: bool = True,
    ) -> None:
        self.matched = matched
        self.readonly_only = readonly_only
        self.policy_allowed = policy_allowed
        self.resolve_calls = 0
        self.safety_calls = 0

    def resolve(self, event, classification) -> PlaybookResolution:
        self.resolve_calls += 1
        raw = {
            "playbook_id": "fake-playbook",
            "execution": {
                "readonly_only": self.readonly_only,
                "auto_execute_allowed": self.policy_allowed,
                "max_commands": 5,
            },
        }
        return PlaybookResolution(
            matched=self.matched,
            playbook_id="fake-playbook" if self.matched else None,
            family=classification.get("family"),
            skill_name="fake-skill" if self.matched else None,
            readonly_only=self.readonly_only,
            auto_execute_allowed=self.policy_allowed,
            max_commands=5 if self.matched else 0,
            command_template_count=2 if self.matched else 0,
            prometheus_evidence_enabled=True,
            prometheus_profile="fixture",
            prometheus_query_names=("metric_a",),
            raw_playbook=MappingProxyType(raw if self.matched else {}),
        )

    def evaluate_safety(self, **kwargs) -> dict[str, Any]:
        self.safety_calls += 1
        return {
            "auto_confirm_allowed": self.policy_allowed,
            "reasons": [] if self.policy_allowed else ["fixture_policy_blocked"],
            "policy_summary": (
                "allowed" if self.policy_allowed else "blocked"
            ),
            "checked_items": {},
            "capability_readonly_only": True,
            "playbook_readonly_only": self.readonly_only,
            "command_generation_performed": False,
        }


class StaticPlannerFixtureTests(unittest.TestCase):
    def test_fixture_set_is_complete(self) -> None:
        actual = {path.name for path in FIXTURE_ROOT.glob("*.json")}
        self.assertEqual(actual, EXPECTED_FIXTURES)

    def test_all_fixtures_generate_valid_evidence_plan(self) -> None:
        for name in sorted(EXPECTED_FIXTURES):
            with self.subTest(name=name):
                payload, outcome = run_fixture(name)
                self.assertIn(
                    outcome.status,
                    {AgentStatus.SUCCESS, AgentStatus.PARTIAL},
                )
                plan = EvidencePlan.model_validate(
                    outcome.output["evidence_plan"]
                )
                self.assertEqual(
                    plan.request_id,
                    payload["unified_event"]["request_id"],
                )
                self.assertEqual(plan.planner_mode, "deterministic")
                self.assertTrue(plan.readonly_only)

    def test_fixture_family_is_preserved(self) -> None:
        for name in sorted(EXPECTED_FIXTURES):
            with self.subTest(name=name):
                payload, outcome = run_fixture(name)
                self.assertEqual(
                    outcome.output["evidence_plan"]["family"],
                    payload["expect"]["family"],
                )

    def test_required_sources_include_fixture_expectation(self) -> None:
        for name in sorted(EXPECTED_FIXTURES):
            with self.subTest(name=name):
                payload, outcome = run_fixture(name)
                required = {
                    item["source"]
                    for item in outcome.output["evidence_plan"]["sources"]
                    if item["required"]
                }
                self.assertTrue(
                    set(payload["expect"]["must_require"]).issubset(required)
                )

    def test_source_order_is_frozen(self) -> None:
        _, outcome = run_fixture("cisco_interface_status.json")
        self.assertEqual(
            [
                item["source"]
                for item in outcome.output["evidence_plan"]["sources"]
            ],
            ["metrics", "device", "logs", "knowledge"],
        )

    def test_logs_and_knowledge_are_optional_placeholders(self) -> None:
        _, outcome = run_fixture("cisco_hardware.json")
        sources = {
            item["source"]: item
            for item in outcome.output["evidence_plan"]["sources"]
        }
        self.assertFalse(sources["logs"]["required"])
        self.assertEqual(
            sources["logs"]["constraints"]["reason"],
            "logs_evidence_not_approved",
        )
        self.assertFalse(sources["knowledge"]["required"])
        self.assertEqual(
            sources["knowledge"]["constraints"]["reason"],
            "local_knowledge_base_not_built",
        )

    def test_plan_is_deterministic_for_same_input(self) -> None:
        payload = load_fixture("cisco_bgp_neighbor.json")
        agent = StaticPlannerAgent()
        first = asyncio.run(agent.run(invocation_for(payload)))
        second = asyncio.run(agent.run(invocation_for(payload)))
        self.assertEqual(
            first.output["evidence_plan"],
            second.output["evidence_plan"],
        )
        self.assertEqual(first.output_refs, second.output_refs)

    def test_plan_ref_uses_current_request(self) -> None:
        payload, outcome = run_fixture("f5_pool_member.json")
        request_id = payload["unified_event"]["request_id"]
        self.assertTrue(
            outcome.output_refs[0].startswith(
                f"plan://{request_id}/evidence_plan/static-"
            )
        )

    def test_output_contains_no_commands_promql_or_dsl(self) -> None:
        _, outcome = run_fixture("cisco_traffic_anomaly.json")
        output = dict(outcome.output)

        self.assertFalse(output["command_generation_performed"])
        self.assertFalse(output["promql_generation_performed"])
        self.assertFalse(output["dsl_generation_performed"])

        sources = {
            item["source"]: item
            for item in output["evidence_plan"]["sources"]
        }

        self.assertFalse(
            sources["metrics"]["constraints"]["promql_generation_allowed"]
        )
        self.assertFalse(
            sources["device"]["constraints"]["command_generation_allowed"]
        )
        self.assertFalse(
            sources["logs"]["constraints"]["dsl_generation_allowed"]
        )

        forbidden_keys = {
            "command",
            "commands",
            "command_templates",
            "promql",
            "dsl",
            "elasticsearch_dsl",
        }

        def assert_no_generated_artifacts(value) -> None:
            if isinstance(value, dict):
                self.assertFalse(forbidden_keys.intersection(value))
                for item in value.values():
                    assert_no_generated_artifacts(item)
            elif isinstance(value, list):
                for item in value:
                    assert_no_generated_artifacts(item)

        assert_no_generated_artifacts(output)

    def test_public_playbook_metadata_does_not_expose_templates(self) -> None:
        _, outcome = run_fixture("dci_traffic_drop.json")
        self.assertNotIn("commands", outcome.output["playbook"])
        self.assertNotIn("execution", outcome.output["playbook"])


class StaticPlannerBoundaryTests(unittest.TestCase):
    def test_wrong_agent_name_returns_failed(self) -> None:
        payload = load_fixture("cisco_interface_status.json")
        invocation = invocation_for(payload)
        wrong = AgentInvocation(
            request_id=invocation.request_id,
            agent_name=AgentName.TRIAGE,
            orchestration_state=OrchestrationState.PLANNING,
            prior_output_refs=invocation.prior_output_refs,
            prior_outputs=invocation.prior_outputs,
        )
        outcome = asyncio.run(StaticPlannerAgent().run(wrong))
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_missing_triage_output_returns_failed(self) -> None:
        invocation = AgentInvocation(
            request_id="planner-missing-triage",
            agent_name=AgentName.STATIC_PLANNER,
            orchestration_state=OrchestrationState.PLANNING,
            prior_output_refs=(),
            prior_outputs={},
        )
        outcome = asyncio.run(StaticPlannerAgent().run(invocation))
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_invalid_unified_event_returns_failed(self) -> None:
        invocation = AgentInvocation(
            request_id="planner-invalid-event",
            agent_name=AgentName.STATIC_PLANNER,
            orchestration_state=OrchestrationState.PLANNING,
            prior_output_refs=(),
            prior_outputs={
                "triage": MappingProxyType(
                    {"unified_event": {"request_id": "planner-invalid-event"}}
                )
            },
        )
        outcome = asyncio.run(StaticPlannerAgent().run(invocation))
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_request_id_mismatch_returns_failed(self) -> None:
        payload = load_fixture("cisco_interface_status.json")
        invocation = invocation_for(payload)
        mismatch = AgentInvocation(
            request_id="different-request",
            agent_name=invocation.agent_name,
            orchestration_state=invocation.orchestration_state,
            prior_output_refs=(),
            prior_outputs=invocation.prior_outputs,
        )
        outcome = asyncio.run(StaticPlannerAgent().run(mismatch))
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_readonly_policy_rejection_returns_failed(self) -> None:
        agent = StaticPlannerAgent(
            skill_adapter=FakeSkillAdapter(),
            playbook_adapter=FakePlaybookAdapter(readonly_only=False),
        )
        _, outcome = run_fixture(
            "cisco_interface_status.json",
            agent=agent,
        )
        self.assertEqual(outcome.status, AgentStatus.FAILED)
        self.assertFalse(outcome.output)

    def test_missing_skill_returns_partial_plan(self) -> None:
        agent = StaticPlannerAgent(
            skill_adapter=FakeSkillAdapter(matched=False),
            playbook_adapter=FakePlaybookAdapter(),
        )
        _, outcome = run_fixture(
            "cisco_interface_status.json",
            agent=agent,
        )
        self.assertEqual(outcome.status, AgentStatus.PARTIAL)
        EvidencePlan.model_validate(outcome.output["evidence_plan"])

    def test_missing_playbook_returns_partial_plan(self) -> None:
        agent = StaticPlannerAgent(
            skill_adapter=FakeSkillAdapter(),
            playbook_adapter=FakePlaybookAdapter(matched=False),
        )
        _, outcome = run_fixture(
            "cisco_interface_status.json",
            agent=agent,
        )
        self.assertEqual(outcome.status, AgentStatus.PARTIAL)
        self.assertIsNone(
            outcome.output["evidence_plan"]["selected_playbook"]
        )

    def test_safety_policy_block_returns_partial_readonly_plan(self) -> None:
        agent = StaticPlannerAgent(
            skill_adapter=FakeSkillAdapter(),
            playbook_adapter=FakePlaybookAdapter(policy_allowed=False),
        )
        _, outcome = run_fixture(
            "cisco_interface_status.json",
            agent=agent,
        )
        self.assertEqual(outcome.status, AgentStatus.PARTIAL)
        self.assertTrue(outcome.output["evidence_plan"]["readonly_only"])
        self.assertFalse(
            outcome.output["safety_policy"]["auto_confirm_allowed"]
        )

    def test_adapters_are_called_once(self) -> None:
        skill = FakeSkillAdapter()
        playbook = FakePlaybookAdapter()
        agent = StaticPlannerAgent(
            skill_adapter=skill,
            playbook_adapter=playbook,
        )
        _, outcome = run_fixture(
            "cisco_interface_status.json",
            agent=agent,
        )
        self.assertIn(outcome.status, {AgentStatus.SUCCESS, AgentStatus.PARTIAL})
        self.assertEqual(len(skill.calls), 1)
        self.assertEqual(playbook.resolve_calls, 1)
        self.assertEqual(playbook.safety_calls, 1)

    def test_orchestrator_contract_compatibility(self) -> None:
        payload = load_fixture("cisco_interface_status.json")
        outcome = asyncio.run(
            StaticPlannerAgent().run(invocation_for(payload))
        )
        self.assertIsInstance(outcome, AgentOutcome)
        self.assertFalse(outcome.external_calls)

    def test_source_has_no_external_or_llm_imports(self) -> None:
        paths = (
            PROJECT_ROOT / "netaiops/v12/agents/static_planner_agent.py",
            PROJECT_ROOT / "netaiops/v12/adapters/skill_adapter.py",
            PROJECT_ROOT / "netaiops/v12/adapters/playbook_adapter.py",
        )
        forbidden = (
            "requests",
            "httpx",
            "socket",
            "subprocess",
            "capability_planner",
            "refine_capability_plan",
            "build_execution_candidates_from_playbook",
            "resolve_execution_candidates",
            "openai",
        )
        for path in paths:
            text = path.read_text(encoding="utf-8").lower()
            for token in forbidden:
                self.assertNotIn(token.lower(), text, (path, token))

    def test_dynamic_source_selection_is_false(self) -> None:
        _, outcome = run_fixture("cisco_hardware.json")
        self.assertFalse(outcome.output["dynamic_source_selection"])

    def test_all_source_capability_ids_are_unique(self) -> None:
        _, outcome = run_fixture("cisco_interface_utilization.json")
        for source in outcome.output["evidence_plan"]["sources"]:
            ids = source["capability_ids"]
            self.assertEqual(len(ids), len(set(ids)))


class StaticPlannerAdapterTests(unittest.TestCase):
    def test_skill_adapter_reuses_current_registry(self) -> None:
        fake_skill = {
            "name": "fixture-skill",
            "stage": "v9",
            "schema_generation": "current",
            "metadata": {"risk_level": "readonly"},
            "files": {},
        }
        with patch(
            "netaiops.v12.adapters.skill_adapter.get_skill_by_family",
            return_value=fake_skill,
        ) as get_skill, patch(
            "netaiops.v12.adapters.skill_adapter.validate_skill_package",
            return_value={
                "verdict": "pass",
                "warnings": [],
                "violations": [],
            },
        ):
            result = SkillAdapter(PROJECT_ROOT).resolve("fixture-family")
        get_skill.assert_called_once()
        self.assertTrue(result.matched)
        self.assertEqual(result.validation_verdict, "pass")

    def test_skill_adapter_handles_missing_skill(self) -> None:
        with patch(
            "netaiops.v12.adapters.skill_adapter.get_skill_by_family",
            return_value=None,
        ):
            result = SkillAdapter(PROJECT_ROOT).resolve("missing-family")
        self.assertFalse(result.matched)
        self.assertEqual(result.validation_verdict, "not_found")

    def test_playbook_adapter_reuses_current_loader(self) -> None:
        playbook = {
            "playbook_id": "fixture-playbook",
            "family": "fixture-family",
            "skill_name": "fixture-skill",
            "execution": {
                "readonly_only": True,
                "auto_execute_allowed": True,
                "max_commands": 3,
                "commands": ["show clock"],
            },
        }
        with patch(
            "netaiops.v12.adapters.playbook_adapter.find_best_playbook",
            return_value=playbook,
        ) as finder:
            result = PlaybookAdapter().resolve(
                {"source": "alertmanager"},
                {"family": "fixture-family"},
            )
        finder.assert_called_once()
        self.assertTrue(result.matched)
        self.assertEqual(result.command_template_count, 1)
        self.assertNotIn("commands", result.public_dict())

    def test_playbook_adapter_handles_missing_playbook(self) -> None:
        with patch(
            "netaiops.v12.adapters.playbook_adapter.find_best_playbook",
            return_value=None,
        ):
            result = PlaybookAdapter().resolve({}, {})
        self.assertFalse(result.matched)
        self.assertTrue(result.readonly_only)

    def test_safety_adapter_reuses_current_policy(self) -> None:
        resolution = PlaybookResolution(
            matched=False,
            playbook_id=None,
            family=None,
            skill_name=None,
            readonly_only=True,
            auto_execute_allowed=False,
            max_commands=0,
            command_template_count=0,
            prometheus_evidence_enabled=False,
            prometheus_profile=None,
            prometheus_query_names=(),
            raw_playbook=MappingProxyType({}),
        )
        with patch(
            "netaiops.v12.adapters.playbook_adapter."
            "evaluate_auto_confirm_policy",
            return_value={
                "auto_confirm_allowed": False,
                "reasons": ["fixture"],
                "policy_summary": "blocked",
                "checked_items": {},
            },
        ) as policy:
            result = PlaybookAdapter().evaluate_safety(
                event={"source": "alertmanager"},
                family_result={"target_scope": {}},
                classification={},
                capability_plan={"readonly_only": True},
                playbook=resolution,
            )
        policy.assert_called_once()
        self.assertFalse(result["auto_confirm_allowed"])
        self.assertFalse(result["command_generation_performed"])

    def test_legacy_event_preserves_family_and_target(self) -> None:
        payload = load_fixture("cisco_bgp_neighbor.json")
        event = UnifiedAlertEvent.model_validate(
            payload["unified_event"]
        )
        legacy = _legacy_event(event)
        self.assertEqual(legacy["family"], "bgp_neighbor_down")
        self.assertEqual(legacy["peer_ip"], "10.10.10.2")
        self.assertEqual(legacy["source"], "alertmanager")

    def test_capability_groups_are_deterministic(self) -> None:
        plan = {
            "selected_capabilities": [
                {"capability": "query_prometheus_metric_window"},
                {"capability": "show_interface_detail"},
                {"capability": "query_elastic_related_logs"},
                {"capability": "show_interface_detail"},
            ]
        }
        groups = _capability_groups(plan)
        self.assertEqual(
            groups[EvidenceSource.METRICS],
            ["query_prometheus_metric_window"],
        )
        self.assertEqual(
            groups[EvidenceSource.DEVICE],
            ["show_interface_detail"],
        )
        self.assertEqual(
            groups[EvidenceSource.LOGS],
            ["query_elastic_related_logs"],
        )


if __name__ == "__main__":
    unittest.main()
