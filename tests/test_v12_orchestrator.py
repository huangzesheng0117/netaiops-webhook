from __future__ import annotations

import asyncio
import unittest
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from netaiops.v12.agent_registry import (
    AGENT_EXECUTION_ORDER,
    AgentFailurePolicy,
    AgentRegistry,
    AgentRegistryError,
    AgentSpec,
    DuplicateAgentRegistrationError,
    IncompleteAgentRegistryError,
)
from netaiops.v12.budget import DEFAULT_AGENT_TIMEOUT_SECONDS, BudgetPolicy
from netaiops.v12.contracts import ContractNotice
from netaiops.v12.execution_context import AgentInvocation, AgentOutcome
from netaiops.v12.orchestrator import DeterministicOrchestrator
from netaiops.v12.state_machine import OrchestrationState
from netaiops.v12.status import AgentName, AgentStatus


REQUEST_ID = "req-20260715-orchestrator"
FIXED_NOW = datetime(2026, 7, 15, 11, 0, tzinfo=timezone.utc)


class FakeClock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@dataclass
class Behavior:
    status: AgentStatus = AgentStatus.SUCCESS
    delay_seconds: float = 0.0
    advance_clock_seconds: float = 0.0
    raise_exception: bool = False
    invalid_result: bool = False


class FakeAgent:
    def __init__(
        self,
        name: AgentName,
        behavior: Behavior,
        calls: list[AgentName],
        invocations: dict[AgentName, AgentInvocation],
        clock: FakeClock | None = None,
    ) -> None:
        self.name = name
        self.behavior = behavior
        self.calls = calls
        self.invocations = invocations
        self.clock = clock
        self.call_count = 0

    async def run(self, invocation: AgentInvocation) -> AgentOutcome:
        self.call_count += 1
        self.calls.append(self.name)
        self.invocations[self.name] = invocation
        if self.behavior.delay_seconds:
            await asyncio.sleep(self.behavior.delay_seconds)
        if self.behavior.advance_clock_seconds and self.clock is not None:
            self.clock.advance(self.behavior.advance_clock_seconds)
        if self.behavior.raise_exception:
            raise RuntimeError("fake failure containing no production data")
        if self.behavior.invalid_result:
            return {"invalid": True}  # type: ignore[return-value]
        refs = ()
        output: dict[str, Any] = {}
        if self.behavior.status in {AgentStatus.SUCCESS, AgentStatus.PARTIAL}:
            refs = (f"agent://{REQUEST_ID}/output/{self.name.value}",)
            output = {"agent": self.name.value, "call_count": self.call_count}
        return AgentOutcome(
            status=self.behavior.status,
            output_refs=refs,
            output=output,
        )


class SyncAgent:
    def run(self, invocation: AgentInvocation) -> AgentOutcome:
        return AgentOutcome(status=AgentStatus.SUCCESS)


def build_registry(
    *,
    behaviors: dict[AgentName, Behavior] | None = None,
    policies: dict[AgentName, AgentFailurePolicy] | None = None,
    required: dict[AgentName, bool] | None = None,
    clock: FakeClock | None = None,
) -> tuple[
    AgentRegistry,
    dict[AgentName, FakeAgent],
    list[AgentName],
    dict[AgentName, AgentInvocation],
]:
    behaviors = behaviors or {}
    policies = policies or {}
    required = required or {}
    calls: list[AgentName] = []
    invocations: dict[AgentName, AgentInvocation] = {}
    agents: dict[AgentName, FakeAgent] = {}
    registry = AgentRegistry()
    for name in AGENT_EXECUTION_ORDER:
        agent = FakeAgent(
            name,
            behaviors.get(name, Behavior()),
            calls,
            invocations,
            clock,
        )
        agents[name] = agent
        registry.register(
            AgentSpec(
                name=name,
                agent=agent,
                required=required.get(name, True),
                failure_policy=policies.get(
                    name,
                    AgentFailurePolicy.FALLBACK_TO_LEGACY,
                ),
            )
        )
    return registry, agents, calls, invocations


def tiny_timeout_policy(name: AgentName, timeout: float) -> BudgetPolicy:
    mapping = dict(DEFAULT_AGENT_TIMEOUT_SECONDS)
    mapping[name] = timeout
    return BudgetPolicy(
        total_timeout_seconds=2.0,
        agent_timeout_seconds=mapping,
    )


class V12AgentRegistryTests(unittest.TestCase):
    def test_registry_resolves_frozen_order(self) -> None:
        registry, _, _, _ = build_registry()
        self.assertEqual(
            tuple(spec.name for spec in registry.ordered_specs()),
            AGENT_EXECUTION_ORDER,
        )

    def test_duplicate_registration_is_rejected(self) -> None:
        registry, agents, _, _ = build_registry()
        with self.assertRaises(DuplicateAgentRegistrationError):
            registry.register(
                AgentSpec(
                    name=AgentName.TRIAGE,
                    agent=agents[AgentName.TRIAGE],
                )
            )

    def test_incomplete_registry_is_rejected(self) -> None:
        registry = AgentRegistry()
        calls: list[AgentName] = []
        invocations: dict[AgentName, AgentInvocation] = {}
        registry.register(
            AgentSpec(
                name=AgentName.TRIAGE,
                agent=FakeAgent(
                    AgentName.TRIAGE,
                    Behavior(),
                    calls,
                    invocations,
                ),
            )
        )
        with self.assertRaises(IncompleteAgentRegistryError):
            registry.validate_complete()

    def test_retry_limit_is_frozen_at_zero(self) -> None:
        calls: list[AgentName] = []
        invocations: dict[AgentName, AgentInvocation] = {}
        with self.assertRaises(AgentRegistryError):
            AgentSpec(
                name=AgentName.TRIAGE,
                agent=FakeAgent(
                    AgentName.TRIAGE,
                    Behavior(),
                    calls,
                    invocations,
                ),
                retry_limit=1,
            )

    def test_sync_agent_is_rejected_for_enforceable_timeout(self) -> None:
        with self.assertRaises(AgentRegistryError):
            AgentSpec(name=AgentName.TRIAGE, agent=SyncAgent())  # type: ignore[arg-type]


class V12OrchestratorTests(unittest.TestCase):
    def make_orchestrator(
        self,
        registry: AgentRegistry,
        *,
        budget_policy: BudgetPolicy | None = None,
        fail_open_to_legacy: bool = True,
        clock: FakeClock | None = None,
    ) -> DeterministicOrchestrator:
        return DeterministicOrchestrator(
            registry,
            budget_policy=budget_policy,
            fail_open_to_legacy=fail_open_to_legacy,
            monotonic_clock=clock or FakeClock(),
            utcnow=lambda: FIXED_NOW,
        )

    def test_all_success_runs_once_in_fixed_order(self) -> None:
        registry, agents, calls, _ = build_registry()
        result = self.make_orchestrator(registry).run(REQUEST_ID)
        self.assertEqual(calls, list(AGENT_EXECUTION_ORDER))
        self.assertEqual(result.final_state, OrchestrationState.COMPLETED)
        self.assertFalse(result.fallback_to_legacy)
        self.assertIsNone(result.stop_reason)
        self.assertEqual(len(result.agent_runs), len(AGENT_EXECUTION_ORDER))
        for name, agent in agents.items():
            self.assertEqual(agent.call_count, 1, name)

    def test_success_state_history_is_deterministic(self) -> None:
        registry, _, _, _ = build_registry()
        result = self.make_orchestrator(registry).run(REQUEST_ID)
        self.assertEqual(
            result.state_history,
            (
                OrchestrationState.INITIALIZED,
                OrchestrationState.TRIAGE,
                OrchestrationState.PLANNING,
                OrchestrationState.EVIDENCE_COLLECTION,
                OrchestrationState.EVIDENCE_JUDGING,
                OrchestrationState.RCA,
                OrchestrationState.REPORTING,
                OrchestrationState.COMPLETED,
            ),
        )

    def test_optional_not_available_continues(self) -> None:
        name = AgentName.LOGS_EVIDENCE
        registry, agents, calls, _ = build_registry(
            behaviors={name: Behavior(status=AgentStatus.NOT_AVAILABLE)},
            policies={name: AgentFailurePolicy.CONTINUE},
            required={name: False},
        )
        result = self.make_orchestrator(registry).run(REQUEST_ID)
        self.assertEqual(result.final_state, OrchestrationState.COMPLETED)
        self.assertEqual(calls, list(AGENT_EXECUTION_ORDER))
        self.assertEqual(agents[name].call_count, 1)
        run = next(item for item in result.agent_runs if item.agent_name == name)
        self.assertEqual(run.status, AgentStatus.NOT_AVAILABLE)

    def test_optional_failure_is_isolated_and_later_agents_run(self) -> None:
        name = AgentName.LOGS_EVIDENCE
        registry, _, calls, _ = build_registry(
            behaviors={name: Behavior(raise_exception=True)},
            policies={name: AgentFailurePolicy.CONTINUE},
            required={name: False},
        )
        result = self.make_orchestrator(registry).run(REQUEST_ID)
        self.assertEqual(result.final_state, OrchestrationState.COMPLETED)
        self.assertIn(AgentName.NOTIFICATION_REPORT, calls)
        run = next(item for item in result.agent_runs if item.agent_name == name)
        self.assertEqual(run.status, AgentStatus.FAILED)
        self.assertEqual(run.errors[0].code, "agent_exception")
        self.assertEqual(run.errors[0].details["exception_type"], "RuntimeError")

    def test_required_failure_falls_back_and_skips_remaining(self) -> None:
        name = AgentName.STATIC_PLANNER
        registry, agents, calls, _ = build_registry(
            behaviors={name: Behavior(status=AgentStatus.FAILED)}
        )
        result = self.make_orchestrator(registry).run(REQUEST_ID)
        self.assertEqual(result.final_state, OrchestrationState.FALLBACK_TO_LEGACY)
        self.assertTrue(result.fallback_to_legacy)
        self.assertEqual(result.stop_reason, "static_planner_failed")
        self.assertEqual(calls, [AgentName.TRIAGE, AgentName.STATIC_PLANNER])
        self.assertEqual(len(result.agent_runs), len(AGENT_EXECUTION_ORDER))
        self.assertEqual(agents[AgentName.METRICS_EVIDENCE].call_count, 0)
        later = result.agent_runs[2:]
        self.assertTrue(all(item.status == AgentStatus.SKIPPED for item in later))
        self.assertTrue(
            all(item.warnings[0].code == "static_planner_failed" for item in later)
        )

    def test_required_not_available_falls_back(self) -> None:
        name = AgentName.METRICS_EVIDENCE
        registry, _, _, _ = build_registry(
            behaviors={name: Behavior(status=AgentStatus.NOT_AVAILABLE)}
        )
        result = self.make_orchestrator(registry).run(REQUEST_ID)
        self.assertEqual(result.final_state, OrchestrationState.FALLBACK_TO_LEGACY)
        self.assertEqual(result.stop_reason, "metrics_evidence_not_available")

    def test_fail_open_false_uses_failed_terminal_state(self) -> None:
        name = AgentName.TRIAGE
        registry, _, _, _ = build_registry(
            behaviors={name: Behavior(status=AgentStatus.FAILED)}
        )
        result = self.make_orchestrator(
            registry,
            fail_open_to_legacy=False,
        ).run(REQUEST_ID)
        self.assertEqual(result.final_state, OrchestrationState.FAILED)
        self.assertFalse(result.fallback_to_legacy)

    def test_stop_policy_does_not_fallback(self) -> None:
        name = AgentName.TRIAGE
        registry, _, _, _ = build_registry(
            behaviors={name: Behavior(status=AgentStatus.FAILED)},
            policies={name: AgentFailurePolicy.STOP},
        )
        result = self.make_orchestrator(registry).run(REQUEST_ID)
        self.assertEqual(result.final_state, OrchestrationState.FAILED)
        self.assertFalse(result.fallback_to_legacy)

    def test_agent_timeout_is_recorded_and_not_retried(self) -> None:
        name = AgentName.TRIAGE
        registry, agents, _, _ = build_registry(
            behaviors={name: Behavior(delay_seconds=0.05)}
        )
        result = self.make_orchestrator(
            registry,
            budget_policy=tiny_timeout_policy(name, 0.005),
        ).run(REQUEST_ID)
        self.assertEqual(result.final_state, OrchestrationState.FALLBACK_TO_LEGACY)
        self.assertEqual(agents[name].call_count, 1)
        run = result.agent_runs[0]
        self.assertEqual(run.status, AgentStatus.FAILED)
        self.assertEqual(run.errors[0].code, "agent_timeout")

    def test_total_budget_exhaustion_stops_before_next_agent(self) -> None:
        clock = FakeClock()
        registry, agents, calls, _ = build_registry(
            behaviors={
                AgentName.TRIAGE: Behavior(advance_clock_seconds=1.5),
            },
            clock=clock,
        )
        policy = BudgetPolicy(total_timeout_seconds=1.0)
        result = self.make_orchestrator(
            registry,
            budget_policy=policy,
            clock=clock,
        ).run(REQUEST_ID)
        self.assertEqual(result.final_state, OrchestrationState.FALLBACK_TO_LEGACY)
        self.assertEqual(result.stop_reason, "total_budget_exhausted")
        self.assertEqual(calls, [AgentName.TRIAGE])
        self.assertEqual(agents[AgentName.STATIC_PLANNER].call_count, 0)
        self.assertEqual(result.agent_runs[1].status, AgentStatus.SKIPPED)
        self.assertEqual(
            result.agent_runs[1].warnings[0].code,
            "total_budget_exhausted",
        )

    def test_invalid_agent_result_is_normalized_to_failure(self) -> None:
        name = AgentName.TRIAGE
        registry, _, _, _ = build_registry(
            behaviors={name: Behavior(invalid_result=True)}
        )
        result = self.make_orchestrator(registry).run(REQUEST_ID)
        run = result.agent_runs[0]
        self.assertEqual(run.status, AgentStatus.FAILED)
        self.assertEqual(run.errors[0].code, "agent_result_invalid")
        self.assertEqual(run.errors[0].details["result_type"], "dict")

    def test_prior_outputs_are_passed_forward_without_orchestrator_reference(self) -> None:
        registry, _, _, invocations = build_registry()
        self.make_orchestrator(registry).run(REQUEST_ID)
        planner = invocations[AgentName.STATIC_PLANNER]
        self.assertIn(AgentName.TRIAGE.value, planner.prior_outputs)
        self.assertEqual(
            planner.prior_output_refs,
            (f"agent://{REQUEST_ID}/output/triage",),
        )
        self.assertFalse(hasattr(planner, "orchestrator"))
        self.assertFalse(hasattr(planner, "registry"))

    def test_every_run_record_is_aware_and_request_scoped(self) -> None:
        registry, _, _, _ = build_registry()
        result = self.make_orchestrator(registry).run(REQUEST_ID)
        for run in result.agent_runs:
            self.assertEqual(run.request_id, REQUEST_ID)
            self.assertIsNotNone(run.started_at.utcoffset())
            self.assertIsNotNone(run.finished_at.utcoffset())

    def test_outputs_are_keyed_by_agent_name(self) -> None:
        registry, _, _, _ = build_registry()
        result = self.make_orchestrator(registry).run(REQUEST_ID)
        self.assertEqual(set(result.outputs), {name.value for name in AGENT_EXECUTION_ORDER})
        self.assertEqual(result.outputs["triage"]["agent"], "triage")

    def test_missing_registry_fails_before_any_agent_call(self) -> None:
        registry = AgentRegistry()
        calls: list[AgentName] = []
        invocations: dict[AgentName, AgentInvocation] = {}
        registry.register(
            AgentSpec(
                name=AgentName.TRIAGE,
                agent=FakeAgent(
                    AgentName.TRIAGE,
                    Behavior(),
                    calls,
                    invocations,
                ),
            )
        )
        with self.assertRaises(IncompleteAgentRegistryError):
            self.make_orchestrator(registry).run(REQUEST_ID)
        self.assertEqual(calls, [])

    def test_utcnow_provider_must_be_timezone_aware(self) -> None:
        registry, _, _, _ = build_registry()
        orchestrator = DeterministicOrchestrator(
            registry,
            monotonic_clock=FakeClock(),
            utcnow=lambda: datetime(2026, 7, 15, 11, 0),
        )
        with self.assertRaises(ValueError):
            orchestrator.run(REQUEST_ID)

    def test_run_wrapper_rejects_active_event_loop(self) -> None:
        registry, _, _, _ = build_registry()
        orchestrator = self.make_orchestrator(registry)

        async def invoke() -> None:
            with self.assertRaises(RuntimeError):
                orchestrator.run(REQUEST_ID)

        asyncio.run(invoke())

    def test_structured_notice_can_be_returned_by_agent(self) -> None:
        class WarningAgent(FakeAgent):
            async def run(self, invocation: AgentInvocation) -> AgentOutcome:
                base = await super().run(invocation)
                return AgentOutcome(
                    status=base.status,
                    output_refs=base.output_refs,
                    output=base.output,
                    warnings=(
                        ContractNotice(
                            code="fixture_warning",
                            message="deterministic warning",
                        ),
                    ),
                )

        registry, agents, _, _ = build_registry()
        spec = registry.get(AgentName.TRIAGE)
        warning_agent = WarningAgent(
            AgentName.TRIAGE,
            Behavior(),
            [],
            {},
        )
        replacement = AgentRegistry()
        for item in registry.ordered_specs():
            replacement.register(
                AgentSpec(
                    name=item.name,
                    agent=warning_agent if item.name == AgentName.TRIAGE else item.agent,
                    required=item.required,
                    failure_policy=item.failure_policy,
                )
            )
        result = self.make_orchestrator(replacement).run(REQUEST_ID)
        self.assertEqual(result.agent_runs[0].warnings[0].code, "fixture_warning")
        self.assertEqual(agents[AgentName.TRIAGE].call_count, 0)
        self.assertEqual(spec.name, AgentName.TRIAGE)


if __name__ == "__main__":
    unittest.main()
