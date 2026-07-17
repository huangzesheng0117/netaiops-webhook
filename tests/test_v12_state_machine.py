from __future__ import annotations

import unittest
from datetime import datetime, timezone
from types import MappingProxyType

from netaiops.v12.agent_registry import AGENT_EXECUTION_ORDER
from netaiops.v12.budget import (
    DEFAULT_AGENT_TIMEOUT_SECONDS,
    DEFAULT_TOTAL_TIMEOUT_SECONDS,
    BudgetConfigurationError,
    BudgetPolicy,
    ExecutionBudget,
    ExecutionBudgetExhausted,
)
from netaiops.v12.contracts import AgentRunRecord
from netaiops.v12.execution_context import (
    AgentOutcome,
    DuplicateAgentExecutionError,
    ExecutionContext,
    ExecutionContextError,
)
from netaiops.v12.state_machine import (
    InvalidStateTransitionError,
    OrchestrationState,
    OrchestrationStateMachine,
)
from netaiops.v12.status import AgentName, AgentStatus


REQUEST_ID = "req-20260715-batch-c"
NOW = datetime(2026, 7, 15, 10, 0, tzinfo=timezone.utc)


class FakeClock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def make_run(
    name: AgentName,
    *,
    request_id: str = REQUEST_ID,
    status: AgentStatus = AgentStatus.SUCCESS,
) -> AgentRunRecord:
    return AgentRunRecord(
        schema_version="v12.1",
        request_id=request_id,
        agent_name=name,
        status=status,
        started_at=NOW,
        finished_at=NOW,
        duration_ms=0,
    )


class V12StateMachineTests(unittest.TestCase):
    def test_execution_order_is_frozen(self) -> None:
        self.assertEqual(
            AGENT_EXECUTION_ORDER,
            (
                AgentName.TRIAGE,
                AgentName.STATIC_PLANNER,
                AgentName.METRICS_EVIDENCE,
                AgentName.DEVICE_EVIDENCE,
                AgentName.LOGS_EVIDENCE,
                AgentName.KNOWLEDGE_CONTEXT,
                AgentName.EVIDENCE_JUDGE,
                AgentName.RCA,
                AgentName.NOTIFICATION_REPORT,
            ),
        )

    def test_initial_state_and_history(self) -> None:
        machine = OrchestrationStateMachine()
        self.assertEqual(machine.state, OrchestrationState.INITIALIZED)
        self.assertEqual(machine.history, (OrchestrationState.INITIALIZED,))
        self.assertFalse(machine.terminal)

    def test_full_agent_sequence_reaches_completed(self) -> None:
        machine = OrchestrationStateMachine()
        for name in AGENT_EXECUTION_ORDER:
            machine.advance_for_agent(name)
        machine.complete()
        self.assertEqual(machine.state, OrchestrationState.COMPLETED)
        self.assertEqual(
            machine.history,
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

    def test_evidence_agents_do_not_duplicate_state_history(self) -> None:
        machine = OrchestrationStateMachine()
        machine.advance_for_agent(AgentName.TRIAGE)
        machine.advance_for_agent(AgentName.STATIC_PLANNER)
        for name in (
            AgentName.METRICS_EVIDENCE,
            AgentName.DEVICE_EVIDENCE,
            AgentName.LOGS_EVIDENCE,
            AgentName.KNOWLEDGE_CONTEXT,
        ):
            machine.advance_for_agent(name)
        self.assertEqual(
            machine.history.count(OrchestrationState.EVIDENCE_COLLECTION),
            1,
        )

    def test_invalid_direct_transition_is_rejected(self) -> None:
        machine = OrchestrationStateMachine()
        with self.assertRaises(InvalidStateTransitionError):
            machine.transition(OrchestrationState.PLANNING)

    def test_backward_transition_is_rejected(self) -> None:
        machine = OrchestrationStateMachine()
        machine.advance_for_agent(AgentName.TRIAGE)
        with self.assertRaises(InvalidStateTransitionError):
            machine.transition(OrchestrationState.INITIALIZED)

    def test_complete_before_reporting_is_rejected(self) -> None:
        machine = OrchestrationStateMachine()
        machine.advance_for_agent(AgentName.TRIAGE)
        with self.assertRaises(InvalidStateTransitionError):
            machine.complete()

    def test_fallback_is_terminal(self) -> None:
        machine = OrchestrationStateMachine()
        machine.advance_for_agent(AgentName.TRIAGE)
        machine.fallback_to_legacy()
        self.assertTrue(machine.terminal)
        self.assertEqual(machine.state, OrchestrationState.FALLBACK_TO_LEGACY)
        with self.assertRaises(InvalidStateTransitionError):
            machine.advance_for_agent(AgentName.STATIC_PLANNER)

    def test_failed_is_terminal(self) -> None:
        machine = OrchestrationStateMachine()
        machine.advance_for_agent(AgentName.TRIAGE)
        machine.fail()
        self.assertTrue(machine.terminal)
        self.assertEqual(machine.state, OrchestrationState.FAILED)
        with self.assertRaises(InvalidStateTransitionError):
            machine.complete()


class V12BudgetTests(unittest.TestCase):
    def test_default_budget_matches_batch_a_flags(self) -> None:
        policy = BudgetPolicy()
        self.assertEqual(policy.total_timeout_seconds, DEFAULT_TOTAL_TIMEOUT_SECONDS)
        self.assertEqual(policy.agent_timeout_seconds, DEFAULT_AGENT_TIMEOUT_SECONDS)
        self.assertEqual(policy.agent_timeout_seconds[AgentName.TRIAGE], 5.0)
        self.assertEqual(policy.agent_timeout_seconds[AgentName.DEVICE_EVIDENCE], 45.0)
        self.assertEqual(policy.agent_timeout_seconds[AgentName.RCA], 30.0)

    def test_budget_policy_mapping_is_immutable(self) -> None:
        policy = BudgetPolicy()
        self.assertIsInstance(policy.agent_timeout_seconds, MappingProxyType)
        with self.assertRaises(TypeError):
            policy.agent_timeout_seconds[AgentName.TRIAGE] = 10.0  # type: ignore[index]

    def test_nonpositive_total_budget_is_rejected(self) -> None:
        with self.assertRaises(BudgetConfigurationError):
            BudgetPolicy(total_timeout_seconds=0)

    def test_missing_agent_timeout_is_rejected(self) -> None:
        mapping = dict(DEFAULT_AGENT_TIMEOUT_SECONDS)
        mapping.pop(AgentName.RCA)
        with self.assertRaises(BudgetConfigurationError):
            BudgetPolicy(agent_timeout_seconds=mapping)

    def test_nonpositive_agent_timeout_is_rejected(self) -> None:
        mapping = dict(DEFAULT_AGENT_TIMEOUT_SECONDS)
        mapping[AgentName.TRIAGE] = 0
        with self.assertRaises(BudgetConfigurationError):
            BudgetPolicy(agent_timeout_seconds=mapping)

    def test_remaining_budget_uses_monotonic_clock(self) -> None:
        clock = FakeClock()
        budget = ExecutionBudget(BudgetPolicy(total_timeout_seconds=10), clock=clock)
        clock.advance(3.25)
        self.assertAlmostEqual(budget.elapsed_seconds, 3.25)
        self.assertAlmostEqual(budget.remaining_seconds, 6.75)
        self.assertFalse(budget.exhausted)

    def test_agent_timeout_is_capped_by_remaining_total(self) -> None:
        clock = FakeClock()
        budget = ExecutionBudget(BudgetPolicy(total_timeout_seconds=4), clock=clock)
        clock.advance(2.5)
        self.assertAlmostEqual(budget.timeout_for(AgentName.DEVICE_EVIDENCE), 1.5)

    def test_timeout_for_raises_after_budget_exhaustion(self) -> None:
        clock = FakeClock()
        budget = ExecutionBudget(BudgetPolicy(total_timeout_seconds=2), clock=clock)
        clock.advance(2)
        self.assertTrue(budget.exhausted)
        with self.assertRaises(ExecutionBudgetExhausted):
            budget.timeout_for(AgentName.TRIAGE)


class V12ExecutionContextTests(unittest.TestCase):
    def test_duplicate_agent_start_is_blocked(self) -> None:
        context = ExecutionContext(REQUEST_ID)
        context.begin(AgentName.TRIAGE)
        with self.assertRaises(DuplicateAgentExecutionError):
            context.begin(AgentName.TRIAGE)

    def test_record_requires_agent_begin(self) -> None:
        context = ExecutionContext(REQUEST_ID)
        with self.assertRaises(ExecutionContextError):
            context.record(AgentName.TRIAGE, make_run(AgentName.TRIAGE), None)

    def test_record_rejects_request_id_mismatch(self) -> None:
        context = ExecutionContext(REQUEST_ID)
        context.begin(AgentName.TRIAGE)
        with self.assertRaises(ExecutionContextError):
            context.record(
                AgentName.TRIAGE,
                make_run(AgentName.TRIAGE, request_id="other-request"),
                None,
            )

    def test_record_rejects_agent_name_mismatch(self) -> None:
        context = ExecutionContext(REQUEST_ID)
        context.begin(AgentName.TRIAGE)
        with self.assertRaises(ExecutionContextError):
            context.record(
                AgentName.TRIAGE,
                make_run(AgentName.STATIC_PLANNER),
                None,
            )

    def test_output_is_sanitized_and_available_to_next_agent(self) -> None:
        context = ExecutionContext(REQUEST_ID)
        context.begin(AgentName.TRIAGE)
        outcome = AgentOutcome(
            status=AgentStatus.SUCCESS,
            output_refs=(f"agent://{REQUEST_ID}/output/triage",),
            output={"family": "interface", "api_token": "sensitive"},
        )
        context.record(
            AgentName.TRIAGE,
            make_run(AgentName.TRIAGE),
            outcome,
        )
        invocation = context.invocation(
            AgentName.STATIC_PLANNER,
            OrchestrationState.PLANNING,
        )
        self.assertEqual(invocation.prior_output_refs, outcome.output_refs)
        self.assertEqual(
            invocation.prior_outputs[AgentName.TRIAGE.value]["api_token"],
            "[REDACTED]",
        )

    def test_output_snapshot_is_immutable(self) -> None:
        context = ExecutionContext(REQUEST_ID)
        context.begin(AgentName.TRIAGE)
        context.record(
            AgentName.TRIAGE,
            make_run(AgentName.TRIAGE),
            AgentOutcome(status=AgentStatus.SUCCESS, output={"value": 1}),
        )
        invocation = context.invocation(
            AgentName.STATIC_PLANNER,
            OrchestrationState.PLANNING,
        )
        with self.assertRaises(TypeError):
            invocation.prior_outputs[AgentName.TRIAGE.value]["value"] = 2  # type: ignore[index]

    def test_execution_count_is_at_most_one(self) -> None:
        context = ExecutionContext(REQUEST_ID)
        self.assertEqual(context.execution_count(AgentName.TRIAGE), 0)
        context.begin(AgentName.TRIAGE)
        self.assertEqual(context.execution_count(AgentName.TRIAGE), 1)


if __name__ == "__main__":
    unittest.main()
