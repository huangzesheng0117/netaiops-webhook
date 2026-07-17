"""Deterministic, single-pass v12 Agent Orchestrator skeleton."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Callable

from .agent_registry import (
    AgentFailurePolicy,
    AgentRegistry,
    AgentSpec,
)
from .budget import BudgetPolicy, ExecutionBudget, ExecutionBudgetExhausted
from .contracts import AgentRunRecord, ContractNotice
from .execution_context import (
    AgentInvocation,
    AgentOutcome,
    ExecutionContext,
    OrchestrationResult,
)
from .state_machine import OrchestrationStateMachine
from .status import AgentName, AgentStatus


class DeterministicOrchestrator:
    """Runs the frozen Agent order once with timeout and failure isolation."""

    def __init__(
        self,
        registry: AgentRegistry,
        *,
        budget_policy: BudgetPolicy | None = None,
        fail_open_to_legacy: bool = True,
        monotonic_clock: Callable[[], float] = time.monotonic,
        utcnow: Callable[[], datetime] | None = None,
    ) -> None:
        self.registry = registry
        self.budget_policy = budget_policy or BudgetPolicy()
        self.fail_open_to_legacy = bool(fail_open_to_legacy)
        self._clock = monotonic_clock
        self._utcnow = utcnow or (lambda: datetime.now(timezone.utc))

    def run(self, request_id: str) -> OrchestrationResult:
        """Synchronous wrapper for non-async production entry points."""

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.run_async(request_id))
        raise RuntimeError("run() cannot be used inside an active event loop")

    async def run_async(self, request_id: str) -> OrchestrationResult:
        self.registry.validate_complete()
        machine = OrchestrationStateMachine()
        context = ExecutionContext(request_id)
        budget = ExecutionBudget(self.budget_policy, clock=self._clock)
        stopped = False
        fallback = False
        stop_reason: str | None = None

        for spec in self.registry.ordered_specs():
            if stopped:
                self._record_skipped(
                    context,
                    spec.name,
                    stop_reason or "orchestration_stopped",
                )
                continue

            machine.advance_for_agent(spec.name)

            if budget.exhausted:
                stop_reason = "total_budget_exhausted"
                fallback = self._stop_machine(machine)
                stopped = True
                self._record_skipped(context, spec.name, stop_reason)
                continue

            context.begin(spec.name)
            invocation = context.invocation(spec.name, machine.state)
            started_at = self._aware_now()
            started_clock = self._clock()
            outcome = await self._execute_agent(spec, invocation, budget)
            finished_at = self._aware_now()
            duration_ms = max(0, int(round((self._clock() - started_clock) * 1000)))

            run_record = AgentRunRecord(
                schema_version="v12.1",
                request_id=request_id,
                agent_name=spec.name,
                status=outcome.status,
                started_at=started_at,
                finished_at=finished_at,
                duration_ms=duration_ms,
                inputs_ref=list(invocation.prior_output_refs),
                outputs_ref=list(outcome.output_refs),
                warnings=list(outcome.warnings),
                errors=list(outcome.errors),
                external_calls=list(outcome.external_calls),
            )
            context.record(spec.name, run_record, outcome)

            if self._must_stop(spec, outcome.status):
                stop_reason = self._stop_reason(spec, outcome.status)
                fallback = self._stop_machine(machine, spec.failure_policy)
                stopped = True
            elif budget.exhausted and spec.name.value != "notification_report":
                stop_reason = "total_budget_exhausted"
                fallback = self._stop_machine(machine)
                stopped = True

        if not stopped:
            machine.complete()

        return OrchestrationResult(
            request_id=request_id,
            final_state=machine.state,
            state_history=machine.history,
            agent_runs=context.runs,
            outputs=context.outputs,
            fallback_to_legacy=fallback,
            stop_reason=stop_reason,
            elapsed_ms=max(0, int(round(budget.elapsed_seconds * 1000))),
        )

    async def _execute_agent(
        self,
        spec: AgentSpec,
        invocation: AgentInvocation,
        budget: ExecutionBudget,
    ) -> AgentOutcome:
        try:
            timeout = budget.timeout_for(spec.name)
            result = await asyncio.wait_for(
                spec.agent.run(invocation),
                timeout=timeout,
            )
            if not isinstance(result, AgentOutcome):
                return self._failed_outcome(
                    code="agent_result_invalid",
                    message="Agent returned an unsupported result type",
                    details={"result_type": type(result).__name__},
                )
            return result
        except ExecutionBudgetExhausted:
            return self._failed_outcome(
                code="total_budget_exhausted",
                message="No execution budget remained before Agent invocation",
            )
        except asyncio.TimeoutError:
            return self._failed_outcome(
                code="agent_timeout",
                message="Agent exceeded its deterministic timeout",
            )
        except Exception as exc:  # failure isolation boundary
            return self._failed_outcome(
                code="agent_exception",
                message="Agent raised an isolated exception",
                details={"exception_type": type(exc).__name__},
            )

    def _failed_outcome(
        self,
        *,
        code: str,
        message: str,
        details: dict[str, str] | None = None,
    ) -> AgentOutcome:
        return AgentOutcome(
            status=AgentStatus.FAILED,
            errors=(
                ContractNotice(
                    code=code,
                    message=message,
                    retryable=False,
                    details=details or {},
                ),
            ),
        )

    def _record_skipped(
        self,
        context: ExecutionContext,
        name: AgentName,
        reason: str,
    ) -> None:
        context.begin(name)
        now = self._aware_now()
        notice = ContractNotice(
            code=reason,
            message="Agent execution skipped by deterministic Orchestrator",
            retryable=False,
        )
        record = AgentRunRecord(
            schema_version="v12.1",
            request_id=context.request_id,
            agent_name=name,
            status=AgentStatus.SKIPPED,
            started_at=now,
            finished_at=now,
            duration_ms=0,
            warnings=[notice],
        )
        context.record(name, record, None)

    def _must_stop(self, spec: AgentSpec, status: AgentStatus) -> bool:
        if status == AgentStatus.FAILED:
            return spec.failure_policy != AgentFailurePolicy.CONTINUE
        if spec.required and status in {
            AgentStatus.NOT_AVAILABLE,
            AgentStatus.SKIPPED,
        }:
            return spec.failure_policy != AgentFailurePolicy.CONTINUE
        return False

    def _stop_reason(self, spec: AgentSpec, status: AgentStatus) -> str:
        return f"{spec.name.value}_{status.value}"

    def _stop_machine(
        self,
        machine: OrchestrationStateMachine,
        policy: AgentFailurePolicy = AgentFailurePolicy.FALLBACK_TO_LEGACY,
    ) -> bool:
        if policy == AgentFailurePolicy.FALLBACK_TO_LEGACY:
            if self.fail_open_to_legacy:
                machine.fallback_to_legacy()
                return True
            machine.fail()
            return False
        machine.fail()
        return False

    def _aware_now(self) -> datetime:
        value = self._utcnow()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("utcnow provider must return a timezone-aware datetime")
        return value
