"""In-memory execution context for one deterministic v12 request."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from .contracts import AgentRunRecord, ContractNotice, ExternalCallRecord
from .schema_validator import sanitize_sensitive_data, validate_request_id
from .state_machine import OrchestrationState
from .status import AgentName, AgentStatus


class DuplicateAgentExecutionError(RuntimeError):
    """Raised when one Agent is started more than once for a request."""


class ExecutionContextError(ValueError):
    """Raised when run records do not match the request context."""


@dataclass(frozen=True, slots=True)
class AgentInvocation:
    request_id: str
    agent_name: AgentName
    orchestration_state: OrchestrationState
    prior_output_refs: tuple[str, ...]
    prior_outputs: Mapping[str, Mapping[str, Any]]


@dataclass(frozen=True, slots=True)
class AgentOutcome:
    status: AgentStatus
    output_refs: tuple[str, ...] = ()
    output: Mapping[str, Any] = field(default_factory=dict)
    warnings: tuple[ContractNotice, ...] = ()
    errors: tuple[ContractNotice, ...] = ()
    external_calls: tuple[ExternalCallRecord, ...] = ()

    def __post_init__(self) -> None:
        sanitized = sanitize_sensitive_data(dict(self.output))
        object.__setattr__(self, "output_refs", tuple(self.output_refs))
        object.__setattr__(self, "output", MappingProxyType(sanitized))
        object.__setattr__(self, "warnings", tuple(self.warnings))
        object.__setattr__(self, "errors", tuple(self.errors))
        object.__setattr__(self, "external_calls", tuple(self.external_calls))


@dataclass(frozen=True, slots=True)
class OrchestrationResult:
    request_id: str
    final_state: OrchestrationState
    state_history: tuple[OrchestrationState, ...]
    agent_runs: tuple[AgentRunRecord, ...]
    outputs: Mapping[str, Mapping[str, Any]]
    fallback_to_legacy: bool
    stop_reason: str | None
    elapsed_ms: int


class ExecutionContext:
    """Tracks attempts, outputs, references, and AgentRunRecord objects."""

    def __init__(self, request_id: str) -> None:
        self.request_id = validate_request_id(request_id)
        self._started: set[AgentName] = set()
        self._recorded: set[AgentName] = set()
        self._runs: list[AgentRunRecord] = []
        self._outputs: dict[str, Mapping[str, Any]] = {}
        self._output_refs: list[str] = []

    def begin(self, name: AgentName) -> None:
        if name in self._started:
            raise DuplicateAgentExecutionError(
                f"Agent already started for request {self.request_id}: {name}"
            )
        self._started.add(name)

    def invocation(
        self,
        name: AgentName,
        state: OrchestrationState,
    ) -> AgentInvocation:
        prior_outputs = {
            key: MappingProxyType(dict(value))
            for key, value in self._outputs.items()
        }
        return AgentInvocation(
            request_id=self.request_id,
            agent_name=name,
            orchestration_state=state,
            prior_output_refs=tuple(self._output_refs),
            prior_outputs=MappingProxyType(prior_outputs),
        )

    def record(
        self,
        name: AgentName,
        run_record: AgentRunRecord,
        outcome: AgentOutcome | None,
    ) -> None:
        if name not in self._started:
            raise ExecutionContextError(f"Agent was not started: {name}")
        if name in self._recorded:
            raise DuplicateAgentExecutionError(
                f"Agent already recorded for request {self.request_id}: {name}"
            )
        if run_record.request_id != self.request_id:
            raise ExecutionContextError("AgentRunRecord request_id mismatch")
        if run_record.agent_name != name:
            raise ExecutionContextError("AgentRunRecord agent_name mismatch")

        self._recorded.add(name)
        self._runs.append(run_record)
        if outcome is not None:
            self._outputs[name.value] = MappingProxyType(dict(outcome.output))
            self._output_refs.extend(outcome.output_refs)

    def execution_count(self, name: AgentName) -> int:
        return 1 if name in self._started else 0

    @property
    def runs(self) -> tuple[AgentRunRecord, ...]:
        return tuple(self._runs)

    @property
    def output_refs(self) -> tuple[str, ...]:
        return tuple(self._output_refs)

    @property
    def outputs(self) -> Mapping[str, Mapping[str, Any]]:
        return MappingProxyType(dict(self._outputs))
