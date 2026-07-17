"""Finite state machine for the deterministic v12 Agent sequence."""

from __future__ import annotations

from enum import Enum

from .status import AgentName


class OrchestrationState(str, Enum):
    INITIALIZED = "initialized"
    TRIAGE = "triage"
    PLANNING = "planning"
    EVIDENCE_COLLECTION = "evidence_collection"
    EVIDENCE_JUDGING = "evidence_judging"
    RCA = "rca"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FALLBACK_TO_LEGACY = "fallback_to_legacy"
    FAILED = "failed"


AGENT_STATE: dict[AgentName, OrchestrationState] = {
    AgentName.TRIAGE: OrchestrationState.TRIAGE,
    AgentName.STATIC_PLANNER: OrchestrationState.PLANNING,
    AgentName.METRICS_EVIDENCE: OrchestrationState.EVIDENCE_COLLECTION,
    AgentName.DEVICE_EVIDENCE: OrchestrationState.EVIDENCE_COLLECTION,
    AgentName.LOGS_EVIDENCE: OrchestrationState.EVIDENCE_COLLECTION,
    AgentName.KNOWLEDGE_CONTEXT: OrchestrationState.EVIDENCE_COLLECTION,
    AgentName.EVIDENCE_JUDGE: OrchestrationState.EVIDENCE_JUDGING,
    AgentName.RCA: OrchestrationState.RCA,
    AgentName.NOTIFICATION_REPORT: OrchestrationState.REPORTING,
}


_ALLOWED_TRANSITIONS: dict[OrchestrationState, frozenset[OrchestrationState]] = {
    OrchestrationState.INITIALIZED: frozenset({OrchestrationState.TRIAGE}),
    OrchestrationState.TRIAGE: frozenset({OrchestrationState.PLANNING}),
    OrchestrationState.PLANNING: frozenset(
        {OrchestrationState.EVIDENCE_COLLECTION}
    ),
    OrchestrationState.EVIDENCE_COLLECTION: frozenset(
        {OrchestrationState.EVIDENCE_JUDGING}
    ),
    OrchestrationState.EVIDENCE_JUDGING: frozenset({OrchestrationState.RCA}),
    OrchestrationState.RCA: frozenset({OrchestrationState.REPORTING}),
    OrchestrationState.REPORTING: frozenset({OrchestrationState.COMPLETED}),
    OrchestrationState.COMPLETED: frozenset(),
    OrchestrationState.FALLBACK_TO_LEGACY: frozenset(),
    OrchestrationState.FAILED: frozenset(),
}

_TERMINAL_STATES = frozenset(
    {
        OrchestrationState.COMPLETED,
        OrchestrationState.FALLBACK_TO_LEGACY,
        OrchestrationState.FAILED,
    }
)


class InvalidStateTransitionError(ValueError):
    """Raised when the deterministic state sequence is violated."""


class OrchestrationStateMachine:
    """Small explicit state machine with an immutable public history."""

    def __init__(self) -> None:
        self._state = OrchestrationState.INITIALIZED
        self._history: list[OrchestrationState] = [self._state]

    @property
    def state(self) -> OrchestrationState:
        return self._state

    @property
    def history(self) -> tuple[OrchestrationState, ...]:
        return tuple(self._history)

    @property
    def terminal(self) -> bool:
        return self._state in _TERMINAL_STATES

    def transition(self, target: OrchestrationState) -> None:
        if self.terminal:
            raise InvalidStateTransitionError(
                f"terminal state cannot transition: {self._state} -> {target}"
            )
        if target not in _ALLOWED_TRANSITIONS[self._state]:
            raise InvalidStateTransitionError(
                f"invalid state transition: {self._state} -> {target}"
            )
        self._state = target
        self._history.append(target)

    def advance_for_agent(self, name: AgentName) -> None:
        target = AGENT_STATE[name]
        if target == self._state:
            return
        self.transition(target)

    def complete(self) -> None:
        self.transition(OrchestrationState.COMPLETED)

    def fallback_to_legacy(self) -> None:
        self._force_terminal(OrchestrationState.FALLBACK_TO_LEGACY)

    def fail(self) -> None:
        self._force_terminal(OrchestrationState.FAILED)

    def _force_terminal(self, target: OrchestrationState) -> None:
        if self.terminal:
            raise InvalidStateTransitionError(
                f"terminal state cannot transition: {self._state} -> {target}"
            )
        self._state = target
        self._history.append(target)
