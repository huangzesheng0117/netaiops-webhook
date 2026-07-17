"""Deterministic Agent registry for the v12 controlled pipeline."""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from .execution_context import AgentInvocation, AgentOutcome
from .status import AgentName


AGENT_EXECUTION_ORDER: tuple[AgentName, ...] = (
    AgentName.TRIAGE,
    AgentName.STATIC_PLANNER,
    AgentName.METRICS_EVIDENCE,
    AgentName.DEVICE_EVIDENCE,
    AgentName.LOGS_EVIDENCE,
    AgentName.KNOWLEDGE_CONTEXT,
    AgentName.EVIDENCE_JUDGE,
    AgentName.RCA,
    AgentName.NOTIFICATION_REPORT,
)


class AgentFailurePolicy(str, Enum):
    """Orchestrator decision after an Agent fails or is unavailable."""

    CONTINUE = "continue"
    STOP = "stop"
    FALLBACK_TO_LEGACY = "fallback_to_legacy"


class AsyncAgent(Protocol):
    """Minimal async Agent interface; Agents cannot schedule other Agents."""

    async def run(self, invocation: AgentInvocation) -> AgentOutcome:
        """Execute exactly one bounded Agent invocation."""


class AgentRegistryError(ValueError):
    """Base class for deterministic Agent registry failures."""


class DuplicateAgentRegistrationError(AgentRegistryError):
    """Raised when an Agent name is registered more than once."""


class IncompleteAgentRegistryError(AgentRegistryError):
    """Raised when the fixed v12 execution sequence is incomplete."""


@dataclass(frozen=True, slots=True)
class AgentSpec:
    """Frozen registration metadata for one Agent."""

    name: AgentName
    agent: AsyncAgent
    required: bool = True
    failure_policy: AgentFailurePolicy = AgentFailurePolicy.FALLBACK_TO_LEGACY
    retry_limit: int = 0

    def __post_init__(self) -> None:
        run_method = getattr(self.agent, "run", None)
        if run_method is None or not callable(run_method):
            raise AgentRegistryError(f"Agent {self.name} must provide run()")
        if not inspect.iscoroutinefunction(run_method):
            raise AgentRegistryError(
                f"Agent {self.name} run() must be async for enforceable timeout"
            )
        if self.retry_limit != 0:
            raise AgentRegistryError("v12 Batch C retry_limit is frozen at zero")


class AgentRegistry:
    """Registration container that always resolves the frozen Agent order."""

    def __init__(self) -> None:
        self._specs: dict[AgentName, AgentSpec] = {}

    def register(self, spec: AgentSpec) -> None:
        if spec.name in self._specs:
            raise DuplicateAgentRegistrationError(
                f"Agent already registered: {spec.name}"
            )
        self._specs[spec.name] = spec

    def get(self, name: AgentName) -> AgentSpec:
        try:
            return self._specs[name]
        except KeyError as exc:
            raise IncompleteAgentRegistryError(
                f"Agent is not registered: {name}"
            ) from exc

    def validate_complete(self) -> None:
        missing = [name.value for name in AGENT_EXECUTION_ORDER if name not in self._specs]
        extra = [name.value for name in self._specs if name not in AGENT_EXECUTION_ORDER]
        if missing or extra:
            raise IncompleteAgentRegistryError(
                f"registry mismatch: missing={missing}, extra={extra}"
            )

    def ordered_specs(self) -> tuple[AgentSpec, ...]:
        self.validate_complete()
        return tuple(self._specs[name] for name in AGENT_EXECUTION_ORDER)

    @property
    def registered_names(self) -> tuple[AgentName, ...]:
        return tuple(name for name in AGENT_EXECUTION_ORDER if name in self._specs)

    def __len__(self) -> int:
        return len(self._specs)
