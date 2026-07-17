"""Execution budget primitives for deterministic v12 orchestration."""

from __future__ import annotations

import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Mapping

from .agent_registry import AGENT_EXECUTION_ORDER
from .status import AgentName


DEFAULT_TOTAL_TIMEOUT_SECONDS = 90.0
DEFAULT_AGENT_TIMEOUT_SECONDS: Mapping[AgentName, float] = MappingProxyType(
    {
        AgentName.TRIAGE: 5.0,
        AgentName.STATIC_PLANNER: 5.0,
        AgentName.METRICS_EVIDENCE: 30.0,
        AgentName.DEVICE_EVIDENCE: 45.0,
        AgentName.LOGS_EVIDENCE: 5.0,
        AgentName.KNOWLEDGE_CONTEXT: 5.0,
        AgentName.EVIDENCE_JUDGE: 5.0,
        AgentName.RCA: 30.0,
        AgentName.NOTIFICATION_REPORT: 5.0,
    }
)


class BudgetConfigurationError(ValueError):
    """Raised when a budget policy violates frozen v12 constraints."""


class ExecutionBudgetExhausted(RuntimeError):
    """Raised when no execution time remains."""


@dataclass(frozen=True, slots=True)
class BudgetPolicy:
    total_timeout_seconds: float = DEFAULT_TOTAL_TIMEOUT_SECONDS
    agent_timeout_seconds: Mapping[AgentName, float] = (
        DEFAULT_AGENT_TIMEOUT_SECONDS
    )

    def __post_init__(self) -> None:
        total = float(self.total_timeout_seconds)
        if total <= 0:
            raise BudgetConfigurationError("total timeout must be greater than zero")

        normalized = {
            AgentName(name): float(value)
            for name, value in self.agent_timeout_seconds.items()
        }
        missing = [name.value for name in AGENT_EXECUTION_ORDER if name not in normalized]
        extra = [name.value for name in normalized if name not in AGENT_EXECUTION_ORDER]
        if missing or extra:
            raise BudgetConfigurationError(
                f"agent timeout map mismatch: missing={missing}, extra={extra}"
            )
        invalid = {
            name.value: value for name, value in normalized.items() if value <= 0
        }
        if invalid:
            raise BudgetConfigurationError(
                f"agent timeouts must be positive: {invalid}"
            )

        object.__setattr__(self, "total_timeout_seconds", total)
        object.__setattr__(
            self,
            "agent_timeout_seconds",
            MappingProxyType(normalized),
        )


class ExecutionBudget:
    """Monotonic total budget with per-Agent timeout caps."""

    def __init__(
        self,
        policy: BudgetPolicy,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.policy = policy
        self._clock = clock
        self._started = float(clock())

    @property
    def elapsed_seconds(self) -> float:
        return max(0.0, float(self._clock()) - self._started)

    @property
    def remaining_seconds(self) -> float:
        return max(
            0.0,
            self.policy.total_timeout_seconds - self.elapsed_seconds,
        )

    @property
    def exhausted(self) -> bool:
        return self.remaining_seconds <= 0.0

    def timeout_for(self, name: AgentName) -> float:
        remaining = self.remaining_seconds
        if remaining <= 0.0:
            raise ExecutionBudgetExhausted("total execution budget is exhausted")
        return min(self.policy.agent_timeout_seconds[name], remaining)
