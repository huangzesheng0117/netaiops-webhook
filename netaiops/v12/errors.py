"""Exceptions raised by v12 contract validation utilities."""

from __future__ import annotations

from typing import Any, Iterable


class V12ContractError(ValueError):
    """Base class for deterministic v12 contract failures."""


class EvidenceReferenceError(V12ContractError):
    """Raised when a contract or evidence reference is malformed."""


class SensitiveDataError(V12ContractError):
    """Raised when unredacted sensitive data is detected after sanitization."""


class ContractValidationError(V12ContractError):
    """Normalized wrapper around schema and JSON validation failures."""

    def __init__(
        self,
        message: str,
        *,
        issues: Iterable[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(message)
        self.issues = tuple(issues or ())
