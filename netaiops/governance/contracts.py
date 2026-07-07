"""Frozen contracts for the NetAIOps Webhook v11 governance layer.

Batch 0 deliberately contains only stable vocabulary and lightweight contract
helpers. Runtime persistence and Pydantic schemas are introduced in Batch 1.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any, Mapping, Sequence


GOVERNANCE_SCHEMA_VERSION = "11.0.0-contract-v1"
LOGS_NOT_AVAILABLE_REASON = "elasticsearch_query_interface_pending"


class StringEnum(str, Enum):
    """String-valued Enum compatible with Python 3.10."""

    def __str__(self) -> str:
        return self.value


class GovernanceStatus(StringEnum):
    CREATED = "created"
    READY = "ready"
    PROCESSING = "processing"
    COMPLETED = "completed"
    WARNING = "warning"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


class EvidenceSourceStatus(StringEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    NO_DATA = "no_data"
    FAILED = "failed"
    NOT_CONFIGURED = "not_configured"
    NOT_AVAILABLE = "not_available"
    SKIPPED = "skipped"


class ProposalStatus(StringEnum):
    DRAFT = "draft"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    IMPLEMENTED = "implemented"
    VERIFIED = "verified"


class ReplayMode(StringEnum):
    OFFLINE = "offline"
    CONTROLLED = "controlled"


class AuditStatus(StringEnum):
    PASS = "PASS"
    WARNING = "WARNING"
    BLOCKED = "BLOCKED"


class LearningSignalSeverity(StringEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


_SAFE_KIND_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _validate_relative_path(value: str) -> str:
    path = str(value or "").strip().replace("\\", "/")
    if not path:
        raise ValueError("artifact path must not be empty")
    posix = PurePosixPath(path)
    if posix.is_absolute() or ".." in posix.parts or "." in posix.parts:
        raise ValueError(f"artifact path must be safe and relative: {value!r}")
    if any(part == "" for part in posix.parts):
        raise ValueError(f"artifact path contains an empty segment: {value!r}")
    return posix.as_posix()


@dataclass(frozen=True)
class ArtifactRef:
    """Reference to an existing or expected runtime artifact.

    ArtifactRef carries metadata only. It never embeds raw payloads, device
    output, Prometheus samples, logs, tokens, or secrets.
    """

    kind: str
    path: str
    sha256: str = ""
    exists: bool = False
    size_bytes: int = 0

    def __post_init__(self) -> None:
        kind = str(self.kind or "").strip()
        if not _SAFE_KIND_RE.fullmatch(kind):
            raise ValueError(f"invalid artifact kind: {self.kind!r}")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "path", _validate_relative_path(self.path))

        digest = str(self.sha256 or "").strip().lower()
        if digest and not _SHA256_RE.fullmatch(digest):
            raise ValueError("sha256 must be empty or 64 lowercase hex characters")
        object.__setattr__(self, "sha256", digest)

        if isinstance(self.size_bytes, bool) or int(self.size_bytes) < 0:
            raise ValueError("size_bytes must be a non-negative integer")
        object.__setattr__(self, "size_bytes", int(self.size_bytes))

        if self.exists and not digest:
            raise ValueError("existing artifact references require sha256")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ExternalCallPolicy:
    """Default-deny policy used by v11 replay and governance tooling."""

    real_glm: bool = False
    real_prometheus: bool = False
    real_device: bool = False
    real_notification: bool = False
    write_production_data: bool = False

    @property
    def offline_safe(self) -> bool:
        return not any(asdict(self).values())

    def assert_offline(self) -> None:
        enabled = [name for name, value in asdict(self).items() if value]
        if enabled:
            raise ValueError(
                "external calls or production writes are forbidden by the "
                f"offline policy: {', '.join(enabled)}"
            )

    def to_dict(self) -> dict[str, bool]:
        return asdict(self)


DEFAULT_EXTERNAL_CALL_POLICY = ExternalCallPolicy()
DEFAULT_EXTERNAL_CALL_POLICY.assert_offline()


INCIDENT_MEMORY_REQUIRED_FIELDS = (
    "memory_id",
    "request_id",
    "schema_version",
    "created_at",
    "source_type",
    "alert_time",
    "device",
    "object",
    "family",
    "alert_summary",
    "analysis_summary",
    "evidence_status",
    "command_summary",
    "review_summary",
    "notification_result",
    "quality_flags",
    "git_metadata",
    "artifact_refs",
)

LEARNING_SIGNAL_REQUIRED_FIELDS = (
    "signal_id",
    "request_id",
    "signal_type",
    "severity",
    "detected_from",
    "reason",
    "evidence_refs",
    "dedupe_key",
    "proposal_eligible",
    "created_at",
)

PROPOSAL_REQUIRED_FIELDS = (
    "proposal_id",
    "signal_id",
    "signal_type",
    "affected_family",
    "affected_components",
    "evidence_refs",
    "suggested_change",
    "expected_benefit",
    "risk",
    "replay_scope",
    "status",
    "reviewer",
    "created_at",
    "updated_at",
    "audit_trail",
)

REPLAY_REQUIRED_FIELDS = (
    "replay_id",
    "request_id",
    "baseline_refs",
    "candidate_refs",
    "before",
    "after",
    "diff",
    "quality_delta",
    "safety_delta",
    "external_calls",
    "errors",
    "warnings",
)

AUDIT_REQUIRED_FIELDS = (
    "audit_id",
    "target_version",
    "branch",
    "commit",
    "worktree",
    "changed_files",
    "test_results",
    "replay_results",
    "smoke_results",
    "sensitive_file_check",
    "external_calls",
    "governance_data_integrity",
    "status",
    "problems",
    "warnings",
    "created_at",
)

CONTRACT_REQUIRED_FIELDS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "incident_memory": INCIDENT_MEMORY_REQUIRED_FIELDS,
        "learning_signal": LEARNING_SIGNAL_REQUIRED_FIELDS,
        "proposal": PROPOSAL_REQUIRED_FIELDS,
        "replay": REPLAY_REQUIRED_FIELDS,
        "audit": AUDIT_REQUIRED_FIELDS,
    }
)

LEARNING_SIGNAL_TYPES = (
    "classification_fallback",
    "playbook_missing",
    "policy_blocked",
    "prometheus_not_configured",
    "prometheus_no_data",
    "prometheus_failed",
    "command_failed",
    "cli_hard_error",
    "review_missing_evidence",
    "notification_failed",
    "runner_false_negative",
    "model_parse_failed",
    "logs_not_available",
)


@dataclass(frozen=True)
class FixtureSpec:
    fixture_id: str
    fixture_type: str
    role: str
    expected_signals: tuple[str, ...] = ()
    proposal_eligible: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


REAL_FIXTURE_MATRIX = (
    FixtureSpec(
        fixture_id="20260703_154613_796157_3750fbea",
        fixture_type="real_request",
        role="v10_release_baseline_cli_failure",
        expected_signals=("command_failed", "cli_hard_error"),
    ),
    FixtureSpec(
        fixture_id="20260706_141707_915316_11eef8e7",
        fixture_type="real_request",
        role="glm52_analysis_success_cli_failure",
        expected_signals=("command_failed", "cli_hard_error"),
    ),
    FixtureSpec(
        fixture_id="20260703_145814_955415_6fe18e1f",
        fixture_type="real_request",
        role="metrics_device_evidence_hub_success",
        expected_signals=(),
        proposal_eligible=False,
    ),
)

SYNTHETIC_FIXTURE_MATRIX = (
    FixtureSpec(
        fixture_id="synthetic-model-parse-failed",
        fixture_type="synthetic_boundary",
        role="model_parse_failed",
        expected_signals=("model_parse_failed",),
    ),
    FixtureSpec(
        fixture_id="synthetic-model-rate-limited",
        fixture_type="synthetic_boundary",
        role="model_rate_limited",
        expected_signals=("model_parse_failed",),
    ),
    FixtureSpec(
        fixture_id="synthetic-policy-blocked",
        fixture_type="synthetic_boundary",
        role="safety_policy_blocked",
        expected_signals=("policy_blocked",),
    ),
    FixtureSpec(
        fixture_id="synthetic-playbook-missing",
        fixture_type="synthetic_boundary",
        role="playbook_missing_or_fallback",
        expected_signals=("playbook_missing", "classification_fallback"),
    ),
    FixtureSpec(
        fixture_id="synthetic-notification-failed",
        fixture_type="synthetic_boundary",
        role="notification_failed",
        expected_signals=("notification_failed",),
    ),
    FixtureSpec(
        fixture_id="synthetic-logs-not-available",
        fixture_type="synthetic_boundary",
        role="logs_not_available",
        expected_signals=("logs_not_available",),
        proposal_eligible=False,
    ),
)


def get_fixture_spec(fixture_id: str) -> FixtureSpec | None:
    for item in (*REAL_FIXTURE_MATRIX, *SYNTHETIC_FIXTURE_MATRIX):
        if item.fixture_id == fixture_id:
            return item
    return None


def missing_required_fields(
    contract_name: str,
    payload: Mapping[str, Any],
) -> tuple[str, ...]:
    try:
        required = CONTRACT_REQUIRED_FIELDS[contract_name]
    except KeyError as exc:
        raise ValueError(f"unknown governance contract: {contract_name!r}") from exc
    return tuple(field for field in required if field not in payload)


def assert_contract_shape(
    contract_name: str,
    payload: Mapping[str, Any],
) -> None:
    missing = missing_required_fields(contract_name, payload)
    if missing:
        raise ValueError(
            f"{contract_name} missing required fields: {', '.join(missing)}"
        )


def enum_values(enum_type: type[StringEnum]) -> tuple[str, ...]:
    return tuple(item.value for item in enum_type)


__all__ = [
    "AUDIT_REQUIRED_FIELDS",
    "ArtifactRef",
    "AuditStatus",
    "CONTRACT_REQUIRED_FIELDS",
    "DEFAULT_EXTERNAL_CALL_POLICY",
    "EvidenceSourceStatus",
    "ExternalCallPolicy",
    "FixtureSpec",
    "GOVERNANCE_SCHEMA_VERSION",
    "GovernanceStatus",
    "INCIDENT_MEMORY_REQUIRED_FIELDS",
    "LEARNING_SIGNAL_REQUIRED_FIELDS",
    "LEARNING_SIGNAL_TYPES",
    "LOGS_NOT_AVAILABLE_REASON",
    "LearningSignalSeverity",
    "PROPOSAL_REQUIRED_FIELDS",
    "ProposalStatus",
    "REAL_FIXTURE_MATRIX",
    "REPLAY_REQUIRED_FIELDS",
    "ReplayMode",
    "SYNTHETIC_FIXTURE_MATRIX",
    "assert_contract_shape",
    "enum_values",
    "get_fixture_spec",
    "missing_required_fields",
]
