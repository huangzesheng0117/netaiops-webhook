"""Pydantic schemas for the NetAIOps Webhook v11 governance layer.

Batch 1 turns the vocabulary frozen in :mod:`contracts` into strict,
serialisable runtime records.  The schemas are side-effect free: they do not
read request artifacts, call external services, or write production data.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Mapping, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .contracts import (
    ArtifactRef,
    AuditStatus,
    EvidenceSourceStatus,
    GOVERNANCE_SCHEMA_VERSION,
    LEARNING_SIGNAL_TYPES,
    LearningSignalSeverity,
    ProposalStatus,
    ReplayMode,
    assert_contract_shape,
)

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
TGovernanceModel = TypeVar("TGovernanceModel", bound="GovernanceBaseModel")


def utc_now() -> datetime:
    """Return an aware UTC timestamp."""

    return datetime.now(timezone.utc)


def validate_governance_id(value: str, *, field_name: str = "id") -> str:
    """Validate an identifier that may safely become a JSON filename."""

    text = str(value or "").strip()
    if not _SAFE_ID_RE.fullmatch(text) or text in {".", ".."}:
        raise ValueError(f"invalid {field_name}: {value!r}")
    return text


def _require_aware(value: datetime | None, *, field_name: str) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include timezone information")
    return value.astimezone(timezone.utc)


class GovernanceBaseModel(BaseModel):
    """Common strict settings for all persisted governance records."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
        use_enum_values=False,
    )

    schema_version: str = GOVERNANCE_SCHEMA_VERSION
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("schema_version")
    @classmethod
    def _schema_version_is_current(cls, value: str) -> str:
        if value != GOVERNANCE_SCHEMA_VERSION:
            raise ValueError(
                "unsupported governance schema_version: "
                f"{value!r}; expected {GOVERNANCE_SCHEMA_VERSION!r}"
            )
        return value

    @field_validator("created_at")
    @classmethod
    def _created_at_is_aware(cls, value: datetime) -> datetime:
        result = _require_aware(value, field_name="created_at")
        assert result is not None
        return result

    def to_payload(self) -> dict[str, Any]:
        """Return a JSON-compatible dictionary."""

        return self.model_dump(mode="json", by_alias=True)


class ArtifactReference(BaseModel):
    """Validated metadata-only reference to a runtime artifact."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
        frozen=True,
    )

    kind: str
    path: str
    sha256: str = ""
    exists: bool = False
    size_bytes: int = 0

    @model_validator(mode="after")
    def _validate_with_frozen_contract(self) -> "ArtifactReference":
        # Reuse Batch 0's single source of truth for path, digest and size rules.
        ref = ArtifactRef(
            kind=self.kind,
            path=self.path,
            sha256=self.sha256,
            exists=self.exists,
            size_bytes=self.size_bytes,
        )
        object.__setattr__(self, "kind", ref.kind)
        object.__setattr__(self, "path", ref.path)
        object.__setattr__(self, "sha256", ref.sha256)
        object.__setattr__(self, "exists", ref.exists)
        object.__setattr__(self, "size_bytes", ref.size_bytes)
        return self

    def to_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class IncidentMemoryRecord(GovernanceBaseModel):
    memory_id: str
    request_id: str
    source_type: str
    alert_time: datetime | None
    device: dict[str, Any]
    object: dict[str, Any]
    family: str
    alert_summary: str
    analysis_summary: str
    evidence_status: dict[str, EvidenceSourceStatus]
    command_summary: dict[str, Any]
    review_summary: dict[str, Any]
    notification_result: dict[str, Any]
    quality_flags: list[str]
    git_metadata: dict[str, Any]
    artifact_refs: list[ArtifactReference] = Field(min_length=1)

    @field_validator("memory_id", "request_id")
    @classmethod
    def _validate_ids(cls, value: str, info: Any) -> str:
        return validate_governance_id(value, field_name=info.field_name)

    @field_validator("alert_time")
    @classmethod
    def _alert_time_is_aware(cls, value: datetime | None) -> datetime | None:
        return _require_aware(value, field_name="alert_time")

    @model_validator(mode="after")
    def _contract_shape(self) -> "IncidentMemoryRecord":
        assert_contract_shape("incident_memory", self.model_dump(mode="python"))
        return self


class LearningSignalRecord(GovernanceBaseModel):
    signal_id: str
    request_id: str
    signal_type: str
    severity: LearningSignalSeverity
    detected_from: list[str] = Field(min_length=1)
    reason: str = Field(min_length=1)
    evidence_refs: list[ArtifactReference] = Field(min_length=1)
    dedupe_key: str = Field(min_length=1, max_length=512)
    proposal_eligible: bool

    @field_validator("signal_id", "request_id")
    @classmethod
    def _validate_ids(cls, value: str, info: Any) -> str:
        return validate_governance_id(value, field_name=info.field_name)

    @field_validator("signal_type")
    @classmethod
    def _known_signal_type(cls, value: str) -> str:
        if value not in LEARNING_SIGNAL_TYPES:
            raise ValueError(f"unknown learning signal type: {value!r}")
        return value

    @model_validator(mode="after")
    def _contract_shape(self) -> "LearningSignalRecord":
        assert_contract_shape("learning_signal", self.model_dump(mode="python"))
        return self


class ProposalRecord(GovernanceBaseModel):
    proposal_id: str
    signal_id: str
    signal_type: str
    affected_family: str
    affected_components: list[str]
    evidence_refs: list[ArtifactReference] = Field(min_length=1)
    suggested_change: dict[str, Any]
    expected_benefit: str
    risk: dict[str, Any]
    replay_scope: dict[str, Any]
    status: ProposalStatus = ProposalStatus.DRAFT
    reviewer: str = ""
    updated_at: datetime = Field(default_factory=utc_now)
    audit_trail: list[dict[str, Any]]

    @field_validator("proposal_id", "signal_id")
    @classmethod
    def _validate_ids(cls, value: str, info: Any) -> str:
        return validate_governance_id(value, field_name=info.field_name)

    @field_validator("signal_type")
    @classmethod
    def _known_signal_type(cls, value: str) -> str:
        if value not in LEARNING_SIGNAL_TYPES:
            raise ValueError(f"unknown learning signal type: {value!r}")
        return value

    @field_validator("updated_at")
    @classmethod
    def _updated_at_is_aware(cls, value: datetime) -> datetime:
        result = _require_aware(value, field_name="updated_at")
        assert result is not None
        return result

    @model_validator(mode="after")
    def _contract_shape(self) -> "ProposalRecord":
        assert_contract_shape("proposal", self.model_dump(mode="python"))
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not be earlier than created_at")
        return self


class ReplayRecord(GovernanceBaseModel):
    replay_id: str
    request_id: str
    mode: ReplayMode = ReplayMode.OFFLINE
    baseline_refs: list[ArtifactReference] = Field(min_length=1)
    candidate_refs: list[ArtifactReference]
    before: dict[str, Any]
    after: dict[str, Any]
    diff: dict[str, Any]
    quality_delta: dict[str, Any]
    safety_delta: dict[str, Any]
    external_calls: dict[str, bool]
    errors: list[str]
    warnings: list[str]

    @field_validator("replay_id", "request_id")
    @classmethod
    def _validate_ids(cls, value: str, info: Any) -> str:
        return validate_governance_id(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _contract_shape(self) -> "ReplayRecord":
        assert_contract_shape("replay", self.model_dump(mode="python"))
        if self.mode == ReplayMode.OFFLINE and any(self.external_calls.values()):
            raise ValueError("offline replay must not record real external calls")
        return self


class AuditRecord(GovernanceBaseModel):
    audit_id: str
    target_version: str
    branch: str
    commit: str
    worktree: dict[str, Any]
    changed_files: list[str]
    test_results: dict[str, Any]
    replay_results: dict[str, Any]
    smoke_results: dict[str, Any]
    sensitive_file_check: dict[str, Any]
    external_calls: dict[str, bool]
    governance_data_integrity: dict[str, Any]
    status: AuditStatus
    problems: list[str]
    warnings: list[str]

    @field_validator("audit_id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        return validate_governance_id(value, field_name="audit_id")

    @model_validator(mode="after")
    def _contract_shape(self) -> "AuditRecord":
        assert_contract_shape("audit", self.model_dump(mode="python"))
        return self


SCHEMA_MODELS: Mapping[str, type[GovernanceBaseModel]] = {
    "incident_memory": IncidentMemoryRecord,
    "learning_signal": LearningSignalRecord,
    "proposal": ProposalRecord,
    "replay": ReplayRecord,
    "audit": AuditRecord,
}


def validate_governance_payload(
    contract_name: str,
    payload: Mapping[str, Any],
) -> GovernanceBaseModel:
    """Validate a dictionary against one of the frozen governance schemas."""

    try:
        model_type = SCHEMA_MODELS[contract_name]
    except KeyError as exc:
        raise ValueError(f"unknown governance schema: {contract_name!r}") from exc
    return model_type.model_validate(dict(payload))


__all__ = [
    "ArtifactReference",
    "AuditRecord",
    "GovernanceBaseModel",
    "IncidentMemoryRecord",
    "LearningSignalRecord",
    "ProposalRecord",
    "ReplayRecord",
    "SCHEMA_MODELS",
    "utc_now",
    "validate_governance_id",
    "validate_governance_payload",
]
