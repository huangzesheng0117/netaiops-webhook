"""Pydantic v2 contracts for the controlled v12 agent pipeline."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .schema_validator import (
    SCHEMA_VERSION,
    sanitize_sensitive_data,
    validate_contract_ref,
    validate_evidence_ref,
    validate_refs_for_request,
    validate_request_id,
)
from .status import (
    AgentName,
    AgentStatus,
    AlertLifecycleStatus,
    AlertSource,
    EvidenceBundleStatus,
    EvidenceSource,
    EvidenceStatus,
    ExternalCallStatus,
    JudgeStatus,
)


NonEmptyStr = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=512),
]
ShortIdentifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@/-]*$",
    ),
]
RequestId = Annotated[str, AfterValidator(validate_request_id)]
ContractRef = Annotated[str, AfterValidator(validate_contract_ref)]
EvidenceRef = Annotated[str, AfterValidator(validate_evidence_ref)]


class StrictContractModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )

    @field_validator("*", mode="before")
    @classmethod
    def _sanitize_field(cls, value: Any) -> Any:
        return sanitize_sensitive_data(value)


class VersionedRequestContract(StrictContractModel):
    schema_version: Literal["v12.1"]
    request_id: RequestId


class ContractNotice(StrictContractModel):
    code: ShortIdentifier
    message: NonEmptyStr
    stage: ShortIdentifier | None = None
    retryable: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class ExternalCallRecord(StrictContractModel):
    system: ShortIdentifier
    operation: ShortIdentifier
    status: ExternalCallStatus
    started_at: AwareDatetime
    finished_at: AwareDatetime
    duration_ms: int = Field(ge=0)
    request_ref: ContractRef | None = None
    response_ref: ContractRef | None = None
    error: ContractNotice | None = None

    @model_validator(mode="after")
    def _validate_time_order(self) -> "ExternalCallRecord":
        if self.finished_at < self.started_at:
            raise ValueError("finished_at must be greater than or equal to started_at")
        return self


class DeviceIdentity(StrictContractModel):
    name: NonEmptyStr | None = None
    ip: NonEmptyStr | None = None
    vendor: NonEmptyStr | None = None
    platform: NonEmptyStr | None = None
    site: NonEmptyStr | None = None

    @model_validator(mode="after")
    def _require_identity(self) -> "DeviceIdentity":
        if not self.name and not self.ip:
            raise ValueError("device requires at least name or ip")
        return self


class AlertObject(StrictContractModel):
    kind: ShortIdentifier
    name: NonEmptyStr
    identifier: NonEmptyStr | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class UnifiedAlertEvent(VersionedRequestContract):
    event_id: ShortIdentifier
    source: AlertSource
    alert_status: AlertLifecycleStatus
    alert_name: NonEmptyStr
    occurred_at: AwareDatetime
    received_at: AwareDatetime
    ends_at: AwareDatetime | None = None
    device: DeviceIdentity
    alert_object: AlertObject
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    family: ShortIdentifier | None = None
    event_key: NonEmptyStr | None = None
    correlation_hints: list[NonEmptyStr] = Field(default_factory=list)
    raw_payload_ref: ContractRef | None = None

    @model_validator(mode="after")
    def _validate_event(self) -> "UnifiedAlertEvent":
        if self.ends_at is not None and self.ends_at < self.occurred_at:
            raise ValueError("ends_at must not be earlier than occurred_at")
        refs = [self.raw_payload_ref] if self.raw_payload_ref else []
        validate_refs_for_request(self.request_id, refs)
        return self


class AgentRunRecord(VersionedRequestContract):
    agent_name: AgentName
    status: AgentStatus
    started_at: AwareDatetime
    finished_at: AwareDatetime
    duration_ms: int = Field(ge=0)
    inputs_ref: list[ContractRef] = Field(default_factory=list)
    outputs_ref: list[ContractRef] = Field(default_factory=list)
    warnings: list[ContractNotice] = Field(default_factory=list)
    errors: list[ContractNotice] = Field(default_factory=list)
    external_calls: list[ExternalCallRecord] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_run(self) -> "AgentRunRecord":
        if self.finished_at < self.started_at:
            raise ValueError("finished_at must be greater than or equal to started_at")
        external_refs = [
            ref
            for call in self.external_calls
            for ref in (call.request_ref, call.response_ref)
            if ref is not None
        ]
        validate_refs_for_request(
            self.request_id,
            [*self.inputs_ref, *self.outputs_ref, *external_refs],
        )
        return self


class EvidenceSourcePlan(StrictContractModel):
    source: EvidenceSource
    required: bool
    capability_ids: list[ShortIdentifier] = Field(default_factory=list)
    existing_artifact_refs: list[ContractRef] = Field(default_factory=list)
    constraints: dict[str, Any] = Field(default_factory=dict)
    max_items: int = Field(default=1, ge=0, le=100)


class EvidencePlan(VersionedRequestContract):
    plan_ref: ContractRef
    planner_mode: Literal["deterministic"]
    family: ShortIdentifier
    selected_playbook: ShortIdentifier | None = None
    sources: list[EvidenceSourcePlan] = Field(min_length=1, max_length=4)
    readonly_only: Literal[True]
    created_at: AwareDatetime

    @model_validator(mode="after")
    def _validate_plan(self) -> "EvidencePlan":
        validate_refs_for_request(self.request_id, [self.plan_ref])
        source_names = [str(item.source) for item in self.sources]
        if len(source_names) != len(set(source_names)):
            raise ValueError("evidence plan sources must be unique")
        refs = [
            ref
            for item in self.sources
            for ref in item.existing_artifact_refs
        ]
        validate_refs_for_request(self.request_id, refs)
        return self


class EvidenceEnvelope(VersionedRequestContract):
    source: EvidenceSource
    evidence_kind: Literal["evidence"]
    status: EvidenceStatus
    summary: str
    facts: dict[str, Any] = Field(default_factory=dict)
    scope: dict[str, Any] = Field(default_factory=dict)
    errors: list[ContractNotice] = Field(default_factory=list)
    warnings: list[ContractNotice] = Field(default_factory=list)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    collected_at: AwareDatetime
    reason: NonEmptyStr | None = None

    @model_validator(mode="after")
    def _validate_evidence(self) -> "EvidenceEnvelope":
        if self.source == EvidenceSource.KNOWLEDGE:
            raise ValueError("knowledge must use ContextEnvelope")
        if self.status == EvidenceStatus.NOT_AVAILABLE and not self.reason:
            raise ValueError("not_available evidence requires reason")
        if self.status in {EvidenceStatus.SUCCESS, EvidenceStatus.PARTIAL}:
            if not self.evidence_refs:
                raise ValueError("successful or partial evidence requires evidence_refs")
        validate_refs_for_request(
            self.request_id,
            self.evidence_refs,
            evidence_only=True,
        )
        return self


class ContextFact(StrictContractModel):
    key: ShortIdentifier
    value: Any
    source_ref: ContractRef
    as_of: AwareDatetime | None = None


class ContextEnvelope(VersionedRequestContract):
    source: Literal["knowledge"]
    evidence_kind: Literal["context"]
    status: EvidenceStatus
    reason: NonEmptyStr | None = None
    context_facts: list[ContextFact] = Field(default_factory=list)
    source_refs: list[ContractRef] = Field(default_factory=list)
    as_of: AwareDatetime | None = None
    collected_at: AwareDatetime

    @model_validator(mode="after")
    def _validate_context(self) -> "ContextEnvelope":
        refs = [
            *self.source_refs,
            *(fact.source_ref for fact in self.context_facts),
        ]
        validate_refs_for_request(self.request_id, refs)
        if self.status == EvidenceStatus.NOT_AVAILABLE and not self.reason:
            raise ValueError("not_available context requires reason")
        if self.status == EvidenceStatus.SUCCESS:
            if self.as_of is None:
                raise ValueError("successful context requires as_of")
            if not self.source_refs:
                raise ValueError("successful context requires source_refs")
        return self


class EvidenceCollection(StrictContractModel):
    metrics: EvidenceEnvelope
    device: EvidenceEnvelope
    logs: EvidenceEnvelope
    knowledge: ContextEnvelope

    @model_validator(mode="after")
    def _validate_sources(self) -> "EvidenceCollection":
        expected = {
            "metrics": self.metrics.source,
            "device": self.device.source,
            "logs": self.logs.source,
            "knowledge": self.knowledge.source,
        }
        for key, actual in expected.items():
            if str(actual) != key:
                raise ValueError(f"{key} envelope source must be {key}")
        return self


class EvidenceBundle(VersionedRequestContract):
    event_ref: ContractRef
    plan_ref: ContractRef
    evidence: EvidenceCollection
    bundle_status: EvidenceBundleStatus
    built_at: AwareDatetime

    @model_validator(mode="after")
    def _validate_bundle(self) -> "EvidenceBundle":
        validate_refs_for_request(
            self.request_id,
            [self.event_ref, self.plan_ref],
        )
        request_ids = {
            self.evidence.metrics.request_id,
            self.evidence.device.request_id,
            self.evidence.logs.request_id,
            self.evidence.knowledge.request_id,
        }
        if request_ids != {self.request_id}:
            raise ValueError("all evidence envelopes must match bundle request_id")
        return self


class EvidenceConflict(StrictContractModel):
    statement: NonEmptyStr
    evidence_refs: list[EvidenceRef] = Field(min_length=2)
    severity: Literal["low", "medium", "high"]


class EvidenceJudgeResult(VersionedRequestContract):
    status: JudgeStatus
    required_sources: list[EvidenceSource] = Field(default_factory=list)
    missing_required_sources: list[EvidenceSource] = Field(default_factory=list)
    missing_optional_sources: list[EvidenceSource] = Field(default_factory=list)
    conflicts: list[EvidenceConflict] = Field(default_factory=list)
    rca_allowed: bool
    confidence_cap: float = Field(ge=0.0, le=1.0)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    judged_at: AwareDatetime

    @model_validator(mode="after")
    def _validate_judge(self) -> "EvidenceJudgeResult":
        if self.status in {JudgeStatus.INSUFFICIENT, JudgeStatus.BLOCKED}:
            if self.rca_allowed:
                raise ValueError("insufficient or blocked evidence cannot allow RCA")
        all_refs = [
            *self.evidence_refs,
            *(
                ref
                for conflict in self.conflicts
                for ref in conflict.evidence_refs
            ),
        ]
        validate_refs_for_request(
            self.request_id,
            all_refs,
            evidence_only=True,
        )
        return self


class RCACandidate(StrictContractModel):
    statement: NonEmptyStr
    confidence: float = Field(ge=0.0, le=1.0)
    supporting_evidence_refs: list[EvidenceRef] = Field(min_length=1)
    contradicting_evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    missing_evidence: list[NonEmptyStr] = Field(default_factory=list)
    uncertainties: list[NonEmptyStr] = Field(default_factory=list)
    scope: dict[str, Any] = Field(default_factory=dict)


class RCAResult(VersionedRequestContract):
    status: AgentStatus
    event_ref: ContractRef
    bundle_ref: ContractRef
    judge_ref: ContractRef
    candidates: list[RCACandidate] = Field(default_factory=list)
    missing_evidence: list[NonEmptyStr] = Field(default_factory=list)
    uncertainties: list[NonEmptyStr] = Field(default_factory=list)
    generated_at: AwareDatetime
    provider: NonEmptyStr | None = None

    @model_validator(mode="after")
    def _validate_rca(self) -> "RCAResult":
        validate_refs_for_request(
            self.request_id,
            [self.event_ref, self.bundle_ref, self.judge_ref],
        )
        if self.status in {AgentStatus.SUCCESS, AgentStatus.PARTIAL}:
            if not self.candidates:
                raise ValueError("successful or partial RCA requires candidates")
        elif self.candidates:
            raise ValueError("failed, skipped, or unavailable RCA cannot have candidates")
        refs = [
            ref
            for candidate in self.candidates
            for ref in (
                *candidate.supporting_evidence_refs,
                *candidate.contradicting_evidence_refs,
            )
        ]
        validate_refs_for_request(
            self.request_id,
            refs,
            evidence_only=True,
        )
        return self


class ReportSection(StrictContractModel):
    key: ShortIdentifier
    title: NonEmptyStr
    body: NonEmptyStr
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)


class ReportArtifact(VersionedRequestContract):
    status: AgentStatus
    title: NonEmptyStr
    summary: NonEmptyStr
    sections: list[ReportSection] = Field(default_factory=list)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    artifact_refs: list[ContractRef] = Field(default_factory=list)
    generated_at: AwareDatetime
    notification_compatible: bool = True

    @model_validator(mode="after")
    def _validate_report(self) -> "ReportArtifact":
        evidence_refs = [
            *self.evidence_refs,
            *(ref for section in self.sections for ref in section.evidence_refs),
        ]
        validate_refs_for_request(
            self.request_id,
            evidence_refs,
            evidence_only=True,
        )
        validate_refs_for_request(self.request_id, self.artifact_refs)
        return self


CONTRACT_MODELS: tuple[type[VersionedRequestContract], ...] = (
    UnifiedAlertEvent,
    AgentRunRecord,
    EvidencePlan,
    EvidenceEnvelope,
    ContextEnvelope,
    EvidenceBundle,
    EvidenceJudgeResult,
    RCAResult,
    ReportArtifact,
)

assert SCHEMA_VERSION == "v12.1"
