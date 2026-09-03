"""Deterministic v13 Evidence Capability contracts.

This module extends, rather than replaces, the frozen v12 EvidenceEnvelope.
It introduces source-specific capability requests, stable fingerprints,
capability-level deduplication identity, and persistent checkpoint contracts.
No raw PromQL or raw CLI field is accepted by these contracts.
"""

from __future__ import annotations

import hashlib
import re
from typing import Annotated, Any, Literal, Mapping, Union

from pydantic import (
    AfterValidator,
    AwareDatetime,
    Field,
    TypeAdapter,
    model_validator,
)

from netaiops.v12.contracts import (
    ContractNotice,
    EvidenceEnvelope,
    RequestId,
    ShortIdentifier,
    StrictContractModel,
)
from netaiops.v12.schema_validator import (
    sanitize_sensitive_data,
    stable_json_dumps,
)
from netaiops.v12.status import EvidenceStatus


V13_CAPABILITY_SCHEMA_VERSION = "v13.0"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _validate_sha256(value: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise ValueError("fingerprint must be a lowercase SHA-256 hex digest")
    return text


Sha256Hex = Annotated[str, AfterValidator(_validate_sha256)]


def _sha256_payload(value: Any) -> str:
    payload = stable_json_dumps(sanitize_sensitive_data(value))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_plan_fingerprint(plan_payload: Mapping[str, Any]) -> str:
    """Build a stable, secret-sanitized plan fingerprint."""

    if not isinstance(plan_payload, Mapping) or not plan_payload:
        raise ValueError("plan_payload must be a non-empty mapping")
    return _sha256_payload({"plan": dict(plan_payload)})


def build_template_fingerprint(
    template_id: str,
    parameters: Mapping[str, Any] | None = None,
) -> str:
    """Fingerprint an approved template identity and bounded parameters.

    The function accepts a template identifier and structured parameters only;
    it is intentionally not a raw PromQL/CLI generator.
    """

    template = str(template_id or "").strip()
    if not template:
        raise ValueError("template_id is required")
    params = dict(parameters or {})
    return _sha256_payload({"template_id": template, "parameters": params})


class CapabilityRequestBase(StrictContractModel):
    """Common identity shared by metrics and device capability requests."""

    schema_version: Literal["v13.0"] = V13_CAPABILITY_SCHEMA_VERSION
    request_id: RequestId
    family: ShortIdentifier
    capability: ShortIdentifier
    target: dict[str, Any] = Field(min_length=1)
    plan_fingerprint: Sha256Hex
    template_fingerprint: Sha256Hex
    required: bool = True
    max_attempts: int = Field(default=2, ge=1, le=2)

    @model_validator(mode="after")
    def _validate_target(self) -> "CapabilityRequestBase":
        # StrictContractModel already sanitized the field in a before-validator.
        # Do not assign to self here because validate_assignment=True would
        # recursively re-enter this model validator.
        if not isinstance(self.target, dict) or not self.target:
            raise ValueError("target must remain a non-empty mapping")
        return self


class MetricsCapabilityRequest(CapabilityRequestBase):
    """Metrics owner contract: approved template identity, never raw PromQL."""

    source: Literal["metrics"] = "metrics"
    query_template_id: ShortIdentifier
    promql_generation_allowed: Literal[False] = False


class DeviceCapabilityRequest(CapabilityRequestBase):
    """Device owner contract: approved Playbook/template and readonly policy."""

    source: Literal["device"] = "device"
    command_template_id: ShortIdentifier
    playbook_id: ShortIdentifier
    readonly_only: Literal[True] = True
    command_generation_allowed: Literal[False] = False
    safety_policy_allowed: bool = True
    safety_policy_reasons: list[str] = Field(default_factory=list, max_length=32)


CapabilityRequest = Union[MetricsCapabilityRequest, DeviceCapabilityRequest]
CAPABILITY_REQUEST_ADAPTER = TypeAdapter(CapabilityRequest)


def build_capability_dedup_key(request: CapabilityRequest) -> str:
    """Build the capability-level idempotency key required by V13-D1.

    It includes the documented minimum identity plus source separation:
    request_id, family, source, capability, target, plan fingerprint, and
    query/command template fingerprint.
    """

    payload = {
        "request_id": request.request_id,
        "family": request.family,
        "source": request.source,
        "capability": request.capability,
        "target": request.target,
        "plan_fingerprint": request.plan_fingerprint,
        "template_fingerprint": request.template_fingerprint,
    }
    return _sha256_payload(payload)


def build_target_fingerprint(request: CapabilityRequest) -> str:
    return _sha256_payload({"target": request.target})


CheckpointStatus = Literal[
    "in_progress",
    "success",
    "partial",
    "no_data",
    "not_available",
    "failed",
    "timeout",
    "policy_blocked",
]


class CapabilityCheckpoint(StrictContractModel):
    schema_version: Literal["v13.0"] = V13_CAPABILITY_SCHEMA_VERSION
    dedup_key: Sha256Hex
    request_id: RequestId
    source: Literal["metrics", "device"]
    family: ShortIdentifier
    capability: ShortIdentifier
    target_fingerprint: Sha256Hex
    plan_fingerprint: Sha256Hex
    template_fingerprint: Sha256Hex
    status: CheckpointStatus
    attempts: int = Field(ge=0, le=2)
    max_attempts: int = Field(ge=1, le=2)
    terminal: bool
    reusable: bool
    envelope: EvidenceEnvelope | None = None
    last_error: ContractNotice | None = None
    created_at: AwareDatetime
    updated_at: AwareDatetime

    @model_validator(mode="after")
    def _validate_checkpoint(self) -> "CapabilityCheckpoint":
        if self.updated_at < self.created_at:
            raise ValueError("checkpoint updated_at must not precede created_at")
        if self.attempts > self.max_attempts:
            raise ValueError("checkpoint attempts cannot exceed max_attempts")
        if self.status == "in_progress":
            if self.terminal or self.reusable:
                raise ValueError("in_progress checkpoint cannot be terminal/reusable")
            if self.envelope is not None:
                raise ValueError("in_progress checkpoint cannot contain envelope")
            return self

        if self.envelope is None:
            raise ValueError("completed checkpoint requires EvidenceEnvelope")
        if self.envelope.request_id != self.request_id:
            raise ValueError("checkpoint/envelope request_id mismatch")
        if str(self.envelope.source) != self.source:
            raise ValueError("checkpoint/envelope source mismatch")

        expected = {
            "success": EvidenceStatus.SUCCESS,
            "partial": EvidenceStatus.PARTIAL,
            "no_data": EvidenceStatus.NO_DATA,
            "not_available": EvidenceStatus.NOT_AVAILABLE,
            "failed": EvidenceStatus.FAILED,
            "timeout": EvidenceStatus.FAILED,
            "policy_blocked": EvidenceStatus.SKIPPED,
        }[self.status]
        if self.envelope.status != expected:
            raise ValueError("checkpoint status does not match EvidenceEnvelope status")

        should_terminal = self.status in {
            "success",
            "partial",
            "no_data",
            "not_available",
            "policy_blocked",
        } or self.attempts >= self.max_attempts
        if self.terminal != should_terminal:
            raise ValueError("checkpoint terminal flag is inconsistent")
        if self.reusable != self.terminal:
            raise ValueError("terminal checkpoint must be reusable and vice versa")
        return self


DecisionAction = Literal[
    "executed",
    "retried",
    "reused_checkpoint",
    "policy_blocked",
]


class CapabilityDecision(StrictContractModel):
    schema_version: Literal["v13.0"] = V13_CAPABILITY_SCHEMA_VERSION
    action: DecisionAction
    dedup_key: Sha256Hex
    checkpoint_ref: str
    external_call_performed: bool
    checkpoint: CapabilityCheckpoint

    @model_validator(mode="after")
    def _validate_decision(self) -> "CapabilityDecision":
        if self.dedup_key != self.checkpoint.dedup_key:
            raise ValueError("decision/checkpoint dedup_key mismatch")
        if self.action in {"reused_checkpoint", "policy_blocked"}:
            if self.external_call_performed:
                raise ValueError("reuse/policy block cannot perform an external call")
        return self
