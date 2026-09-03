"""V13-D3 deterministic Metrics/Device ownership contracts.

D3 does not create a second Evidence schema.  It binds the D1 capability
request/decision contracts to one upper owner per evidence source and records
whether the old active caller must be fenced for the same request/source.
"""

from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, model_validator

from netaiops.v12.contracts import RequestId, ShortIdentifier, StrictContractModel
from netaiops.v12.status import EvidenceStatus

from .capability_contracts import CapabilityDecision, Sha256Hex


V13_D3_SCHEMA_VERSION = "v13.0"
APPROVED_OWNER_FAMILIES = (
    "interface_status_or_flap",
    "interface_or_link_utilization_high",
    "interface_traffic_anomaly",
)


class EvidenceOwnerRecord(StrictContractModel):
    schema_version: Literal["v13.0"] = V13_D3_SCHEMA_VERSION
    request_id: RequestId
    family: ShortIdentifier
    source: Literal["metrics", "device"]
    owner: Literal["metrics_agent", "device_agent"]
    owner_count: Literal[1] = 1
    capability: ShortIdentifier
    dedup_key: Sha256Hex
    checkpoint_ref: str
    decision_action: Literal[
        "executed",
        "retried",
        "reused_checkpoint",
        "policy_blocked",
    ]
    evidence_status: EvidenceStatus
    external_call_performed: bool
    legacy_active_call_allowed: Literal[False] = False
    arbitrary_query_or_command_generated: Literal[False] = False
    write_command_executed: Literal[False] = False
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def _validate_owner(self) -> "EvidenceOwnerRecord":
        if self.family not in APPROVED_OWNER_FAMILIES:
            raise ValueError("D3 owner record requires an approved family")
        expected = "metrics_agent" if self.source == "metrics" else "device_agent"
        if self.owner != expected:
            raise ValueError("source/owner mismatch")
        return self


class LegacyCallFenceRecord(StrictContractModel):
    schema_version: Literal["v13.0"] = V13_D3_SCHEMA_VERSION
    request_id: RequestId
    family: ShortIdentifier
    source: Literal["metrics", "device"]
    dedup_key: Sha256Hex
    owner: Literal["metrics_agent", "device_agent"]
    active: Literal[True] = True
    legacy_action: Literal["skip_duplicate"] = "skip_duplicate"
    reason: Literal["v13_owner_claimed_source"] = "v13_owner_claimed_source"
    external_call_already_attempted: bool
    recorded_at: AwareDatetime


class D3OwnerOutcome(StrictContractModel):
    schema_version: Literal["v13.0"] = V13_D3_SCHEMA_VERSION
    owner_record: EvidenceOwnerRecord
    fence_record: LegacyCallFenceRecord
    capability_decision: CapabilityDecision

    @model_validator(mode="after")
    def _validate_consistency(self) -> "D3OwnerOutcome":
        if self.owner_record.request_id != self.fence_record.request_id:
            raise ValueError("owner/fence request_id mismatch")
        if self.owner_record.dedup_key != self.fence_record.dedup_key:
            raise ValueError("owner/fence dedup mismatch")
        if self.owner_record.dedup_key != self.capability_decision.dedup_key:
            raise ValueError("owner/decision dedup mismatch")
        return self
