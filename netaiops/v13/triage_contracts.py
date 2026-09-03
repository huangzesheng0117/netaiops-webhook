"""V13-D2 deterministic Triage ownership contracts.

D2 extends the existing v12 Triage/UnifiedAlertEvent contract instead of
creating a second classification model.  Build/store/shadow stages prove that
one Triage owner can emit the canonical family result while every non-migrated
family has an explicit legacy fallback.  Production Primary activation remains
forbidden in D2.
"""

from __future__ import annotations

import hashlib
import re
from typing import Annotated, Any, Literal, Mapping

from pydantic import AfterValidator, AwareDatetime, Field, model_validator

from netaiops.v12.contracts import (
    RequestId,
    ShortIdentifier,
    StrictContractModel,
    UnifiedAlertEvent,
)
from netaiops.v12.schema_validator import sanitize_sensitive_data, stable_json_dumps


V13_TRIAGE_SCHEMA_VERSION = "v13.0"
MIGRATED_FAMILIES = (
    "interface_status_or_flap",
    "interface_or_link_utilization_high",
    "interface_traffic_anomaly",
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _validate_sha256(value: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise ValueError("fingerprint must be a lowercase SHA-256 hex digest")
    return text


Sha256Hex = Annotated[str, AfterValidator(_validate_sha256)]


def stable_fingerprint(value: Mapping[str, Any]) -> str:
    if not isinstance(value, Mapping):
        raise ValueError("fingerprint input must be a mapping")
    payload = stable_json_dumps(sanitize_sensitive_data(dict(value)))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class TriageOwnershipRecord(StrictContractModel):
    """Canonical D2 wrapper around the existing v12 Triage output."""

    schema_version: Literal["v13.0"] = V13_TRIAGE_SCHEMA_VERSION
    trace_type: Literal["triage_classification_owner"] = "triage_classification_owner"
    request_id: RequestId
    source: Literal["alertmanager", "elastic", "replay"]
    mode: Literal["build_only", "store_only", "shadow"]
    classification_owner: Literal["triage"] = "triage"
    classification_owner_count: Literal[1] = 1
    classification_engine: Literal["family_registry"] = "family_registry"
    triage_agent_reused: Literal[True] = True
    classification_call_count: Literal[1] = 1
    legacy_reclassification_performed: Literal[False] = False
    external_calls_performed: Literal[False] = False
    primary_entry_activated: Literal[False] = False
    normalized_event_fingerprint: Sha256Hex
    triage_output_ref: str
    unified_event: UnifiedAlertEvent
    family: ShortIdentifier
    family_confidence: Literal["high", "medium", "low"]
    match_source: str = ""
    match_reason: str = ""
    target_kind: str = "generic"
    target_scope: dict[str, Any]
    auto_execute_allowed: bool = False
    family_result: dict[str, Any] = Field(default_factory=dict)
    migrated_family: bool
    routing_action: Literal["controlled_orchestrator", "fallback_legacy"]
    fallback_reason: str | None = None
    classified_at: AwareDatetime

    @model_validator(mode="after")
    def _validate_ownership(self) -> "TriageOwnershipRecord":
        if self.unified_event.request_id != self.request_id:
            raise ValueError("UnifiedAlertEvent request_id must match owner record")
        if (self.unified_event.family or "generic_network_readonly") != self.family:
            raise ValueError("UnifiedAlertEvent family must match canonical family")
        if self.family_result:
            if str(self.family_result.get("family") or "").strip() != self.family:
                raise ValueError("family_result family must match canonical family")
        expected_migrated = self.family in MIGRATED_FAMILIES
        if self.migrated_family != expected_migrated:
            raise ValueError("migrated_family does not match frozen D2 family set")
        if self.migrated_family:
            if self.routing_action != "controlled_orchestrator":
                raise ValueError("migrated family must route to controlled_orchestrator")
            if self.fallback_reason is not None:
                raise ValueError("migrated family must not contain fallback_reason")
        else:
            if self.routing_action != "fallback_legacy":
                raise ValueError("non-migrated family must explicitly fallback_legacy")
            if not self.fallback_reason:
                raise ValueError("fallback_legacy requires fallback_reason")
        return self


class TriageShadowComparison(StrictContractModel):
    """Compare Triage owner output with a persisted legacy plan only.

    The legacy side is never reclassified during D2 shadow comparison.
    """

    schema_version: Literal["v13.0"] = V13_TRIAGE_SCHEMA_VERSION
    trace_type: Literal["triage_shadow_comparison"] = "triage_shadow_comparison"
    request_id: RequestId
    triage_owner_ref: str
    triage_family: ShortIdentifier
    legacy_family: str = ""
    legacy_source: Literal["persisted_legacy_plan_artifact"] = (
        "persisted_legacy_plan_artifact"
    )
    comparison: Literal["match", "mismatch", "legacy_missing"]
    migrated_family: bool
    migration_acceptable: bool
    routing_action: Literal["controlled_orchestrator", "fallback_legacy"]
    legacy_reclassification_performed: Literal[False] = False
    external_calls_performed: Literal[False] = False
    compared_at: AwareDatetime

    @model_validator(mode="after")
    def _validate_shadow(self) -> "TriageShadowComparison":
        if self.migrated_family:
            if self.migration_acceptable != (self.comparison == "match"):
                raise ValueError(
                    "migrated family is acceptable only when persisted legacy family matches"
                )
        elif self.routing_action != "fallback_legacy":
            raise ValueError("non-migrated shadow result must fallback_legacy")
        return self
