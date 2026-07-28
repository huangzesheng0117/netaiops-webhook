"""Frozen contracts for v12 fail-open Shadow Integration."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal, Mapping

from pydantic import Field, field_validator, model_validator

from .contracts import StrictContractModel
from .redaction import redact_for_persistence
from .schema_validator import validate_contract_ref


class ShadowStatus(str, Enum):
    DISABLED = "disabled"
    SKIPPED_ROUTE = "skipped_route"
    SKIPPED_LEGACY_INCOMPLETE = "skipped_legacy_incomplete"
    COMPLETED = "completed"
    FAILED_OPEN = "failed_open"


class ShadowIntegrationSettings(StrictContractModel):
    enabled: bool = False
    mode: Literal["shadow"] = "shadow"
    fail_open_to_legacy: Literal[True] = True
    timeout_ms: int = Field(default=15000, ge=100, le=60000)
    allowed_routes: tuple[str, ...] = ("/webhook/alertmanager",)
    excluded_routes: tuple[str, ...] = (
        "/light-alert/alertmanager",
    )
    send_notification: Literal[False] = False
    replace_production_card: Literal[False] = False
    rca_enabled: Literal[False] = False

    @field_validator("allowed_routes", "excluded_routes")
    @classmethod
    def _routes_are_safe(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        normalized: list[str] = []
        for route in value:
            text = str(route).strip()
            if (
                not text.startswith("/")
                or "?" in text
                or "#" in text
                or ".." in text
            ):
                raise ValueError("shadow routes must be safe absolute paths")
            if text not in normalized:
                normalized.append(text)
        if not normalized:
            raise ValueError("shadow route sets must not be empty")
        return tuple(normalized)

    @model_validator(mode="after")
    def _route_sets_do_not_overlap(
        self,
    ) -> "ShadowIntegrationSettings":
        overlap = set(self.allowed_routes) & set(
            self.excluded_routes
        )
        if overlap:
            raise ValueError(
                "allowed_routes and excluded_routes must not overlap"
            )
        return self


class LegacyDeliverySnapshot(StrictContractModel):
    schema_version: Literal["v12.1"] = "v12.1"
    request_id: str
    route: str
    alert_status: Literal["firing", "resolved"]
    legacy_completed: bool
    legacy_notification_count: int = Field(ge=0)
    legacy_notification_ref: str | None = None
    captured_at: datetime
    legacy_metadata: Mapping[str, Any] = Field(
        default_factory=dict
    )

    @field_validator("route")
    @classmethod
    def _route_is_absolute(cls, value: str) -> str:
        text = str(value).strip()
        if not text.startswith("/") or ".." in text:
            raise ValueError("route must be a safe absolute path")
        return text

    @field_validator("legacy_notification_ref")
    @classmethod
    def _notification_ref_is_valid(
        cls,
        value: str | None,
    ) -> str | None:
        if value is not None:
            validate_contract_ref(value)
        return value


class ShadowPipelineRequest(StrictContractModel):
    schema_version: Literal["v12.1"] = "v12.1"
    request_id: str
    route: str
    alert_status: Literal["firing", "resolved"]
    legacy_notification_count: int = Field(ge=0)
    legacy_notification_ref: str | None = None
    captured_at: datetime
    input_refs: list[str] = Field(default_factory=list)
    input_snapshot: Mapping[str, Any] = Field(
        default_factory=dict
    )

    @field_validator("input_refs")
    @classmethod
    def _input_refs_are_valid(
        cls,
        value: list[str],
    ) -> list[str]:
        output = sorted(set(value))
        for reference in output:
            validate_contract_ref(reference)
        return output

    @field_validator("input_snapshot", mode="after")
    @classmethod
    def _input_snapshot_uses_persistence_redaction(
        cls,
        value: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        redacted = redact_for_persistence(value)
        if not isinstance(redacted, Mapping):
            raise ValueError(
                "input_snapshot must remain a mapping"
            )
        return redacted


class ShadowPipelineResult(StrictContractModel):
    schema_version: Literal["v12.1"] = "v12.1"
    request_id: str
    final_state: Literal["completed"]
    artifact_refs: list[str] = Field(default_factory=list)
    report_generated: bool = False
    trace_written: bool = False
    notification_sent: Literal[False] = False
    notification_count: Literal[0] = 0
    second_card_sent: Literal[False] = False
    production_card_replaced: Literal[False] = False
    production_glm_called: Literal[False] = False
    mcp_called: Literal[False] = False
    tool_called: Literal[False] = False
    automatic_followup_queries: Literal[False] = False
    external_calls: list[Mapping[str, Any]] = Field(
        default_factory=list
    )

    @field_validator("artifact_refs")
    @classmethod
    def _artifact_refs_are_valid(
        cls,
        value: list[str],
    ) -> list[str]:
        output = sorted(set(value))
        for reference in output:
            validate_contract_ref(reference)
        return output

    @model_validator(mode="after")
    def _external_calls_are_empty(
        self,
    ) -> "ShadowPipelineResult":
        if self.external_calls:
            raise ValueError(
                "Batch M Shadow result must not expose external calls"
            )
        return self


class ShadowIntegrationAudit(StrictContractModel):
    schema_version: Literal["v12.1"] = "v12.1"
    request_id: str
    route: str
    status: ShadowStatus
    reason: str
    legacy_preserved: Literal[True] = True
    fail_open_to_legacy: Literal[True] = True
    legacy_notification_count: int = Field(ge=0)
    shadow_notification_count: Literal[0] = 0
    notification_count_delta: Literal[0] = 0
    second_card_sent: Literal[False] = False
    production_card_replaced: Literal[False] = False
    production_glm_called: Literal[False] = False
    mcp_called: Literal[False] = False
    tool_called: Literal[False] = False
    report_generated: bool = False
    trace_written: bool = False
    artifact_refs: list[str] = Field(default_factory=list)
    error_code: str | None = None
    started_at: datetime
    finished_at: datetime
    duration_ms: int = Field(ge=0)

    @field_validator("artifact_refs")
    @classmethod
    def _audit_refs_are_valid(
        cls,
        value: list[str],
    ) -> list[str]:
        output = sorted(set(value))
        for reference in output:
            validate_contract_ref(reference)
        return output

    @model_validator(mode="after")
    def _timestamps_are_consistent(
        self,
    ) -> "ShadowIntegrationAudit":
        for value in (self.started_at, self.finished_at):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(
                    "Shadow audit timestamps must be timezone-aware"
                )
        if self.finished_at < self.started_at:
            raise ValueError(
                "finished_at must not precede started_at"
            )
        if (
            self.status == ShadowStatus.COMPLETED
            and self.error_code is not None
        ):
            raise ValueError(
                "completed Shadow audit cannot contain error_code"
            )
        if (
            self.status == ShadowStatus.FAILED_OPEN
            and not self.error_code
        ):
            raise ValueError(
                "failed_open Shadow audit requires error_code"
            )
        return self
