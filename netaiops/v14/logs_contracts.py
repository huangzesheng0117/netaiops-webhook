"""Frozen Webhook-side contracts for v14 Logs Evidence W1.

The FastMCP evidence status remains orthogonal to artifact/job lifecycle.
This deliberately avoids adding ``complete`` or ``provisional`` to the shared
v12 EvidenceStatus enum because those values describe collection coverage,
not evidence health.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator, model_validator

EXPECTED_LOG_TOOLS = frozenset(
    {
        "get_log_capabilities",
        "get_log_fields",
        "search_logs",
        "collect_log_evidence",
    }
)
ALLOWED_PROFILES = frozenset(
    {
        "cisco_aci_system_log",
        "cisco_switch_system_log",
        "f5_system_log",
        "fortigate_system_log",
    }
)
FORBIDDEN_CALLER_FIELDS = frozenset(
    {
        "cluster",
        "index",
        "index_pattern",
        "url",
        "api_key",
        "secret",
        "raw_dsl",
        "query_dsl",
        "body",
        "script",
        "runtime_mappings",
    }
)


class StringEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class IncidentTimeSource(StringEnum):
    EXPLICIT_FAULT_TIME = "explicit_fault_time"
    ALERTMANAGER_STARTS_AT = "alertmanager_starts_at"
    PROMETHEUS_FIRING_TIME = "prometheus_firing_time"
    WEBHOOK_RECEIVED_AT = "webhook_received_at"


class LogsArtifactPhase(StringEnum):
    INITIAL = "initial"
    COMPLETE = "complete"
    LATE_CHECK = "late_check"


class LogsCollectionState(StringEnum):
    PROVISIONAL = "provisional"
    COMPLETE = "complete"
    LATE_CHECK = "late_check"
    PARTIAL = "partial"
    NO_DATA = "no_data"
    FAILED = "failed"
    NOT_AVAILABLE = "not_available"


class LogsEvidenceStatus(StringEnum):
    SUCCESS = "success"
    NO_DATA = "no_data"
    PARTIAL = "partial"
    FAILED = "failed"
    NOT_AVAILABLE = "not_available"


class LogsJobState(StringEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class IncidentTimeDecision(StrictModel):
    incident_time: datetime
    source: IncidentTimeSource
    fallback_used: bool = False
    selection_reason: str = Field(min_length=1, max_length=256)
    candidates_present: tuple[IncidentTimeSource, ...] = ()
    candidates_invalid: tuple[IncidentTimeSource, ...] = ()

    @field_validator("incident_time")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("incident_time must be timezone-aware")
        return value.astimezone(timezone.utc)


class LogsCollectionRequest(StrictModel):
    profile_id: str
    incident_time: datetime
    window_before_minutes: int = Field(default=5, ge=0, le=15)
    window_after_minutes: int = Field(default=5, ge=0, le=15)
    phase: LogsArtifactPhase = LogsArtifactPhase.INITIAL
    device_ip: IPvAnyAddress | None = None
    device_name: str | None = Field(default=None, min_length=1, max_length=256)
    event_code: str | None = Field(default=None, min_length=1, max_length=256)
    severity: str | None = Field(default=None, min_length=1, max_length=64)
    keywords: tuple[str, ...] = ()
    max_raw_samples: int = Field(default=10, ge=1, le=20)

    @field_validator("profile_id")
    @classmethod
    def _profile(cls, value: str) -> str:
        if value not in ALLOWED_PROFILES:
            raise ValueError("profile_id is not allow-listed")
        return value

    @field_validator("incident_time")
    @classmethod
    def _incident_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("incident_time must be timezone-aware")
        return value.astimezone(timezone.utc)

    @field_validator("keywords")
    @classmethod
    def _keywords(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > 5:
            raise ValueError("keywords must contain <= 5 items")
        out: list[str] = []
        for item in value:
            cleaned = item.strip()
            if not cleaned:
                raise ValueError("keywords must not contain empty values")
            if len(cleaned) > 128:
                raise ValueError("each keyword must be <= 128 characters")
            if cleaned not in out:
                out.append(cleaned)
        return tuple(out)

    @model_validator(mode="after")
    def _window(self) -> "LogsCollectionRequest":
        total = self.window_before_minutes + self.window_after_minutes
        if total < 1 or total > 15:
            raise ValueError("total evidence window must be 1..15 minutes")
        return self

    def tool_arguments(self) -> dict[str, Any]:
        data = self.model_dump(mode="json", exclude_none=True)
        data["keywords"] = list(self.keywords)
        return data

    def selector_fingerprint(self) -> str:
        data = self.tool_arguments()
        data.pop("phase", None)
        encoded = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class LogsQueryWindow(StrictModel):
    start_time: datetime
    end_time: datetime

    @field_validator("start_time", "end_time")
    @classmethod
    def _aware_window_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("query_window timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def _ordered(self) -> "LogsQueryWindow":
        if self.end_time < self.start_time:
            raise ValueError("query_window end_time precedes start_time")
        return self


class LogsCoverage(StrictModel):
    state: LogsCollectionState
    window_complete: bool
    matched_total: int = Field(ge=0)
    analyzed_total: int = Field(ge=0)
    representative_sample_count: int = Field(ge=0, le=20)


class LogsCollectionResult(StrictModel):
    status: LogsEvidenceStatus
    profile_id: str
    phase: LogsArtifactPhase
    incident_time: datetime
    query_window: LogsQueryWindow
    matched_total: int = Field(default=0, ge=0)
    analyzed_total: int = Field(default=0, ge=0)
    earliest_timestamp: datetime | None = None
    latest_timestamp: datetime | None = None
    time_histogram: tuple[Mapping[str, Any], ...] = Field(default=(), max_length=32)
    severity_distribution: tuple[Mapping[str, Any], ...] = Field(default=(), max_length=20)
    event_code_distribution: tuple[Mapping[str, Any], ...] = Field(default=(), max_length=20)
    facility_distribution: tuple[Mapping[str, Any], ...] = Field(default=(), max_length=20)
    process_distribution: tuple[Mapping[str, Any], ...] = Field(default=(), max_length=20)
    representative_samples: tuple[Mapping[str, Any], ...] = Field(default=(), max_length=20)
    result_truncated: bool = False
    coverage: LogsCoverage
    missing_evidence: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    errors: tuple[Mapping[str, Any], ...] = ()
    request_id: str | None = Field(default=None, max_length=128)
    reason: str | None = Field(default=None, max_length=256)

    @field_validator("profile_id")
    @classmethod
    def _result_profile(cls, value: str) -> str:
        if value not in ALLOWED_PROFILES:
            raise ValueError("response profile_id is not allow-listed")
        return value

    @field_validator("incident_time")
    @classmethod
    def _result_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("response incident_time must be timezone-aware")
        return value.astimezone(timezone.utc)

    @field_validator("earliest_timestamp", "latest_timestamp")
    @classmethod
    def _optional_result_time(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("response evidence timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def _totals(self) -> "LogsCollectionResult":
        if self.analyzed_total > self.matched_total:
            raise ValueError("analyzed_total must not exceed matched_total")
        if self.coverage.matched_total != self.matched_total:
            raise ValueError("coverage.matched_total mismatch")
        if self.coverage.analyzed_total != self.analyzed_total:
            raise ValueError("coverage.analyzed_total mismatch")
        if self.coverage.representative_sample_count != len(self.representative_samples):
            raise ValueError("coverage representative_sample_count mismatch")
        expected_truncated = self.matched_total > len(self.representative_samples)
        if self.result_truncated != expected_truncated:
            raise ValueError("result_truncated does not match sample coverage")
        return self
