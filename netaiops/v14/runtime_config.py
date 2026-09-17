"""Frozen runtime control for v14 Logs Evidence.

The Evidence MCP endpoint is code-owned and cannot be supplied by runtime
configuration. W1 installs with all production-use flags disabled. W2 may
later enable store-only real querying under a separate approved activation.
"""
from __future__ import annotations

from pathlib import Path
from typing import Mapping

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

SCHEMA_VERSION = "v14.w1.logs-runtime.v1"
FIXED_EVIDENCE_MCP_URL = "http://10.191.97.137:10002/mcp"
DEFAULT_CONFIG_PATH = Path("/opt/netaiops-webhook/config/v14_logs_w1.yaml")
WORKER_POLL_SECONDS = 30

_ALLOWED_KEYS = frozenset({
    "schema_version", "activation_id", "enabled", "store_evidence_enabled",
    "real_query_enabled", "include_in_analysis", "include_in_review",
    "include_in_rca", "include_in_card", "window_before_minutes",
    "window_after_minutes", "ingestion_grace_seconds", "max_raw_samples",
    "retry_delay_seconds", "max_attempts_per_phase", "late_check_enabled",
    "late_check_delay_seconds", "startup_recovery_max_jobs",
})
_FORBIDDEN_PARTS = frozenset({
    "password", "passwd", "secret", "token", "api", "key", "url",
    "cluster", "index", "dsl", "script", "runtime", "mapping",
})


class LogsRuntimeConfigError(ValueError):
    pass


class LogsRuntimeSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = SCHEMA_VERSION
    activation_id: str = "w1-disabled-default"
    enabled: bool = False
    store_evidence_enabled: bool = False
    real_query_enabled: bool = False
    include_in_analysis: bool = False
    include_in_review: bool = False
    include_in_rca: bool = False
    include_in_card: bool = False
    window_before_minutes: int = Field(default=5, ge=0, le=15)
    window_after_minutes: int = Field(default=5, ge=0, le=15)
    ingestion_grace_seconds: int = Field(default=120, ge=0, le=1800)
    max_raw_samples: int = Field(default=10, ge=1, le=20)
    retry_delay_seconds: int = Field(default=60, ge=1, le=1800)
    max_attempts_per_phase: int = Field(default=2, ge=1, le=3)
    late_check_enabled: bool = False
    late_check_delay_seconds: int = Field(default=300, ge=30, le=3600)
    startup_recovery_max_jobs: int = Field(default=16, ge=1, le=100)

    @model_validator(mode="after")
    def _boundary(self) -> "LogsRuntimeSettings":
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("runtime schema_version mismatch")
        if not self.activation_id.strip() or len(self.activation_id) > 128:
            raise ValueError("activation_id is required and must be <=128 chars")

        total = self.window_before_minutes + self.window_after_minutes
        if total < 1 or total > 15:
            raise ValueError("total evidence window must be 1..15 minutes")

        active_flags = (
            self.store_evidence_enabled
            or self.real_query_enabled
            or self.include_in_analysis
            or self.include_in_review
            or self.include_in_rca
            or self.include_in_card
        )
        if not self.enabled and active_flags:
            raise ValueError("disabled runtime cannot enable production-use flags")
        if self.real_query_enabled and not self.store_evidence_enabled:
            raise ValueError("real_query_enabled requires store_evidence_enabled")
        if (
            self.include_in_analysis
            or self.include_in_review
            or self.include_in_rca
            or self.include_in_card
        ) and not self.store_evidence_enabled:
            raise ValueError("include flags require store_evidence_enabled")

        # R1 is frozen as store-only -> Review -> RCA -> Card.  Analysis is an
        # internal prerequisite for the Review path, not an independently
        # approved external checkpoint.
        if self.include_in_review and not self.include_in_analysis:
            raise ValueError("include_in_review requires include_in_analysis")
        if self.include_in_rca and not self.include_in_review:
            raise ValueError("include_in_rca requires include_in_review")
        if self.include_in_card and not self.include_in_rca:
            raise ValueError("include_in_card requires include_in_rca")
        return self


def disabled_settings() -> LogsRuntimeSettings:
    return LogsRuntimeSettings()


def load_runtime_settings(path: str | Path = DEFAULT_CONFIG_PATH) -> LogsRuntimeSettings:
    config_path = Path(path)
    if not config_path.exists():
        return disabled_settings()
    if config_path.is_symlink() or not config_path.is_file():
        raise LogsRuntimeConfigError("runtime config must be a regular file")
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise LogsRuntimeConfigError("runtime config cannot be decoded") from exc
    if not isinstance(raw, Mapping):
        raise LogsRuntimeConfigError("runtime config root must be an object")

    keys = {str(key) for key in raw}
    unknown = sorted(keys - _ALLOWED_KEYS)
    if unknown:
        raise LogsRuntimeConfigError("unknown runtime keys: " + ", ".join(unknown))
    for key in keys:
        normalized = str(key).lower().replace("-", "_")
        parts = {part for part in normalized.split("_") if part}
        if parts & _FORBIDDEN_PARTS:
            raise LogsRuntimeConfigError(
                "runtime config contains forbidden connection/secret key"
            )

    try:
        return LogsRuntimeSettings.model_validate(dict(raw))
    except Exception as exc:
        raise LogsRuntimeConfigError("runtime config failed validation") from exc
