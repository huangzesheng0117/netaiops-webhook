"""Batch P2-A controlled real-Agent Canary control-plane contract.

This module defines only configuration, policy, call-budget, and audit
contracts. It does not contain a Prometheus, Netmiko, GLM, FastMCP,
Elasticsearch, HTTP, socket, subprocess, notification, or device execution
implementation.

P2-A keeps every real external call disabled. Later P2 batches may inject
approved clients behind these frozen contracts after separate approval.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml


P2_SCHEMA_VERSION = "v12-p2-controlled-canary-1"
DEFAULT_PROJECT_ROOT = Path("/opt/netaiops-webhook")
DEFAULT_RUNTIME_CONFIG = (
    DEFAULT_PROJECT_ROOT / "config" / "v12_p2_canary.yaml"
)
DEFAULT_ALLOWED_FAMILIES = (
    "interface_status_or_flap",
    "interface_or_link_utilization_high",
    "interface_traffic_anomaly",
)
P2A_FORBIDDEN_CONFIG_KEYS = frozenset(
    {
        "password",
        "passwd",
        "api_key",
        "apikey",
        "authorization",
        "bearer",
        "token",
        "secret",
        "private_key",
    }
)


class P2ContractError(RuntimeError):
    """Raised when the P2 control-plane contract is violated."""


class P2CallKind(str, Enum):
    METRICS = "prometheus_mcp"
    DEVICE = "netmiko_mcp"
    RCA = "glm_rca"


@dataclass(frozen=True, slots=True)
class P2Settings:
    schema_version: str
    activation_id: str
    enabled: bool
    mode: str
    fail_open_to_legacy: bool
    notifications_use_v12: bool
    logs_enabled: bool
    knowledge_enabled: bool
    metrics_real_calls_enabled: bool
    device_real_calls_enabled: bool
    rca_real_calls_enabled: bool
    reuse_existing_evidence_before_real_call: bool
    activated_at: datetime
    canary_window_minutes: int
    max_canary_requests: int
    minimum_completed_for_gate: int
    allowed_families: tuple[str, ...]
    total_timeout_seconds: int
    metrics_timeout_seconds: int
    device_timeout_seconds: int
    rca_timeout_seconds: int
    max_metrics_calls_per_request: int
    max_device_calls_per_request: int
    max_rca_calls_per_request: int
    max_total_external_calls_per_request: int
    promql_generation_allowed: bool
    command_generation_allowed: bool
    dsl_generation_allowed: bool
    write_commands_allowed: bool
    arbitrary_tool_selection_allowed: bool
    automatic_followup_queries_allowed: bool

    @property
    def expires_at(self) -> datetime:
        return self.activated_at + timedelta(
            minutes=self.canary_window_minutes
        )

    @property
    def active_now(self) -> bool:
        now = datetime.now(timezone.utc)
        return (
            self.enabled
            and self.activated_at <= now <= self.expires_at
        )

    @property
    def real_calls_enabled(self) -> bool:
        return any(
            (
                self.metrics_real_calls_enabled,
                self.device_real_calls_enabled,
                self.rca_real_calls_enabled,
            )
        )

    def source_enabled(self, kind: P2CallKind) -> bool:
        return {
            P2CallKind.METRICS: self.metrics_real_calls_enabled,
            P2CallKind.DEVICE: self.device_real_calls_enabled,
            P2CallKind.RCA: self.rca_real_calls_enabled,
        }[kind]

    def per_source_limit(self, kind: P2CallKind) -> int:
        return {
            P2CallKind.METRICS: self.max_metrics_calls_per_request,
            P2CallKind.DEVICE: self.max_device_calls_per_request,
            P2CallKind.RCA: self.max_rca_calls_per_request,
        }[kind]

    def validate_frozen_boundary(self) -> None:
        if self.schema_version != P2_SCHEMA_VERSION:
            raise P2ContractError(
                "P2 runtime schema_version mismatch"
            )
        if not self.activation_id:
            raise P2ContractError(
                "P2 activation_id is required"
            )
        if self.mode != "shadow":
            raise P2ContractError(
                "P2 mode must remain shadow"
            )
        if self.fail_open_to_legacy is not True:
            raise P2ContractError(
                "P2 fail_open_to_legacy must be true"
            )
        if self.notifications_use_v12 is not False:
            raise P2ContractError(
                "P2 must not send or replace production notifications"
            )
        if self.logs_enabled is not False:
            raise P2ContractError(
                "P2 Logs Agent must remain disabled"
            )
        if self.knowledge_enabled is not False:
            raise P2ContractError(
                "P2 Knowledge Agent must remain disabled"
            )
        if (
            self.reuse_existing_evidence_before_real_call
            is not True
        ):
            raise P2ContractError(
                "P2 must try existing evidence before a real call"
            )
        if not 1 <= self.canary_window_minutes <= 240:
            raise P2ContractError(
                "P2 canary window must be 1..240 minutes"
            )
        if not 1 <= self.max_canary_requests <= 3:
            raise P2ContractError(
                "P2 max_canary_requests must be 1..3"
            )
        if not (
            1
            <= self.minimum_completed_for_gate
            <= self.max_canary_requests
        ):
            raise P2ContractError(
                "P2 minimum_completed_for_gate is invalid"
            )

        families = tuple(
            dict.fromkeys(
                family.strip()
                for family in self.allowed_families
                if family.strip()
            )
        )
        if families != self.allowed_families:
            raise P2ContractError(
                "P2 allowed_families must be unique and normalized"
            )
        if not families:
            raise P2ContractError(
                "P2 allowed_families must not be empty"
            )
        unknown = sorted(
            set(families) - set(DEFAULT_ALLOWED_FAMILIES)
        )
        if unknown:
            raise P2ContractError(
                "P2 family is not approved: "
                + ", ".join(unknown)
            )

        if not 10 <= self.total_timeout_seconds <= 90:
            raise P2ContractError(
                "P2 total timeout must be 10..90 seconds"
            )
        for name, value, maximum in (
            (
                "metrics_timeout_seconds",
                self.metrics_timeout_seconds,
                20,
            ),
            (
                "device_timeout_seconds",
                self.device_timeout_seconds,
                30,
            ),
            (
                "rca_timeout_seconds",
                self.rca_timeout_seconds,
                30,
            ),
        ):
            if not 1 <= value <= maximum:
                raise P2ContractError(
                    f"P2 {name} is out of range"
                )

        for name, value in (
            (
                "max_metrics_calls_per_request",
                self.max_metrics_calls_per_request,
            ),
            (
                "max_device_calls_per_request",
                self.max_device_calls_per_request,
            ),
            (
                "max_rca_calls_per_request",
                self.max_rca_calls_per_request,
            ),
        ):
            if value not in {0, 1}:
                raise P2ContractError(
                    f"P2 {name} must be 0 or 1"
                )

        if not 1 <= self.max_total_external_calls_per_request <= 3:
            raise P2ContractError(
                "P2 total external-call budget must be 1..3"
            )

        enabled_limits = {
            P2CallKind.METRICS: self.max_metrics_calls_per_request,
            P2CallKind.DEVICE: self.max_device_calls_per_request,
            P2CallKind.RCA: self.max_rca_calls_per_request,
        }
        for kind, limit in enabled_limits.items():
            if self.source_enabled(kind) and limit != 1:
                raise P2ContractError(
                    f"P2 enabled source requires one-call budget: "
                    f"{kind.value}"
                )
            if not self.source_enabled(kind) and limit != 0:
                raise P2ContractError(
                    f"P2 disabled source requires zero budget: "
                    f"{kind.value}"
                )

        if self.enabled and not self.real_calls_enabled:
            raise P2ContractError(
                "P2 enabled=true requires at least one approved source"
            )
        if not self.enabled and self.real_calls_enabled:
            raise P2ContractError(
                "P2-A disabled config cannot enable real calls"
            )

        if self.promql_generation_allowed:
            raise P2ContractError(
                "P2 arbitrary PromQL generation is forbidden"
            )
        if self.command_generation_allowed:
            raise P2ContractError(
                "P2 arbitrary CLI generation is forbidden"
            )
        if self.dsl_generation_allowed:
            raise P2ContractError(
                "P2 arbitrary DSL generation is forbidden"
            )
        if self.write_commands_allowed:
            raise P2ContractError(
                "P2 write commands are forbidden"
            )
        if self.arbitrary_tool_selection_allowed:
            raise P2ContractError(
                "P2 arbitrary tool selection is forbidden"
            )
        if self.automatic_followup_queries_allowed:
            raise P2ContractError(
                "P2 automatic follow-up queries are forbidden"
            )


@dataclass(frozen=True, slots=True)
class P2CallRecord:
    request_id: str
    family: str
    kind: P2CallKind
    operation_id: str
    provider: str
    ordinal_for_kind: int
    ordinal_total: int
    reserved_at: datetime

    def as_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "family": self.family,
            "kind": self.kind.value,
            "operation_id": self.operation_id,
            "provider": self.provider,
            "ordinal_for_kind": self.ordinal_for_kind,
            "ordinal_total": self.ordinal_total,
            "reserved_at": self.reserved_at.isoformat(),
        }


@dataclass(slots=True)
class P2CallLedger:
    settings: P2Settings
    request_id: str
    family: str
    records: list[P2CallRecord] = field(default_factory=list)

    def reserve(
        self,
        kind: P2CallKind,
        *,
        operation_id: str,
        provider: str,
        now: datetime | None = None,
    ) -> P2CallRecord:
        if not self.settings.active_now:
            raise P2ContractError(
                "P2 runtime is not active"
            )
        if self.family not in self.settings.allowed_families:
            raise P2ContractError(
                "P2 request family is not allowlisted"
            )
        if not self.settings.source_enabled(kind):
            raise P2ContractError(
                f"P2 source is disabled: {kind.value}"
            )

        safe_operation = operation_id.strip()
        safe_provider = provider.strip()
        if not safe_operation:
            raise P2ContractError(
                "P2 operation_id is required"
            )
        if not safe_provider:
            raise P2ContractError(
                "P2 provider is required"
            )
        if any(
            record.kind == kind
            and record.operation_id == safe_operation
            for record in self.records
        ):
            raise P2ContractError(
                "P2 duplicate operation_id is forbidden"
            )

        kind_count = sum(
            1 for record in self.records if record.kind == kind
        )
        if kind_count >= self.settings.per_source_limit(kind):
            raise P2ContractError(
                f"P2 per-source call budget exceeded: {kind.value}"
            )
        if (
            len(self.records)
            >= self.settings.max_total_external_calls_per_request
        ):
            raise P2ContractError(
                "P2 total external-call budget exceeded"
            )

        reserved_at = now or datetime.now(timezone.utc)
        if (
            reserved_at.tzinfo is None
            or reserved_at.utcoffset() is None
        ):
            raise P2ContractError(
                "P2 call timestamp must be timezone-aware"
            )

        record = P2CallRecord(
            request_id=self.request_id,
            family=self.family,
            kind=kind,
            operation_id=safe_operation,
            provider=safe_provider,
            ordinal_for_kind=kind_count + 1,
            ordinal_total=len(self.records) + 1,
            reserved_at=reserved_at.astimezone(timezone.utc),
        )
        self.records.append(record)
        return record

    def snapshot(self) -> dict[str, Any]:
        counts = {
            kind.value: sum(
                1 for record in self.records if record.kind == kind
            )
            for kind in P2CallKind
        }
        return {
            "schema_version": P2_SCHEMA_VERSION,
            "request_id": self.request_id,
            "family": self.family,
            "call_counts": counts,
            "total_calls": len(self.records),
            "records": [
                record.as_dict() for record in self.records
            ],
        }


@dataclass(frozen=True, slots=True)
class P2Decision:
    allowed: bool
    reason: str
    request_id: str
    family: str
    active_now: bool
    enabled_sources: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "request_id": self.request_id,
            "family": self.family,
            "active_now": self.active_now,
            "enabled_sources": list(self.enabled_sources),
        }


class P2CanaryPolicy:
    """Pure policy evaluation; it cannot call any external system."""

    def __init__(self, settings: P2Settings) -> None:
        settings.validate_frozen_boundary()
        self.settings = settings

    def evaluate(
        self,
        *,
        request_id: str,
        family: str,
        event_count: int,
        alert_status: str,
    ) -> P2Decision:
        safe_id = request_id.strip()
        safe_family = family.strip()
        enabled_sources = tuple(
            kind.value
            for kind in P2CallKind
            if self.settings.source_enabled(kind)
        )

        if not safe_id:
            return self._decision(
                False,
                "request_id_missing",
                safe_id,
                safe_family,
                enabled_sources,
            )
        if event_count != 1:
            return self._decision(
                False,
                "single_event_required",
                safe_id,
                safe_family,
                enabled_sources,
            )
        if alert_status.strip().lower() != "firing":
            return self._decision(
                False,
                "only_firing_is_allowed",
                safe_id,
                safe_family,
                enabled_sources,
            )
        if safe_family not in self.settings.allowed_families:
            return self._decision(
                False,
                "family_not_allowlisted",
                safe_id,
                safe_family,
                enabled_sources,
            )
        if not self.settings.active_now:
            return self._decision(
                False,
                "runtime_inactive",
                safe_id,
                safe_family,
                enabled_sources,
            )
        return self._decision(
            True,
            "controlled_canary_allowed",
            safe_id,
            safe_family,
            enabled_sources,
        )

    def _decision(
        self,
        allowed: bool,
        reason: str,
        request_id: str,
        family: str,
        enabled_sources: tuple[str, ...],
    ) -> P2Decision:
        return P2Decision(
            allowed=allowed,
            reason=reason,
            request_id=request_id,
            family=family,
            active_now=self.settings.active_now,
            enabled_sources=enabled_sources,
        )


def _bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in {"true", "yes", "1", "on"}:
        return True
    if text in {"false", "no", "0", "off"}:
        return False
    return default


def _aware_datetime(value: Any, *, field: str) -> datetime:
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise P2ContractError(
            f"{field} must use ISO 8601"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise P2ContractError(
            f"{field} must be timezone-aware"
        )
    return parsed.astimezone(timezone.utc)


def _scan_forbidden_keys(value: Any, path: str = "root") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).strip().lower()
            if normalized in P2A_FORBIDDEN_CONFIG_KEYS:
                raise P2ContractError(
                    f"secret-like config key is forbidden: "
                    f"{path}.{key}"
                )
            _scan_forbidden_keys(item, f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        for index, item in enumerate(value):
            _scan_forbidden_keys(item, f"{path}[{index}]")


def load_p2_settings(
    path: str | Path = DEFAULT_RUNTIME_CONFIG,
) -> P2Settings | None:
    value = Path(path)
    if not value.exists():
        return None
    if value.is_symlink() or not value.is_file():
        raise P2ContractError(
            "P2 runtime config must be a regular file"
        )
    if value.stat().st_size > 64 * 1024:
        raise P2ContractError(
            "P2 runtime config is too large"
        )
    try:
        raw = yaml.safe_load(
            value.read_text(encoding="utf-8")
        ) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise P2ContractError(
            "P2 runtime config cannot be decoded"
        ) from exc
    if not isinstance(raw, Mapping):
        raise P2ContractError(
            "P2 runtime config root must be an object"
        )
    _scan_forbidden_keys(raw)

    allowed_keys = {
        "schema_version",
        "activation_id",
        "enabled",
        "mode",
        "fail_open_to_legacy",
        "notifications_use_v12",
        "logs_enabled",
        "knowledge_enabled",
        "metrics_real_calls_enabled",
        "device_real_calls_enabled",
        "rca_real_calls_enabled",
        "reuse_existing_evidence_before_real_call",
        "activated_at",
        "canary_window_minutes",
        "max_canary_requests",
        "minimum_completed_for_gate",
        "allowed_families",
        "total_timeout_seconds",
        "metrics_timeout_seconds",
        "device_timeout_seconds",
        "rca_timeout_seconds",
        "max_metrics_calls_per_request",
        "max_device_calls_per_request",
        "max_rca_calls_per_request",
        "max_total_external_calls_per_request",
        "promql_generation_allowed",
        "command_generation_allowed",
        "dsl_generation_allowed",
        "write_commands_allowed",
        "arbitrary_tool_selection_allowed",
        "automatic_followup_queries_allowed",
    }
    unknown = sorted(set(raw) - allowed_keys)
    if unknown:
        raise P2ContractError(
            "unknown P2 runtime keys: "
            + ", ".join(unknown)
        )

    families = raw.get("allowed_families")
    if not isinstance(families, list):
        raise P2ContractError(
            "P2 allowed_families must be a list"
        )

    settings = P2Settings(
        schema_version=str(raw.get("schema_version") or ""),
        activation_id=str(raw.get("activation_id") or ""),
        enabled=_bool(raw.get("enabled")),
        mode=str(raw.get("mode") or ""),
        fail_open_to_legacy=_bool(
            raw.get("fail_open_to_legacy")
        ),
        notifications_use_v12=_bool(
            raw.get("notifications_use_v12")
        ),
        logs_enabled=_bool(raw.get("logs_enabled")),
        knowledge_enabled=_bool(raw.get("knowledge_enabled")),
        metrics_real_calls_enabled=_bool(
            raw.get("metrics_real_calls_enabled")
        ),
        device_real_calls_enabled=_bool(
            raw.get("device_real_calls_enabled")
        ),
        rca_real_calls_enabled=_bool(
            raw.get("rca_real_calls_enabled")
        ),
        reuse_existing_evidence_before_real_call=_bool(
            raw.get(
                "reuse_existing_evidence_before_real_call"
            )
        ),
        activated_at=_aware_datetime(
            raw.get("activated_at"),
            field="activated_at",
        ),
        canary_window_minutes=int(
            raw.get("canary_window_minutes", 0)
        ),
        max_canary_requests=int(
            raw.get("max_canary_requests", 0)
        ),
        minimum_completed_for_gate=int(
            raw.get("minimum_completed_for_gate", 0)
        ),
        allowed_families=tuple(str(item) for item in families),
        total_timeout_seconds=int(
            raw.get("total_timeout_seconds", 0)
        ),
        metrics_timeout_seconds=int(
            raw.get("metrics_timeout_seconds", 0)
        ),
        device_timeout_seconds=int(
            raw.get("device_timeout_seconds", 0)
        ),
        rca_timeout_seconds=int(
            raw.get("rca_timeout_seconds", 0)
        ),
        max_metrics_calls_per_request=int(
            raw.get("max_metrics_calls_per_request", -1)
        ),
        max_device_calls_per_request=int(
            raw.get("max_device_calls_per_request", -1)
        ),
        max_rca_calls_per_request=int(
            raw.get("max_rca_calls_per_request", -1)
        ),
        max_total_external_calls_per_request=int(
            raw.get(
                "max_total_external_calls_per_request",
                0,
            )
        ),
        promql_generation_allowed=_bool(
            raw.get("promql_generation_allowed")
        ),
        command_generation_allowed=_bool(
            raw.get("command_generation_allowed")
        ),
        dsl_generation_allowed=_bool(
            raw.get("dsl_generation_allowed")
        ),
        write_commands_allowed=_bool(
            raw.get("write_commands_allowed")
        ),
        arbitrary_tool_selection_allowed=_bool(
            raw.get("arbitrary_tool_selection_allowed")
        ),
        automatic_followup_queries_allowed=_bool(
            raw.get("automatic_followup_queries_allowed")
        ),
    )
    settings.validate_frozen_boundary()
    return settings


def offline_contract_report(
    settings: P2Settings,
) -> dict[str, Any]:
    settings.validate_frozen_boundary()
    if settings.enabled:
        raise P2ContractError(
            "P2-A offline gate requires enabled=false"
        )
    if settings.real_calls_enabled:
        raise P2ContractError(
            "P2-A offline gate requires all real calls disabled"
        )

    policy = P2CanaryPolicy(settings)
    sample_decisions = [
        policy.evaluate(
            request_id=f"p2a-sample-{index}",
            family=family,
            event_count=1,
            alert_status="firing",
        ).as_dict()
        for index, family in enumerate(
            settings.allowed_families,
            start=1,
        )
    ]
    return {
        "schema_version": P2_SCHEMA_VERSION,
        "stage": "P2-A",
        "status": "pass",
        "enabled": settings.enabled,
        "real_calls_enabled": settings.real_calls_enabled,
        "allowed_families": list(settings.allowed_families),
        "sample_decisions": sample_decisions,
        "boundaries": {
            "fail_open_to_legacy": (
                settings.fail_open_to_legacy
            ),
            "notifications_use_v12": (
                settings.notifications_use_v12
            ),
            "logs_enabled": settings.logs_enabled,
            "knowledge_enabled": settings.knowledge_enabled,
            "promql_generation_allowed": (
                settings.promql_generation_allowed
            ),
            "command_generation_allowed": (
                settings.command_generation_allowed
            ),
            "dsl_generation_allowed": (
                settings.dsl_generation_allowed
            ),
            "write_commands_allowed": (
                settings.write_commands_allowed
            ),
            "arbitrary_tool_selection_allowed": (
                settings.arbitrary_tool_selection_allowed
            ),
            "automatic_followup_queries_allowed": (
                settings.automatic_followup_queries_allowed
            ),
        },
        "external_calls": {
            kind.value: False for kind in P2CallKind
        },
    }


def stable_report_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        dict(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
