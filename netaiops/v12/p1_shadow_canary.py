"""Batch P1 artifact-reuse Shadow Canary.

This module is a non-blocking v12 sidecar. It runs only after the legacy
callback/review/notification path has completed. It reuses existing Metrics and
Device artifacts, keeps Logs and Knowledge unavailable, disables RCA generation,
does not send a second card, and never calls an external system.
"""

from __future__ import annotations

import asyncio
import fcntl
import json
import os
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from netaiops.family_registry import classify_family

from .adapters.device_evidence_adapter import DeviceEvidenceAdapter
from .adapters.prometheus_evidence_adapter import PrometheusEvidenceAdapter
from .agent_trace_store import AgentTraceStore
from .agents.device_evidence_agent import DeviceEvidenceAgent
from .agents.evidence_judge_agent import EvidenceJudgeAgent
from .agents.knowledge_context_agent import KnowledgeContextAgent
from .agents.logs_evidence_agent import LogsEvidenceAgent
from .agents.metrics_evidence_agent import MetricsEvidenceAgent
from .agents.notification_report_agent import NotificationReportAgent
from .agents.rca_agent import RCAAgent
from .agents.static_planner_agent import StaticPlannerAgent
from .agents.triage_agent import TriageAgent
from .api import AgentTraceReadService
from .atomic_writer import AtomicJsonWriter
from .contracts import AgentRunRecord, ContractNotice
from .evidence_bundle import BundleArtifacts, EvidenceBundleBuilder
from .execution_context import AgentInvocation, AgentOutcome, OrchestrationResult
from .governance_adapter import AgentTraceGovernanceAdapter
from .schema_validator import (
    build_contract_ref,
    stable_json_dumps,
    validate_request_id,
)
from .shadow_audit_store import ShadowAuditStore
from .shadow_contracts import (
    LegacyDeliverySnapshot,
    ShadowIntegrationSettings,
    ShadowPipelineRequest,
    ShadowPipelineResult,
    ShadowStatus,
)
from .shadow_integration import ShadowIntegrationController
from .state_machine import OrchestrationState
from .status import AgentName, AgentStatus


P1_SCHEMA_VERSION = "v12-p1-shadow-canary-1"
DEFAULT_PROJECT_ROOT = Path("/opt/netaiops-webhook")
DEFAULT_RUNTIME_CONFIG = (
    DEFAULT_PROJECT_ROOT / "config" / "v12_p1_shadow.yaml"
)
DEFAULT_TRACE_ROOT = (
    DEFAULT_PROJECT_ROOT / "data" / "evidence_hub" / "requests"
)
DEFAULT_STATE_FILE = (
    DEFAULT_PROJECT_ROOT
    / "data"
    / "evidence_hub"
    / "p1_shadow_canary_state.json"
)
DEFAULT_ALLOWED_FAMILIES = (
    "interface_status_or_flap",
    "interface_or_link_utilization_high",
    "interface_traffic_anomaly",
    "interface_or_link_traffic_drop",
)
_EXPECTED_AGENT_ORDER = (
    AgentName.TRIAGE,
    AgentName.STATIC_PLANNER,
    AgentName.METRICS_EVIDENCE,
    AgentName.DEVICE_EVIDENCE,
    AgentName.LOGS_EVIDENCE,
    AgentName.KNOWLEDGE_CONTEXT,
    AgentName.EVIDENCE_JUDGE,
    AgentName.RCA,
    AgentName.NOTIFICATION_REPORT,
)
_EXPECTED_TRACE_FILES = frozenset(
    {
        "unified_event.json",
        "evidence_plan.json",
        "agent_runs.json",
        "evidence_bundle.json",
        "judge_result.json",
        "rca_result.json",
        "report.json",
        "shadow_integration.json",
        "p1_canary.json",
    }
)
_FORBIDDEN_TRUE_OUTPUT_KEYS = frozenset(
    {
        "production_glm_called",
        "prometheus_mcp_called",
        "netmiko_mcp_called",
        "fastmcp_called",
        "ops_es_api_called",
        "analytics_mcp_called",
        "elasticsearch_called",
        "notification_sent",
        "mcp_called",
        "tool_called",
        "automatic_followup_queries",
        "second_card_sent",
        "production_card_replaced",
        "write_command_executed",
        "command_generation_performed",
        "promql_generation_performed",
        "dsl_generation_performed",
    }
)


class P1CanaryError(RuntimeError):
    """Raised when P1 cannot complete its no-side-effect contract."""


@dataclass(frozen=True, slots=True)
class P1Settings:
    schema_version: str
    activation_id: str
    enabled: bool
    mode: str
    fail_open_to_legacy: bool
    reuse_existing_evidence: bool
    notifications_use_v12: bool
    rca_enabled: bool
    logs_enabled: bool
    knowledge_enabled: bool
    activated_at: datetime
    canary_window_minutes: int
    max_canary_requests: int
    allowed_families: tuple[str, ...]
    total_timeout_seconds: int
    agent_timeout_seconds: int
    minimum_completed_for_gate: int

    @property
    def expires_at(self) -> datetime:
        return self.activated_at + timedelta(
            minutes=self.canary_window_minutes
        )

    @property
    def active_now(self) -> bool:
        now = datetime.now(timezone.utc)
        return self.enabled and self.activated_at <= now <= self.expires_at

    def validate_frozen_boundary(self) -> None:
        if self.schema_version != P1_SCHEMA_VERSION:
            raise P1CanaryError("P1 runtime schema_version mismatch")
        if not self.activation_id:
            raise P1CanaryError("P1 activation_id is required")
        if self.mode != "shadow":
            raise P1CanaryError("P1 mode must remain shadow")
        if self.fail_open_to_legacy is not True:
            raise P1CanaryError("P1 fail_open_to_legacy must be true")
        if self.reuse_existing_evidence is not True:
            raise P1CanaryError(
                "P1 reuse_existing_evidence must be true"
            )
        if self.notifications_use_v12 is not False:
            raise P1CanaryError(
                "P1 notifications_use_v12 must be false"
            )
        if self.rca_enabled is not False:
            raise P1CanaryError("P1 RCA must remain disabled")
        if self.logs_enabled is not False:
            raise P1CanaryError("P1 Logs must remain disabled")
        if self.knowledge_enabled is not False:
            raise P1CanaryError("P1 Knowledge must remain disabled")
        if not 1 <= self.canary_window_minutes <= 1440:
            raise P1CanaryError("P1 canary window is out of range")
        if not 1 <= self.max_canary_requests <= 100:
            raise P1CanaryError(
                "P1 max_canary_requests is out of range"
            )
        if not self.allowed_families:
            raise P1CanaryError(
                "P1 allowed_families must not be empty"
            )
        if not 5 <= self.total_timeout_seconds <= 60:
            raise P1CanaryError(
                "P1 total timeout is out of range"
            )
        if not 1 <= self.agent_timeout_seconds <= 30:
            raise P1CanaryError(
                "P1 agent timeout is out of range"
            )
        if not (
            1
            <= self.minimum_completed_for_gate
            <= self.max_canary_requests
        ):
            raise P1CanaryError(
                "P1 minimum_completed_for_gate is invalid"
            )


@dataclass(frozen=True, slots=True)
class P1RequestInput:
    request_id: str
    source: str
    raw_payload: Mapping[str, Any]
    normalized_event: Mapping[str, Any]
    event_count: int
    family: str
    alert_status: str


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


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
        raise P1CanaryError(
            f"{field} must use ISO 8601"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise P1CanaryError(f"{field} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _safe_json_read(
    path: Path,
    *,
    max_bytes: int = 8 * 1024 * 1024,
) -> Mapping[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise P1CanaryError(f"unsafe or missing JSON file: {path}")
    if path.stat().st_size > max_bytes:
        raise P1CanaryError(f"JSON file exceeds size limit: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise P1CanaryError(
            f"JSON file cannot be decoded: {path.name}"
        ) from exc
    if not isinstance(value, Mapping):
        raise P1CanaryError(
            f"JSON file root must be an object: {path.name}"
        )
    return value


def _newest_match(root: Path, pattern: str) -> Path:
    if root.is_symlink() or not root.is_dir():
        raise P1CanaryError(f"artifact root is unavailable: {root}")
    candidates = [
        path
        for path in root.glob(pattern)
        if path.is_file() and not path.is_symlink()
    ]
    if not candidates:
        raise P1CanaryError(
            f"artifact not found: {root}/{pattern}"
        )
    candidates.sort(
        key=lambda path: (path.stat().st_mtime_ns, path.name),
        reverse=True,
    )
    return candidates[0]


def load_p1_settings(
    path: str | Path = DEFAULT_RUNTIME_CONFIG,
) -> P1Settings | None:
    value = Path(path)
    if not value.exists():
        return None
    if value.is_symlink() or not value.is_file():
        raise P1CanaryError(
            "P1 runtime config must be a regular file"
        )
    if value.stat().st_size > 64 * 1024:
        raise P1CanaryError("P1 runtime config is too large")
    try:
        raw = yaml.safe_load(
            value.read_text(encoding="utf-8")
        ) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise P1CanaryError(
            "P1 runtime config cannot be decoded"
        ) from exc
    if not isinstance(raw, Mapping):
        raise P1CanaryError(
            "P1 runtime config root must be an object"
        )
    allowed = {
        "schema_version",
        "activation_id",
        "enabled",
        "mode",
        "fail_open_to_legacy",
        "reuse_existing_evidence",
        "notifications_use_v12",
        "rca_enabled",
        "logs_enabled",
        "knowledge_enabled",
        "activated_at",
        "canary_window_minutes",
        "max_canary_requests",
        "allowed_families",
        "total_timeout_seconds",
        "agent_timeout_seconds",
        "minimum_completed_for_gate",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise P1CanaryError(
            "unknown P1 runtime keys: " + ", ".join(unknown)
        )
    families = raw.get("allowed_families")
    if not isinstance(families, list):
        raise P1CanaryError(
            "allowed_families must be a list"
        )
    settings = P1Settings(
        schema_version=str(raw.get("schema_version") or ""),
        activation_id=str(raw.get("activation_id") or ""),
        enabled=_bool(raw.get("enabled")),
        mode=str(raw.get("mode") or ""),
        fail_open_to_legacy=_bool(
            raw.get("fail_open_to_legacy")
        ),
        reuse_existing_evidence=_bool(
            raw.get("reuse_existing_evidence")
        ),
        notifications_use_v12=_bool(
            raw.get("notifications_use_v12")
        ),
        rca_enabled=_bool(raw.get("rca_enabled")),
        logs_enabled=_bool(raw.get("logs_enabled")),
        knowledge_enabled=_bool(raw.get("knowledge_enabled")),
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
        allowed_families=tuple(
            dict.fromkeys(
                str(item).strip()
                for item in families
                if str(item).strip()
            )
        ),
        total_timeout_seconds=int(
            raw.get("total_timeout_seconds", 0)
        ),
        agent_timeout_seconds=int(
            raw.get("agent_timeout_seconds", 0)
        ),
        minimum_completed_for_gate=int(
            raw.get("minimum_completed_for_gate", 0)
        ),
    )
    settings.validate_frozen_boundary()
    return settings


def load_request_input(
    request_id: str,
    *,
    project_root: str | Path = DEFAULT_PROJECT_ROOT,
) -> P1RequestInput:
    safe_id = validate_request_id(request_id)
    root = Path(project_root)
    normalized_path = _newest_match(
        root / "data" / "normalized",
        f"*_{safe_id}.json",
    )
    raw_path = _newest_match(
        root / "data" / "raw",
        f"*_{safe_id}.json",
    )
    normalized = _safe_json_read(normalized_path)
    raw_payload = _safe_json_read(raw_path)
    source = str(normalized.get("source") or "").strip().lower()
    events = normalized.get("events")
    if not isinstance(events, list) or not events:
        raise P1CanaryError(
            "normalized request does not contain events"
        )
    if len(events) != 1:
        raise P1CanaryError(
            "P1 accepts exactly one event per canary request"
        )
    event = events[0]
    if not isinstance(event, Mapping):
        raise P1CanaryError(
            "normalized event must be an object"
        )
    family_result = classify_family(dict(event))
    family = str(
        family_result.get("family")
        or event.get("family")
        or "generic_network_readonly"
    ).strip()
    status = str(
        event.get("status")
        or _mapping(event.get("labels")).get("status")
        or "firing"
    ).strip().lower()
    alert_status = (
        "resolved"
        if status
        in {
            "resolved",
            "recovered",
            "recovery",
            "closed",
            "clear",
            "cleared",
            "ok",
        }
        else "firing"
    )
    return P1RequestInput(
        request_id=safe_id,
        source=source,
        raw_payload=raw_payload,
        normalized_event=event,
        event_count=len(events),
        family=family,
        alert_status=alert_status,
    )


def _legacy_notification_count(value: Any) -> int:
    result = _mapping(value)
    for key in (
        "sent_count",
        "notification_count",
        "success_count",
        "count",
    ):
        try:
            count = int(result.get(key))
        except (TypeError, ValueError):
            continue
        if count >= 0:
            return count
    if result.get("ok") is True or result.get("sent") is True:
        return 1
    return 0


def _recursive_true_keys(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, Mapping):
        for key, item in value.items():
            name = str(key)
            if (
                name in _FORBIDDEN_TRUE_OUTPUT_KEYS
                and item is True
            ):
                found.add(name)
            found.update(_recursive_true_keys(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            found.update(_recursive_true_keys(item))
    return found


class P1ArtifactReuseRunner:
    """Run the fixed v12 sequence with existing local artifacts only."""

    def __init__(
        self,
        *,
        settings: P1Settings,
        request_input: P1RequestInput,
        project_root: str | Path = DEFAULT_PROJECT_ROOT,
        trace_root: str | Path = DEFAULT_TRACE_ROOT,
        governance_root: str | Path | None = None,
        utcnow: Any | None = None,
        monotonic: Any | None = None,
    ) -> None:
        self.settings = settings
        self.request_input = request_input
        self.project_root = Path(project_root)
        self.trace_root = Path(trace_root)
        self.governance_root = Path(
            governance_root
            or (
                self.project_root
                / "data"
                / "governance"
                / "agent_traces"
            )
        )
        self._utcnow = utcnow or (
            lambda: datetime.now(timezone.utc)
        )
        self._monotonic = monotonic or time.monotonic

    async def run(
        self,
        request: ShadowPipelineRequest,
    ) -> ShadowPipelineResult:
        if request.request_id != self.request_input.request_id:
            raise P1CanaryError(
                "P1 Shadow request_id mismatch"
            )
        started_clock = self._monotonic()
        outputs: dict[str, Mapping[str, Any]] = {}
        output_refs: list[str] = []
        runs: list[AgentRunRecord] = []

        metrics_adapter = PrometheusEvidenceAdapter(
            self.project_root / "data" / "prometheus_evidence",
            utcnow=self._utcnow,
        )
        device_adapter = DeviceEvidenceAdapter(
            (
                self.project_root / "data" / "callback",
                self.project_root / "data" / "execution",
            ),
            utcnow=self._utcnow,
        )
        agents = {
            AgentName.TRIAGE: TriageAgent(
                source=self.request_input.source,
                payload=self.request_input.raw_payload,
                event_index=0,
                received_at=self._utcnow(),
            ),
            AgentName.STATIC_PLANNER: StaticPlannerAgent(),
            AgentName.METRICS_EVIDENCE: MetricsEvidenceAgent(
                adapter=metrics_adapter,
                utcnow=self._utcnow,
            ),
            AgentName.DEVICE_EVIDENCE: DeviceEvidenceAgent(
                adapter=device_adapter,
                utcnow=self._utcnow,
            ),
            AgentName.LOGS_EVIDENCE: LogsEvidenceAgent(
                utcnow=self._utcnow,
            ),
            AgentName.KNOWLEDGE_CONTEXT: KnowledgeContextAgent(
                utcnow=self._utcnow,
            ),
            AgentName.EVIDENCE_JUDGE: EvidenceJudgeAgent(),
            AgentName.RCA: RCAAgent(
                enabled=False,
                client=None,
                utcnow=self._utcnow,
            ),
            AgentName.NOTIFICATION_REPORT: NotificationReportAgent(
                utcnow=self._utcnow,
            ),
        }
        states = {
            AgentName.TRIAGE: OrchestrationState.TRIAGE,
            AgentName.STATIC_PLANNER: OrchestrationState.PLANNING,
            AgentName.METRICS_EVIDENCE: (
                OrchestrationState.EVIDENCE_COLLECTION
            ),
            AgentName.DEVICE_EVIDENCE: (
                OrchestrationState.EVIDENCE_COLLECTION
            ),
            AgentName.LOGS_EVIDENCE: (
                OrchestrationState.EVIDENCE_COLLECTION
            ),
            AgentName.KNOWLEDGE_CONTEXT: (
                OrchestrationState.EVIDENCE_COLLECTION
            ),
            AgentName.EVIDENCE_JUDGE: (
                OrchestrationState.EVIDENCE_JUDGING
            ),
            AgentName.RCA: OrchestrationState.RCA,
            AgentName.NOTIFICATION_REPORT: (
                OrchestrationState.REPORTING
            ),
        }

        async def invoke(name: AgentName) -> AgentOutcome:
            invocation = AgentInvocation(
                request_id=request.request_id,
                agent_name=name,
                orchestration_state=states[name],
                prior_output_refs=tuple(output_refs),
                prior_outputs=dict(outputs),
            )
            started_at = self._aware_now()
            started = self._monotonic()
            try:
                outcome = await asyncio.wait_for(
                    agents[name].run(invocation),
                    timeout=self.settings.agent_timeout_seconds,
                )
            except asyncio.TimeoutError:
                notice = ContractNotice(
                    code="p1_agent_timeout",
                    message="P1 Agent exceeded its timeout",
                    stage=name.value,
                    retryable=False,
                )
                outcome = AgentOutcome(
                    status=AgentStatus.FAILED,
                    errors=(notice,),
                )
            finished_at = self._aware_now()
            record = AgentRunRecord(
                schema_version="v12.1",
                request_id=request.request_id,
                agent_name=name,
                status=outcome.status,
                started_at=started_at,
                finished_at=finished_at,
                duration_ms=max(
                    0,
                    int((self._monotonic() - started) * 1000),
                ),
                inputs_ref=list(invocation.prior_output_refs),
                outputs_ref=list(outcome.output_refs),
                warnings=list(outcome.warnings),
                errors=list(outcome.errors),
                external_calls=list(outcome.external_calls),
            )
            if record.external_calls:
                raise P1CanaryError(
                    f"P1 external call record detected: {name.value}"
                )
            forbidden = _recursive_true_keys(outcome.output)
            if forbidden:
                raise P1CanaryError(
                    "P1 forbidden side-effect flag is true: "
                    + ", ".join(sorted(forbidden))
                )
            runs.append(record)
            outputs[name.value] = dict(outcome.output)
            output_refs.extend(outcome.output_refs)
            return outcome

        for name in _EXPECTED_AGENT_ORDER[:6]:
            outcome = await invoke(name)
            if (
                name
                in {
                    AgentName.TRIAGE,
                    AgentName.STATIC_PLANNER,
                }
                and outcome.status == AgentStatus.FAILED
            ):
                raise P1CanaryError(
                    f"P1 required Agent failed: {name.value}"
                )
            if (
                name
                in {
                    AgentName.METRICS_EVIDENCE,
                    AgentName.DEVICE_EVIDENCE,
                }
                and not outcome.output
            ):
                raise P1CanaryError(
                    f"P1 evidence Agent omitted contract: {name.value}"
                )

        partial_result = OrchestrationResult(
            request_id=request.request_id,
            final_state=OrchestrationState.EVIDENCE_COLLECTION,
            state_history=(
                OrchestrationState.INITIALIZED,
                OrchestrationState.TRIAGE,
                OrchestrationState.PLANNING,
                OrchestrationState.EVIDENCE_COLLECTION,
            ),
            agent_runs=tuple(runs),
            outputs=dict(outputs),
            fallback_to_legacy=False,
            stop_reason=None,
            elapsed_ms=max(
                0,
                int((self._monotonic() - started_clock) * 1000),
            ),
        )
        artifacts = EvidenceBundleBuilder(
            utcnow=self._utcnow
        ).build(partial_result)
        bundle_ref = build_contract_ref(
            "artifact",
            request.request_id,
            "evidence_bundle",
            "bundle-p1",
        )
        outputs["evidence_bundle"] = {
            "evidence_bundle": (
                artifacts.evidence_bundle.model_dump(mode="json")
            )
        }
        output_refs.append(bundle_ref)

        judge_outcome = await invoke(AgentName.EVIDENCE_JUDGE)
        if judge_outcome.status == AgentStatus.FAILED:
            raise P1CanaryError("P1 Judge failed")

        rca_outcome = await invoke(AgentName.RCA)
        if rca_outcome.status not in {
            AgentStatus.SKIPPED,
            AgentStatus.PARTIAL,
        }:
            raise P1CanaryError(
                "P1 RCA did not remain disabled/skipped"
            )
        if (
            _mapping(rca_outcome.output).get(
                "production_glm_called"
            )
            is not False
        ):
            raise P1CanaryError(
                "P1 RCA production_glm_called drift"
            )

        report_outcome = await invoke(
            AgentName.NOTIFICATION_REPORT
        )
        if report_outcome.status == AgentStatus.FAILED:
            raise P1CanaryError("P1 Report failed")
        plan = _mapping(report_outcome.output).get(
            "notification_plan"
        )
        if not isinstance(plan, Mapping):
            raise P1CanaryError(
                "P1 Report notification_plan is missing"
            )
        if (
            plan.get("send_notification") is not False
            or int(plan.get("notification_count", -1)) != 0
            or plan.get("second_card_sent") is not False
            or plan.get("production_card_replaced") is not False
        ):
            raise P1CanaryError(
                "P1 Report notification boundary drift"
            )

        final_result = OrchestrationResult(
            request_id=request.request_id,
            final_state=OrchestrationState.COMPLETED,
            state_history=(
                OrchestrationState.INITIALIZED,
                OrchestrationState.TRIAGE,
                OrchestrationState.PLANNING,
                OrchestrationState.EVIDENCE_COLLECTION,
                OrchestrationState.EVIDENCE_JUDGING,
                OrchestrationState.RCA,
                OrchestrationState.REPORTING,
                OrchestrationState.COMPLETED,
            ),
            agent_runs=tuple(runs),
            outputs=dict(outputs),
            fallback_to_legacy=False,
            stop_reason=None,
            elapsed_ms=max(
                0,
                int((self._monotonic() - started_clock) * 1000),
            ),
        )
        stored = AgentTraceStore(self.trace_root).persist(
            final_result,
            BundleArtifacts(
                unified_event=artifacts.unified_event,
                evidence_plan=artifacts.evidence_plan,
                evidence_bundle=artifacts.evidence_bundle,
            ),
        )
        writer = AtomicJsonWriter(stored.directory)
        judge_payload = _mapping(
            outputs[AgentName.EVIDENCE_JUDGE.value]
        ).get("judge_result")
        rca_payload = _mapping(
            outputs[AgentName.RCA.value]
        ).get("rca_result")
        report_payload = dict(
            outputs[AgentName.NOTIFICATION_REPORT.value]
        )
        if not all(
            isinstance(item, Mapping)
            for item in (
                judge_payload,
                rca_payload,
                report_payload.get("report_artifact"),
            )
        ):
            raise P1CanaryError(
                "P1 supplemental trace contract is missing"
            )
        writer.write_many(
            {
                "judge_result.json": {
                    "schema_version": "v12.1",
                    "request_id": request.request_id,
                    "judge_result": judge_payload,
                },
                "rca_result.json": {
                    "schema_version": "v12.1",
                    "request_id": request.request_id,
                    "rca_result": rca_payload,
                },
                "report.json": {
                    "schema_version": "v12.1",
                    "request_id": request.request_id,
                    **report_payload,
                },
            }
        )
        governance = AgentTraceGovernanceAdapter(
            trace_service=AgentTraceReadService(
                self.trace_root
            ),
            governance_root=self.governance_root,
            utcnow=self._utcnow,
        ).persist_for_request_safe(request.request_id)
        if governance.get("ok") is not True:
            raise P1CanaryError(
                "P1 Governance summary persistence failed"
            )

        report_ref = report_outcome.output_refs[0]
        judge_ref = judge_outcome.output_refs[0]
        rca_ref = rca_outcome.output_refs[0]
        return ShadowPipelineResult(
            request_id=request.request_id,
            final_state="completed",
            artifact_refs=[
                bundle_ref,
                judge_ref,
                rca_ref,
                report_ref,
            ],
            report_generated=True,
            trace_written=True,
            notification_sent=False,
            notification_count=0,
            second_card_sent=False,
            production_card_replaced=False,
            production_glm_called=False,
            mcp_called=False,
            tool_called=False,
            automatic_followup_queries=False,
            external_calls=[],
        )

    def _aware_now(self) -> datetime:
        value = self._utcnow()
        if value.tzinfo is None or value.utcoffset() is None:
            raise P1CanaryError(
                "P1 utcnow must return an aware datetime"
            )
        return value


class P1CanaryState:
    """Small locked state file that bounds one activation."""

    def __init__(
        self,
        state_file: str | Path = DEFAULT_STATE_FILE,
    ) -> None:
        self.state_file = Path(state_file)
        self.lock_file = self.state_file.with_suffix(
            self.state_file.suffix + ".lock"
        )

    def claim(
        self,
        settings: P1Settings,
        request_id: str,
    ) -> tuple[bool, str]:
        request_id = validate_request_id(request_id)
        self.state_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        with self.lock_file.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            state = self._read_unlocked()
            if state.get("activation_id") != settings.activation_id:
                state = {
                    "schema_version": P1_SCHEMA_VERSION,
                    "activation_id": settings.activation_id,
                    "attempted_request_ids": [],
                    "outcomes": {},
                }
            attempted = list(
                state.get("attempted_request_ids") or []
            )
            if request_id in attempted:
                return False, "duplicate_request"
            if len(attempted) >= settings.max_canary_requests:
                return False, "max_canary_requests_reached"
            attempted.append(request_id)
            state["attempted_request_ids"] = attempted
            self._write_unlocked(state)
            return True, "claimed"

    def record(
        self,
        settings: P1Settings,
        request_id: str,
        outcome: str,
    ) -> None:
        request_id = validate_request_id(request_id)
        self.state_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        with self.lock_file.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            state = self._read_unlocked()
            if state.get("activation_id") != settings.activation_id:
                state = {
                    "schema_version": P1_SCHEMA_VERSION,
                    "activation_id": settings.activation_id,
                    "attempted_request_ids": [request_id],
                    "outcomes": {},
                }
            outcomes = dict(state.get("outcomes") or {})
            outcomes[request_id] = str(outcome)
            state["outcomes"] = outcomes
            self._write_unlocked(state)

    def _read_unlocked(self) -> dict[str, Any]:
        if not self.state_file.exists():
            return {}
        if self.state_file.is_symlink():
            raise P1CanaryError(
                "P1 state file must not be a symlink"
            )
        value = _safe_json_read(
            self.state_file,
            max_bytes=512 * 1024,
        )
        return dict(value)

    def _write_unlocked(self, state: Mapping[str, Any]) -> None:
        AtomicJsonWriter(self.state_file.parent).write_json(
            self.state_file.name,
            dict(state),
        )


def _summary_for_audit(
    *,
    settings: P1Settings,
    request_input: P1RequestInput,
    audit: Any,
    trace_root: Path,
) -> dict[str, Any]:
    trace: Mapping[str, Any] = {}
    try:
        trace = AgentTraceReadService(trace_root).get_trace(
            request_input.request_id
        )
    except Exception:
        trace = {}
    runs = (
        trace.get("agent_runs")
        if isinstance(trace.get("agent_runs"), list)
        else []
    )
    judge = _mapping(trace.get("judge"))
    rca = _mapping(trace.get("rca"))
    missing = set(
        str(item)
        for item in (
            list(judge.get("missing_required_sources") or [])
            + list(judge.get("missing_optional_sources") or [])
            + list(rca.get("missing_evidence") or [])
        )
    )
    directory = (
        trace_root / request_input.request_id / "v12"
    )
    files = {
        path.name
        for path in directory.glob("*.json")
        if path.is_file() and not path.is_symlink()
    } if directory.is_dir() and not directory.is_symlink() else set()
    artifact_complete = (
        audit.status == ShadowStatus.COMPLETED
        and (_EXPECTED_TRACE_FILES - {"p1_canary.json"})
        .issubset(files)
    )
    return {
        "schema_version": P1_SCHEMA_VERSION,
        "activation_id": settings.activation_id,
        "request_id": request_input.request_id,
        "family": request_input.family,
        "source": request_input.source,
        "status": audit.status.value,
        "reason": audit.reason,
        "error_code": audit.error_code,
        "started_at": audit.started_at.isoformat(),
        "finished_at": audit.finished_at.isoformat(),
        "duration_ms": audit.duration_ms,
        "legacy_preserved": audit.legacy_preserved,
        "fail_open_to_legacy": audit.fail_open_to_legacy,
        "legacy_notification_count": (
            audit.legacy_notification_count
        ),
        "shadow_notification_count": 0,
        "notification_count_delta": 0,
        "second_card_sent": False,
        "production_card_replaced": False,
        "agent_statuses": [
            {
                "agent_name": str(item.get("agent_name") or ""),
                "status": str(item.get("status") or ""),
                "duration_ms": int(
                    item.get("duration_ms") or 0
                ),
            }
            for item in runs
            if isinstance(item, Mapping)
        ],
        "judge_status": str(judge.get("status") or ""),
        "missing_evidence": sorted(missing),
        "rca_status": str(rca.get("status") or ""),
        "fallback_to_legacy": bool(
            trace.get("fallback_to_legacy", False)
        ),
        "artifact_complete": artifact_complete,
        "trace_file_names": sorted(files),
        "full_logs_copied": False,
        "full_device_output_copied": False,
        "full_metrics_copied": False,
        "raw_payload_copied": False,
        "external_calls": {
            "production_glm": False,
            "prometheus_mcp": False,
            "netmiko_mcp": False,
            "evidence_mcp": False,
            "ops_es_api": False,
            "analytics_mcp": False,
            "fastmcp": False,
            "elasticsearch_direct": False,
            "notification": False,
        },
    }


def run_p1_after_legacy_safe(
    *,
    request_id: str,
    notify_result: Mapping[str, Any] | None = None,
    logger: Any | None = None,
    project_root: str | Path = DEFAULT_PROJECT_ROOT,
    runtime_config: str | Path | None = None,
    trace_root: str | Path | None = None,
    governance_root: str | Path | None = None,
    state_file: str | Path | None = None,
) -> dict[str, Any]:
    """Fail-open entry used by the existing legacy callback route."""

    safe_id = str(request_id)
    root = Path(project_root)
    config_path = Path(
        runtime_config
        or root / "config" / "v12_p1_shadow.yaml"
    )
    trace_path = Path(
        trace_root
        or root / "data" / "evidence_hub" / "requests"
    )
    state_path = Path(
        state_file
        or (
            root
            / "data"
            / "evidence_hub"
            / "p1_shadow_canary_state.json"
        )
    )
    settings: P1Settings | None = None
    request_input: P1RequestInput | None = None
    state: P1CanaryState | None = None
    try:
        settings = load_p1_settings(config_path)
        if settings is None or not settings.enabled:
            return {
                "status": "disabled",
                "request_id": safe_id,
                "external_calls": False,
            }
        if not settings.active_now:
            return {
                "status": "inactive_window",
                "request_id": safe_id,
                "activation_id": settings.activation_id,
                "external_calls": False,
            }
        request_input = load_request_input(
            safe_id,
            project_root=root,
        )
        if request_input.source != "alertmanager":
            return {
                "status": "skipped_source",
                "request_id": safe_id,
                "source": request_input.source,
                "external_calls": False,
            }
        if request_input.family not in settings.allowed_families:
            return {
                "status": "skipped_family",
                "request_id": safe_id,
                "family": request_input.family,
                "external_calls": False,
            }
        state = P1CanaryState(state_path)
        claimed, reason = state.claim(settings, safe_id)
        if not claimed:
            return {
                "status": "skipped_limit_or_duplicate",
                "request_id": safe_id,
                "reason": reason,
                "external_calls": False,
            }

        runner = P1ArtifactReuseRunner(
            settings=settings,
            request_input=request_input,
            project_root=root,
            trace_root=trace_path,
            governance_root=governance_root,
        )
        snapshot = LegacyDeliverySnapshot(
            request_id=safe_id,
            route="/webhook/alertmanager",
            alert_status=request_input.alert_status,
            legacy_completed=True,
            legacy_notification_count=(
                _legacy_notification_count(notify_result)
            ),
            legacy_notification_ref=None,
            captured_at=datetime.now(timezone.utc),
            legacy_metadata={
                "p1_activation_id": settings.activation_id,
                "legacy_result_preserved": True,
            },
        )
        audit_store = ShadowAuditStore(trace_path)
        controller = ShadowIntegrationController(
            settings=ShadowIntegrationSettings(
                enabled=True,
                mode="shadow",
                fail_open_to_legacy=True,
                timeout_ms=(
                    settings.total_timeout_seconds * 1000
                ),
                allowed_routes=("/webhook/alertmanager",),
                excluded_routes=(
                    "/light-alert/alertmanager",
                ),
                send_notification=False,
                replace_production_card=False,
                rca_enabled=False,
            ),
            runner=runner,
            audit_store=audit_store,
        )
        audit = asyncio.run(
            controller.run_after_legacy(
                snapshot,
                input_refs=[],
                input_snapshot={
                    "request_id": safe_id,
                    "source": request_input.source,
                    "family": request_input.family,
                    "event_count": request_input.event_count,
                    "raw_payload": "[OMITTED]",
                },
            )
        )
        shadow_file = (
            trace_path
            / safe_id
            / "v12"
            / "shadow_integration.json"
        )
        if not shadow_file.is_file():
            audit_store.persist(audit)
        summary = _summary_for_audit(
            settings=settings,
            request_input=request_input,
            audit=audit,
            trace_root=trace_path,
        )
        AtomicJsonWriter(
            trace_path / safe_id / "v12"
        ).write_json("p1_canary.json", summary)
        state.record(
            settings,
            safe_id,
            audit.status.value,
        )
        if logger is not None:
            logger.info(
                "v12 P1 shadow completed request_id=%s "
                "status=%s family=%s duration_ms=%s",
                safe_id,
                audit.status.value,
                request_input.family,
                audit.duration_ms,
            )
        return {
            "status": audit.status.value,
            "request_id": safe_id,
            "family": request_input.family,
            "activation_id": settings.activation_id,
            "legacy_preserved": True,
            "notification_count_delta": 0,
            "external_calls": False,
        }
    except Exception as exc:
        if logger is not None:
            try:
                logger.exception(
                    "v12 P1 shadow failed open request_id=%s: %r",
                    safe_id,
                    exc,
                )
            except Exception:
                pass
        if settings is not None and settings.enabled:
            try:
                validate_request_id(safe_id)
                family = (
                    request_input.family
                    if request_input is not None
                    else ""
                )
                failure = {
                    "schema_version": P1_SCHEMA_VERSION,
                    "activation_id": settings.activation_id,
                    "request_id": safe_id,
                    "family": family,
                    "source": (
                        request_input.source
                        if request_input is not None
                        else ""
                    ),
                    "status": "failed_open",
                    "reason": "p1_safe_entry_exception",
                    "error_code": type(exc).__name__,
                    "started_at": datetime.now(timezone.utc).isoformat(),
                    "finished_at": datetime.now(timezone.utc).isoformat(),
                    "duration_ms": 0,
                    "legacy_preserved": True,
                    "fail_open_to_legacy": True,
                    "legacy_notification_count": (
                        _legacy_notification_count(
                            notify_result
                        )
                    ),
                    "shadow_notification_count": 0,
                    "notification_count_delta": 0,
                    "second_card_sent": False,
                    "production_card_replaced": False,
                    "agent_statuses": [],
                    "judge_status": "",
                    "missing_evidence": [],
                    "rca_status": "",
                    "fallback_to_legacy": True,
                    "artifact_complete": False,
                    "trace_file_names": [],
                    "full_logs_copied": False,
                    "full_device_output_copied": False,
                    "full_metrics_copied": False,
                    "raw_payload_copied": False,
                    "external_calls": {
                        "production_glm": False,
                        "prometheus_mcp": False,
                        "netmiko_mcp": False,
                        "evidence_mcp": False,
                        "ops_es_api": False,
                        "analytics_mcp": False,
                        "fastmcp": False,
                        "elasticsearch_direct": False,
                        "notification": False,
                    },
                }
                AtomicJsonWriter(
                    trace_path / safe_id / "v12"
                ).write_json("p1_canary.json", failure)
                (state or P1CanaryState(state_path)).record(
                    settings,
                    safe_id,
                    "failed_open",
                )
            except Exception:
                pass
        return {
            "status": "failed_open",
            "request_id": safe_id,
            "legacy_preserved": True,
            "notification_count_delta": 0,
            "error_category": type(exc).__name__,
            "external_calls": False,
        }


def collect_p1_observations(
    *,
    trace_root: str | Path = DEFAULT_TRACE_ROOT,
    activation_id: str = "",
) -> dict[str, Any]:
    root = Path(trace_root)
    records: list[Mapping[str, Any]] = []
    if root.is_dir() and not root.is_symlink():
        for path in root.glob("*/v12/p1_canary.json"):
            if path.is_symlink() or not path.is_file():
                continue
            try:
                item = _safe_json_read(
                    path,
                    max_bytes=1024 * 1024,
                )
            except Exception:
                continue
            if activation_id and (
                str(item.get("activation_id") or "")
                != activation_id
            ):
                continue
            records.append(item)
    statuses = Counter(
        str(item.get("status") or "")
        for item in records
    )
    judge_statuses = Counter(
        str(item.get("judge_status") or "")
        for item in records
        if item.get("judge_status")
    )
    missing = Counter(
        str(value)
        for item in records
        for value in (
            item.get("missing_evidence")
            if isinstance(
                item.get("missing_evidence"),
                list,
            )
            else []
        )
    )
    durations = [
        int(item.get("duration_ms") or 0)
        for item in records
    ]
    completed = int(statuses.get("completed", 0))
    failed_open = int(statuses.get("failed_open", 0))
    external_violations = sum(
        1
        for item in records
        if any(
            bool(value)
            for value in _mapping(
                item.get("external_calls")
            ).values()
        )
    )
    notification_violations = sum(
        1
        for item in records
        if (
            int(item.get("notification_count_delta") or 0)
            != 0
            or item.get("second_card_sent") is not False
            or item.get("production_card_replaced") is not False
        )
    )
    incomplete = sum(
        1
        for item in records
        if item.get("artifact_complete") is not True
    )
    return {
        "schema_version": P1_SCHEMA_VERSION,
        "activation_id": activation_id,
        "record_count": len(records),
        "completed_count": completed,
        "failed_open_count": failed_open,
        "success_rate": (
            completed / len(records)
            if records
            else 0.0
        ),
        "average_duration_ms": (
            sum(durations) / len(durations)
            if durations
            else 0.0
        ),
        "maximum_duration_ms": max(durations, default=0),
        "status_distribution": dict(sorted(statuses.items())),
        "judge_distribution": dict(
            sorted(judge_statuses.items())
        ),
        "missing_evidence_distribution": dict(
            sorted(missing.items())
        ),
        "fallback_count": sum(
            1
            for item in records
            if bool(item.get("fallback_to_legacy"))
        ),
        "artifact_incomplete_count": incomplete,
        "external_call_violation_count": external_violations,
        "notification_regression_count": (
            notification_violations
        ),
        "records": [
            {
                "request_id": str(
                    item.get("request_id") or ""
                ),
                "family": str(item.get("family") or ""),
                "status": str(item.get("status") or ""),
                "duration_ms": int(
                    item.get("duration_ms") or 0
                ),
                "judge_status": str(
                    item.get("judge_status") or ""
                ),
                "artifact_complete": bool(
                    item.get("artifact_complete")
                ),
            }
            for item in sorted(
                records,
                key=lambda value: str(
                    value.get("finished_at") or ""
                ),
            )
        ],
    }


def evaluate_p1_gate(
    observations: Mapping[str, Any],
    *,
    minimum_completed: int,
) -> dict[str, Any]:
    violations: list[str] = []
    completed = int(
        observations.get("completed_count") or 0
    )
    if completed < int(minimum_completed):
        violations.append("minimum_completed_not_reached")
    if int(observations.get("failed_open_count") or 0):
        violations.append("failed_open_detected")
    if int(
        observations.get("external_call_violation_count") or 0
    ):
        violations.append("external_call_detected")
    if int(
        observations.get("notification_regression_count") or 0
    ):
        violations.append("notification_regression_detected")
    if int(
        observations.get("artifact_incomplete_count") or 0
    ):
        violations.append("artifact_incomplete")
    return {
        "schema_version": P1_SCHEMA_VERSION,
        "status": "passed" if not violations else "failed",
        "minimum_completed": int(minimum_completed),
        "completed_count": completed,
        "violation_count": len(violations),
        "violations": violations,
    }


__all__ = [
    "DEFAULT_ALLOWED_FAMILIES",
    "DEFAULT_PROJECT_ROOT",
    "DEFAULT_RUNTIME_CONFIG",
    "DEFAULT_STATE_FILE",
    "DEFAULT_TRACE_ROOT",
    "P1ArtifactReuseRunner",
    "P1CanaryError",
    "P1CanaryState",
    "P1RequestInput",
    "P1Settings",
    "P1_SCHEMA_VERSION",
    "collect_p1_observations",
    "evaluate_p1_gate",
    "load_p1_settings",
    "load_request_input",
    "run_p1_after_legacy_safe",
]
