"""Batch P2 controlled real-Agent Shadow Canary.

P2 is a manual, bounded Canary. It does not mount into the production
Alertmanager route and does not send a notification. It selects one existing
single-event firing Alertmanager sample with a real, Safety-Policy-approved
target, then runs the frozen v12 sequence with:

- one fixed Prometheus MCP range query;
- one existing read-only Playbook command through the Netmiko MCP wrapper;
- one GLM 5.2 RCA request that reads only the Evidence Bundle and Judge result.

Logs and Knowledge remain not_available. Evidence MCP 10002, Analytics MCP
10004, FastMCP, Elasticsearch, arbitrary PromQL, arbitrary CLI, write commands,
automatic follow-up queries, and a second card remain forbidden.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import shlex
import subprocess
import time
import traceback
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol
from urllib.parse import urlparse

import yaml

from agent_runner.executors import run_mcp_commands_placeholder
from netaiops.family_registry import classify_family
from netaiops.llm_client import call_llm
from netaiops.normalizers import normalize_alertmanager
from netaiops.plan_builder import command_is_readonly
from netaiops.prometheus_evidence_v8 import collect_prometheus_evidence
from netaiops.prometheus_metric_mapping import (
    PrometheusMetricMapping,
    normalize_context,
)
from netaiops.prometheus_plan_hooks import (
    apply_prometheus_evidence_metadata_to_plan,
)
from netaiops.safety_policy import (
    evaluate_candidate,
    evaluate_plan_safety,
    safety_config,
)

from .agent_trace_store import AgentTraceStore
from .agents.evidence_judge_agent import EvidenceJudgeAgent
from .agents.knowledge_context_agent import KnowledgeContextAgent
from .agents.logs_evidence_agent import LogsEvidenceAgent
from .agents.notification_report_agent import NotificationReportAgent
from .agents.static_planner_agent import StaticPlannerAgent
from .agents.triage_agent import TriageAgent
from .api import AgentTraceReadService
from .atomic_writer import AtomicJsonWriter
from .contracts import (
    AgentRunRecord,
    ContractNotice,
    EvidenceEnvelope,
    ExternalCallRecord,
)
from .evidence_bundle import BundleArtifacts, EvidenceBundleBuilder
from .execution_context import (
    AgentInvocation,
    AgentOutcome,
    OrchestrationResult,
)
from .governance_adapter import AgentTraceGovernanceAdapter
from .p2_controlled_canary import (
    DEFAULT_ALLOWED_FAMILIES,
    P2CallKind,
    P2CallLedger,
    P2CanaryPolicy,
    P2ContractError,
    P2Settings,
)
from .rca_validator import (
    bundle_evidence_refs,
    inherited_missing_evidence,
    validate_rca_response,
)
from .schema_validator import (
    build_contract_ref,
    build_evidence_ref,
    parse_contract_ref,
    sanitize_sensitive_data,
    stable_json_dumps,
    validate_request_id,
)
from .state_machine import OrchestrationState
from .status import (
    AgentName,
    AgentStatus,
    EvidenceSource,
    EvidenceStatus,
    ExternalCallStatus,
    JudgeStatus,
)


P2_REAL_SCHEMA_VERSION = "v12-p2-real-canary-1"
DEFAULT_PROJECT_ROOT = Path("/opt/netaiops-webhook")
DEFAULT_CONFIG_PATH = DEFAULT_PROJECT_ROOT / "config.yaml"
EXPECTED_CALL_KINDS = (
    P2CallKind.METRICS,
    P2CallKind.DEVICE,
    P2CallKind.RCA,
)
EXPECTED_AGENT_ORDER = (
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
EXPECTED_TRACE_FILES = frozenset(
    {
        "unified_event.json",
        "evidence_plan.json",
        "agent_runs.json",
        "evidence_bundle.json",
        "judge_result.json",
        "rca_result.json",
        "report.json",
        "shadow_integration.json",
        "p2_canary.json",
    }
)
DANGEROUS_COMMAND_RE = re.compile(
    r"""(?ix)
    (^\s*(?:conf(?:ig(?:ure)?)?|set|unset|delete|edit|add|create|
      modify|remove|clear|reset|reload|reboot|shutdown|no\s+shutdown|
      write|copy|commit|save|erase|format|mkdir|rm|mv|chmod|chown|
      bash|python|sh|sudo|systemctl)\b)
    |(;|&&|\|\|)
    """
)


class P2RealCanaryError(RuntimeError):
    """Raised when a real Canary violates a frozen P2 boundary."""


@dataclass(frozen=True, slots=True)
class P2CanarySample:
    original_request_id: str
    source: str
    family: str
    raw_payload: Mapping[str, Any]
    normalized_event: Mapping[str, Any]
    legacy_plan: Mapping[str, Any]
    target_scope: Mapping[str, Any]
    command_candidate: Mapping[str, Any]
    metrics_profile: str
    metrics_query_name: str
    metrics_target: Mapping[str, Any]
    raw_path: str
    normalized_path: str
    plan_path: str
    discovery_mode: str

    def public_dict(self) -> dict[str, Any]:
        command = str(
            self.command_candidate.get("command") or ""
        )
        return {
            "original_request_id": self.original_request_id,
            "source": self.source,
            "family": self.family,
            "target": {
                "hostname": self.target_scope.get("hostname"),
                "device_ip": self.target_scope.get("device_ip"),
                "interface": (
                    self.target_scope.get("interface")
                    or self.target_scope.get("if_name")
                    or self.target_scope.get("ifName")
                ),
                "vendor": self.target_scope.get("vendor"),
                "platform": self.target_scope.get("platform"),
            },
            "command_sha256": hashlib.sha256(
                command.encode("utf-8")
            ).hexdigest(),
            "command_prefix": command.split(" ", 1)[0].lower(),
            "metrics_profile": self.metrics_profile,
            "metrics_query_name": self.metrics_query_name,
            "raw_path_name": Path(self.raw_path).name,
            "normalized_path_name": Path(
                self.normalized_path
            ).name,
            "plan_path_name": Path(self.plan_path).name,
            "discovery_mode": self.discovery_mode,
        }


class MetricsCollector(Protocol):
    async def collect(
        self,
        *,
        request_id: str,
        sample: P2CanarySample,
        settings: P2Settings,
        ledger: P2CallLedger,
    ) -> AgentOutcome:
        """Collect one bounded Metrics evidence result."""


class DeviceCollector(Protocol):
    async def collect(
        self,
        *,
        request_id: str,
        sample: P2CanarySample,
        settings: P2Settings,
        ledger: P2CallLedger,
    ) -> AgentOutcome:
        """Collect one bounded Device evidence result."""


class RCACollector(Protocol):
    async def collect(
        self,
        *,
        request_id: str,
        outputs: Mapping[str, Mapping[str, Any]],
        output_refs: tuple[str, ...],
        settings: P2Settings,
        ledger: P2CallLedger,
    ) -> AgentOutcome:
        """Generate one evidence-grounded RCA result."""


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _aware_now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_json_read(
    path: Path,
    *,
    max_bytes: int = 16 * 1024 * 1024,
) -> Mapping[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise P2RealCanaryError(
            f"unsafe or missing JSON file: {path}"
        )
    if path.stat().st_size > max_bytes:
        raise P2RealCanaryError(
            f"JSON file exceeds size limit: {path.name}"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise P2RealCanaryError(
            f"JSON file cannot be decoded: {path.name}"
        ) from exc
    if not isinstance(value, Mapping):
        raise P2RealCanaryError(
            f"JSON root must be an object: {path.name}"
        )
    return value


def _private_target_ip(value: Any) -> bool:
    text = _text(value).split(":", 1)[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    documentation_ranges = (
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    )
    if any(address in network for network in documentation_ranges):
        return False
    return bool(
        address.version == 4
        and address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_unspecified
    )


def _validate_mcp_endpoint(
    url: str,
    *,
    expected_port: int,
    label: str,
) -> None:
    parsed = urlparse(_text(url))
    if parsed.scheme not in {"http", "https"}:
        raise P2RealCanaryError(
            f"{label} endpoint scheme is not http/https"
        )
    if parsed.username is not None or parsed.password is not None:
        raise P2RealCanaryError(
            f"{label} endpoint must not contain credentials"
        )
    if parsed.hostname != "10.191.97.137":
        raise P2RealCanaryError(
            f"{label} endpoint host is not approved"
        )
    if parsed.port != expected_port:
        raise P2RealCanaryError(
            f"{label} endpoint port is not approved"
        )


def _family_from_event(event: Mapping[str, Any]) -> str:
    result = classify_family(dict(event))
    return _text(
        result.get("family")
        or event.get("family")
        or "generic_network_readonly"
    )


def _event_status(event: Mapping[str, Any]) -> str:
    labels = _mapping(event.get("labels"))
    status = _text(
        event.get("status")
        or event.get("alert_status")
        or labels.get("status")
        or "firing"
    ).lower()
    return (
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


def _single_raw_alert(payload: Mapping[str, Any]) -> bool:
    alerts = payload.get("alerts")
    return (
        isinstance(alerts, list)
        and len(alerts) == 1
        and isinstance(alerts[0], Mapping)
    )


def _target_scope(plan: Mapping[str, Any]) -> Mapping[str, Any]:
    target = _mapping(plan.get("target_scope"))
    interface = (
        target.get("interface")
        or target.get("if_name")
        or target.get("ifName")
        or target.get("interface_name")
    )
    if not _private_target_ip(
        target.get("device_ip")
        or target.get("ip")
        or target.get("instance")
    ):
        return {}
    if not _text(interface):
        return {}
    return target


def _safe_candidate(
    plan: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    target = _target_scope(plan)
    if not target:
        return None

    high_risk = {
        _text(item).lower()
        for item in safety_config().get(
            "high_risk_devices",
            [],
        )
        if _text(item)
    }
    identities = {
        _text(target.get("device_ip")).lower(),
        _text(target.get("hostname")).lower(),
        _text(target.get("mcp_device_name")).lower(),
    }
    identities.discard("")
    if any(
        risk == identity or risk in identity
        for risk in high_risk
        for identity in identities
    ):
        return None

    candidates = [
        dict(item)
        for item in (plan.get("execution_candidates") or [])
        if isinstance(item, Mapping)
    ]
    if not candidates:
        return None

    cfg = safety_config()
    interface = _text(
        target.get("interface")
        or target.get("if_name")
        or target.get("ifName")
    ).lower()

    ranked: list[tuple[int, int, Mapping[str, Any]]] = []
    for index, item in enumerate(candidates):
        command = _text(item.get("command"))
        if not command:
            continue
        if "{" in command or "}" in command:
            continue
        if DANGEROUS_COMMAND_RE.search(command):
            continue
        if not command_is_readonly(command):
            continue

        candidate = dict(item)
        candidate["readonly"] = True
        evaluation = evaluate_candidate(candidate, cfg)
        if not evaluation.get("safe"):
            continue

        lowered = command.lower()
        score = 0
        if interface and interface in lowered:
            score += 100
        if any(
            token in lowered
            for token in (
                "interface",
                "port-channel",
                "ethernet",
                "transceiver",
                "counter",
                "brief",
            )
        ):
            score += 30
        if lowered.startswith("show clock"):
            score -= 100
        if " log" in lowered or lowered.startswith("show log"):
            score -= 30
        ranked.append((-score, index, candidate))

    if not ranked:
        return None
    ranked.sort(key=lambda item: (item[0], item[1]))
    selected = dict(ranked[0][2])

    one_command_plan = dict(plan)
    one_command_plan["execution_candidates"] = [selected]
    safety = evaluate_plan_safety(one_command_plan)
    if not safety.get("allowed"):
        return None
    return selected


def _prometheus_contract(
    plan: Mapping[str, Any],
    project_root: Path,
) -> tuple[str, str, Mapping[str, Any]] | None:
    normalized = apply_prometheus_evidence_metadata_to_plan(
        dict(plan)
    )
    metadata = _mapping(
        normalized.get("prometheus_evidence_first")
    )
    if metadata.get("enabled") is not True:
        return None
    if _text(metadata.get("status")) != "metadata_ready":
        return None
    profile = _text(metadata.get("evidence_profile"))
    query_names = [
        _text(item)
        for item in (metadata.get("query_names") or [])
        if _text(item)
    ]
    target = normalize_context(
        dict(_mapping(metadata.get("target_context")))
    )
    if not profile or not query_names:
        return None

    mapping = PrometheusMetricMapping(
        str(project_root / "config" / "prometheus_metrics.yaml")
    )
    for query_name in query_names:
        try:
            candidates = mapping.render_candidates(
                profile,
                query_name,
                target,
            )
        except Exception:
            continue
        usable = [
            item
            for item in candidates
            if not item.get("missing_variables")
        ]
        if usable:
            return profile, query_name, target
    return None


def _matching_file(
    root: Path,
    request_id: str,
    suffix: str,
) -> Path | None:
    candidates = [
        path
        for path in root.glob(f"*_{request_id}{suffix}")
        if path.is_file() and not path.is_symlink()
    ]
    if not candidates:
        return None
    candidates.sort(
        key=lambda path: (
            path.stat().st_mtime_ns,
            path.name,
        ),
        reverse=True,
    )
    return candidates[0]


def discover_real_canary_sample(
    project_root: str | Path = DEFAULT_PROJECT_ROOT,
    *,
    preferred_request_id: str | None = None,
) -> P2CanarySample:
    root = Path(project_root)
    plan_root = root / "data" / "plans"
    raw_root = root / "data" / "raw"
    normalized_root = root / "data" / "normalized"

    if not all(
        path.is_dir()
        for path in (plan_root, raw_root, normalized_root)
    ):
        raise P2RealCanaryError(
            "production Raw/Normalized/Plan roots are unavailable"
        )

    plans = [
        path
        for path in plan_root.glob("*.plan.json")
        if path.is_file() and not path.is_symlink()
    ]
    plans.sort(
        key=lambda path: (
            path.stat().st_mtime_ns,
            path.name,
        ),
        reverse=True,
    )
    if preferred_request_id:
        safe_preferred = validate_request_id(
            preferred_request_id
        )
        filtered: list[Path] = []
        for path in plans:
            try:
                candidate_id = _text(
                    _safe_json_read(path).get("request_id")
                )
            except Exception:
                continue
            if candidate_id == safe_preferred:
                filtered.append(path)
        plans = filtered

    rejection_counts: dict[str, int] = {}
    for plan_path in plans:
        reason = ""
        try:
            plan = _safe_json_read(plan_path)
            request_id = _text(plan.get("request_id"))
            validate_request_id(request_id)
            source = _text(plan.get("source")).lower()
            if source != "alertmanager":
                reason = "source_not_alertmanager"
                raise ValueError(reason)

            normalized_path = _matching_file(
                normalized_root,
                request_id,
                ".json",
            )
            raw_path = _matching_file(
                raw_root,
                request_id,
                ".json",
            )
            if normalized_path is None or raw_path is None:
                reason = "raw_or_normalized_missing"
                raise ValueError(reason)

            normalized = _safe_json_read(normalized_path)
            events = normalized.get("events")
            if not (
                isinstance(events, list)
                and len(events) == 1
                and isinstance(events[0], Mapping)
            ):
                reason = "single_event_required"
                raise ValueError(reason)
            event = dict(events[0])
            if _event_status(event) != "firing":
                reason = "firing_required"
                raise ValueError(reason)

            family = _family_from_event(event)
            if family not in DEFAULT_ALLOWED_FAMILIES:
                reason = "family_not_approved"
                raise ValueError(reason)

            raw_payload = _safe_json_read(raw_path)
            if not _single_raw_alert(raw_payload):
                reason = "raw_single_alert_required"
                raise ValueError(reason)

            target = _target_scope(plan)
            if not target:
                reason = "safe_real_interface_target_missing"
                raise ValueError(reason)

            candidate = _safe_candidate(plan)
            if candidate is None:
                reason = "safe_command_missing"
                raise ValueError(reason)

            metrics = _prometheus_contract(plan, root)
            if metrics is None:
                reason = "fixed_metrics_contract_missing"
                raise ValueError(reason)
            profile, query_name, metrics_target = metrics

            return P2CanarySample(
                original_request_id=request_id,
                source=source,
                family=family,
                raw_payload=raw_payload,
                normalized_event=event,
                legacy_plan=plan,
                target_scope=target,
                command_candidate=candidate,
                metrics_profile=profile,
                metrics_query_name=query_name,
                metrics_target=metrics_target,
                raw_path=str(raw_path),
                normalized_path=str(normalized_path),
                plan_path=str(plan_path),
                discovery_mode="historical_real_target",
            )
        except Exception:
            key = reason or "invalid_or_unreadable"
            rejection_counts[key] = (
                rejection_counts.get(key, 0) + 1
            )
            continue

    summary = ", ".join(
        f"{key}={value}"
        for key, value in sorted(rejection_counts.items())
    )
    raise P2RealCanaryError(
        "no safe P2 real-Canary sample was found; "
        + (summary or "no plan artifacts")
    )


def build_active_p2_settings(
    activation_id: str,
) -> P2Settings:
    now = _aware_now()
    settings = P2Settings(
        schema_version="v12-p2-controlled-canary-1",
        activation_id=activation_id,
        enabled=True,
        mode="shadow",
        fail_open_to_legacy=True,
        notifications_use_v12=False,
        logs_enabled=False,
        knowledge_enabled=False,
        metrics_real_calls_enabled=True,
        device_real_calls_enabled=True,
        rca_real_calls_enabled=True,
        reuse_existing_evidence_before_real_call=True,
        activated_at=now - timedelta(seconds=5),
        canary_window_minutes=60,
        max_canary_requests=1,
        minimum_completed_for_gate=1,
        allowed_families=tuple(DEFAULT_ALLOWED_FAMILIES),
        total_timeout_seconds=90,
        metrics_timeout_seconds=20,
        device_timeout_seconds=30,
        rca_timeout_seconds=30,
        max_metrics_calls_per_request=1,
        max_device_calls_per_request=1,
        max_rca_calls_per_request=1,
        max_total_external_calls_per_request=3,
        promql_generation_allowed=False,
        command_generation_allowed=False,
        dsl_generation_allowed=False,
        write_commands_allowed=False,
        arbitrary_tool_selection_allowed=False,
        automatic_followup_queries_allowed=False,
    )
    settings.validate_frozen_boundary()
    return settings


def _notice(
    code: str,
    message: str,
    *,
    stage: str,
    details: Mapping[str, Any] | None = None,
) -> ContractNotice:
    return ContractNotice(
        code=code,
        message=message,
        stage=stage,
        retryable=False,
        details=dict(details or {}),
    )


def _external_record(
    *,
    request_id: str,
    system: str,
    operation: str,
    status: ExternalCallStatus,
    started_at: datetime,
    finished_at: datetime,
    request_ref: str,
    response_ref: str | None,
    error: ContractNotice | None = None,
) -> ExternalCallRecord:
    return ExternalCallRecord(
        system=system,
        operation=operation,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=max(
            0,
            int((finished_at - started_at).total_seconds() * 1000),
        ),
        request_ref=request_ref,
        response_ref=response_ref,
        error=error,
    )


def _minimal_prometheus_config(
    production_config: Mapping[str, Any],
    destination: Path,
    timeout_seconds: int,
) -> Path:
    config = _mapping(production_config.get("prometheus_mcp"))
    sse_url = _text(config.get("sse_url"))
    if not bool(config.get("enabled", False)):
        raise P2RealCanaryError(
            "production prometheus_mcp.enabled is not true"
        )
    if not sse_url:
        raise P2RealCanaryError(
            "production prometheus_mcp.sse_url is empty"
        )
    _validate_mcp_endpoint(
        sse_url,
        expected_port=10001,
        label="Prometheus MCP",
    )

    payload = {
        "prometheus_mcp": {
            "enabled": True,
            "sse_url": sse_url,
            "backend_url": _text(config.get("backend_url")),
            "timeout_seconds": min(
                int(timeout_seconds),
                int(config.get("timeout_seconds") or timeout_seconds),
            ),
            "fallback_http_api": {
                "enabled": False,
                "url": "",
            },
        },
        "prometheus_direct": {
            "enabled_for_targets": False,
            "url": "",
        },
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        yaml.safe_dump(
            payload,
            allow_unicode=True,
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    os.chmod(destination, 0o600)
    return destination


class RealPrometheusCollector:
    def __init__(
        self,
        *,
        project_root: str | Path,
        work_root: str | Path,
        production_config: Mapping[str, Any],
    ) -> None:
        self.project_root = Path(project_root)
        self.work_root = Path(work_root)
        self.production_config = dict(production_config)

    async def collect(
        self,
        *,
        request_id: str,
        sample: P2CanarySample,
        settings: P2Settings,
        ledger: P2CallLedger,
    ) -> AgentOutcome:
        profile = sample.metrics_profile
        query_name = sample.metrics_query_name
        target = dict(sample.metrics_target)

        mapping = PrometheusMetricMapping(
            str(
                self.project_root
                / "config"
                / "prometheus_metrics.yaml"
            )
        )
        candidates = mapping.render_candidates(
            profile,
            query_name,
            normalize_context(target),
        )
        usable = [
            item
            for item in candidates
            if not item.get("missing_variables")
        ]
        if not usable:
            raise P2RealCanaryError(
                "fixed Prometheus mapping has no usable candidate"
            )

        ledger.reserve(
            P2CallKind.METRICS,
            operation_id=(
                "fixed-range:"
                + hashlib.sha256(
                    f"{profile}:{query_name}".encode("utf-8")
                ).hexdigest()[:16]
            ),
            provider="prometheus-mcp-10001",
        )

        config_path = _minimal_prometheus_config(
            self.production_config,
            self.work_root / "runtime" / "prometheus_minimal.yaml",
            settings.metrics_timeout_seconds,
        )
        request_ref = build_contract_ref(
            "artifact",
            request_id,
            "external_request",
            "prometheus-range-query",
        )
        started_at = _aware_now()
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: collect_prometheus_evidence(
                profile=profile,
                query_name=query_name,
                target=target,
                mapping_path=str(
                    self.project_root
                    / "config"
                    / "prometheus_metrics.yaml"
                ),
                config_path=str(config_path),
                lookback_minutes=15,
                compare_offset_minutes=5,
                step="60s",
                max_candidates_per_query=1,
            ),
        )
        finished_at = _aware_now()

        attempts = result.get("attempts") or []
        if len(attempts) != 1:
            raise P2RealCanaryError(
                "Prometheus Canary must perform exactly one "
                f"candidate attempt; observed={len(attempts)}"
            )
        attempt = _mapping(attempts[0])
        if (
            _text(attempt.get("bridge_source"))
            != "prometheus_mcp"
            or attempt.get("fallback_used") is True
        ):
            raise P2RealCanaryError(
                "Prometheus Canary did not remain MCP-only"
            )

        digest = hashlib.sha256(
            stable_json_dumps(
                {
                    "profile": profile,
                    "query_name": query_name,
                    "status": result.get("status"),
                    "analysis": result.get("analysis"),
                    "attempt": {
                        "bridge_ok": attempt.get("bridge_ok"),
                        "analysis_ok": attempt.get("analysis_ok"),
                        "series_count": attempt.get("series_count"),
                    },
                }
            ).encode("utf-8")
        ).hexdigest()[:24]
        evidence_ref = build_evidence_ref(
            request_id,
            "metrics",
            f"prometheus-{digest}",
        )
        response_ref = build_contract_ref(
            "artifact",
            request_id,
            "external_response",
            f"prometheus-{digest}",
        )

        bridge_ok = bool(attempt.get("bridge_ok"))
        analysis_ok = bool(attempt.get("analysis_ok"))
        if not bridge_ok:
            error = _notice(
                "p2_prometheus_mcp_failed",
                "Prometheus MCP range query failed",
                stage="metrics_evidence",
                details={
                    "mcp_error_present": bool(
                        attempt.get("mcp_error")
                    ),
                },
            )
            external = _external_record(
                request_id=request_id,
                system="prometheus_mcp",
                operation="execute_range_query",
                status=ExternalCallStatus.FAILED,
                started_at=started_at,
                finished_at=finished_at,
                request_ref=request_ref,
                response_ref=response_ref,
                error=error,
            )
            envelope = EvidenceEnvelope(
                schema_version="v12.1",
                request_id=request_id,
                source=EvidenceSource.METRICS,
                evidence_kind="evidence",
                status=EvidenceStatus.FAILED,
                summary="Prometheus MCP query failed.",
                facts={
                    "profile": profile,
                    "query_name": query_name,
                    "prometheus_mcp_called": True,
                    "fallback_used": False,
                    "candidate_count": 1,
                },
                scope=dict(target),
                errors=[error],
                collected_at=finished_at,
                reason="prometheus_mcp_query_failed",
            )
            return AgentOutcome(
                status=AgentStatus.FAILED,
                output_refs=(response_ref,),
                output={
                    "metrics_evidence": envelope.model_dump(
                        mode="json"
                    ),
                    "prometheus_mcp_called": True,
                    "promql_generation_performed": False,
                    "query_logic_changed": False,
                    "fallback_used": False,
                },
                errors=(error,),
                external_calls=(external,),
            )

        evidence_status = (
            EvidenceStatus.SUCCESS
            if analysis_ok and result.get("ok")
            else EvidenceStatus.NO_DATA
        )
        agent_status = (
            AgentStatus.SUCCESS
            if evidence_status == EvidenceStatus.SUCCESS
            else AgentStatus.PARTIAL
        )
        warning = None
        if evidence_status == EvidenceStatus.NO_DATA:
            warning = _notice(
                "p2_prometheus_no_data",
                "Prometheus MCP query succeeded but produced no "
                "analyzable series.",
                stage="metrics_evidence",
            )

        external = _external_record(
            request_id=request_id,
            system="prometheus_mcp",
            operation="execute_range_query",
            status=ExternalCallStatus.SUCCESS,
            started_at=started_at,
            finished_at=finished_at,
            request_ref=request_ref,
            response_ref=response_ref,
        )
        analysis = _mapping(result.get("analysis"))
        envelope = EvidenceEnvelope(
            schema_version="v12.1",
            request_id=request_id,
            source=EvidenceSource.METRICS,
            evidence_kind="evidence",
            status=evidence_status,
            summary=(
                "Prometheus MCP returned analyzable interface "
                "window evidence."
                if evidence_status == EvidenceStatus.SUCCESS
                else "Prometheus MCP returned no analyzable "
                "interface series."
            ),
            facts={
                "profile": profile,
                "query_name": query_name,
                "series_count": (
                    analysis.get("series_count")
                    or attempt.get("series_count")
                    or 0
                ),
                "prometheus_mcp_called": True,
                "fallback_used": False,
                "candidate_count": 1,
                "query_sha256": hashlib.sha256(
                    _text(usable[0].get("promql")).encode("utf-8")
                ).hexdigest(),
            },
            scope=dict(target),
            warnings=[warning] if warning else [],
            evidence_refs=[evidence_ref],
            collected_at=finished_at,
            reason=(
                "prometheus_no_analyzable_series"
                if evidence_status == EvidenceStatus.NO_DATA
                else None
            ),
        )
        return AgentOutcome(
            status=agent_status,
            output_refs=(response_ref, evidence_ref),
            output={
                "metrics_evidence": envelope.model_dump(mode="json"),
                "prometheus_mcp_called": True,
                "promql_generation_performed": False,
                "query_logic_changed": False,
                "fallback_used": False,
            },
            warnings=(warning,) if warning else (),
            external_calls=(external,),
        )


def _systemd_service_environment(
    allowed: set[str] | None = None,
) -> dict[str, str]:
    try:
        proc = subprocess.run(
            [
                "systemctl",
                "show",
                "-p",
                "Environment",
                "netaiops-webhook.service",
            ],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except Exception:
        return {}
    if proc.returncode != 0:
        return {}
    raw = proc.stdout or ""
    if raw.startswith("Environment="):
        raw = raw[len("Environment="):]
    try:
        tokens = shlex.split(raw)
    except ValueError:
        return {}
    output: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if allowed is None or key in allowed:
            output[key] = value

    missing = (
        set()
        if allowed is None
        else set(allowed) - set(output)
    )
    if not missing:
        return output

    # EnvironmentFile values are not consistently exposed by older
    # systemd releases. Read only the requested variables from the
    # already-running Webhook process and never print or persist them.
    try:
        pid_proc = subprocess.run(
            [
                "systemctl",
                "show",
                "-p",
                "MainPID",
                "netaiops-webhook.service",
            ],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        pid_text = (pid_proc.stdout or "").strip()
        pid = int(pid_text.split("=", 1)[-1])
    except Exception:
        return output
    if pid <= 0:
        return output

    environ_bytes: bytes | None = None
    environ_path = Path(f"/proc/{pid}/environ")
    try:
        environ_bytes = environ_path.read_bytes()
    except OSError:
        try:
            proc_env = subprocess.run(
                [
                    "sudo",
                    "-n",
                    "cat",
                    str(environ_path),
                ],
                capture_output=True,
                timeout=10,
                check=False,
            )
            if proc_env.returncode == 0:
                environ_bytes = proc_env.stdout
        except Exception:
            environ_bytes = None

    for item in (environ_bytes or b"").split(b"\0"):
        if b"=" not in item:
            continue
        key_bytes, value_bytes = item.split(b"=", 1)
        try:
            key = key_bytes.decode("utf-8")
            value = value_bytes.decode("utf-8")
        except UnicodeError:
            continue
        if key in missing:
            output[key] = value
    return output


def _netmiko_runtime(
    production_config: Mapping[str, Any],
    project_root: Path,
) -> dict[str, str]:
    service_env = _systemd_service_environment(
        {
            "MCP_WRAPPER_CMD",
            "MCP_SERVER_URL",
            "MCP_TIMEOUT",
            "RUNNER_BACKEND",
        }
    )
    mcp = _mapping(production_config.get("mcp"))
    runner = _mapping(production_config.get("runner"))

    wrapper = (
        _text(service_env.get("MCP_WRAPPER_CMD"))
        or _text(os.environ.get("MCP_WRAPPER_CMD"))
        or _text(mcp.get("wrapper_cmd"))
    )
    server_url = (
        _text(service_env.get("MCP_SERVER_URL"))
        or _text(os.environ.get("MCP_SERVER_URL"))
        or _text(mcp.get("server_url"))
    )
    timeout = (
        _text(service_env.get("MCP_TIMEOUT"))
        or _text(os.environ.get("MCP_TIMEOUT"))
        or _text(mcp.get("timeout"))
        or _text(runner.get("command_timeout"))
        or "30"
    )

    if not wrapper:
        raise P2RealCanaryError(
            "Netmiko MCP wrapper command is not configured"
        )
    wrapper_path = Path(wrapper)
    if not wrapper_path.is_absolute():
        wrapper_path = project_root / wrapper_path
    wrapper_path = wrapper_path.resolve()
    if (
        not wrapper_path.is_file()
        or not os.access(wrapper_path, os.X_OK)
    ):
        raise P2RealCanaryError(
            "Netmiko MCP wrapper is missing or not executable"
        )
    if not server_url:
        raise P2RealCanaryError(
            "Netmiko MCP server URL is not configured"
        )
    _validate_mcp_endpoint(
        server_url,
        expected_port=10000,
        label="Netmiko MCP",
    )
    try:
        timeout_value = max(1, min(30, int(timeout)))
    except ValueError as exc:
        raise P2RealCanaryError(
            "Netmiko MCP timeout is invalid"
        ) from exc

    return {
        "MCP_WRAPPER_CMD": str(wrapper_path),
        "MCP_SERVER_URL": server_url,
        "MCP_TIMEOUT": str(timeout_value),
        "MCP_MODE": "placeholder",
        "RUNNER_BACKEND": "mcp",
    }


class RealNetmikoCollector:
    def __init__(
        self,
        *,
        project_root: str | Path,
        production_config: Mapping[str, Any],
    ) -> None:
        self.project_root = Path(project_root)
        self.production_config = dict(production_config)

    async def collect(
        self,
        *,
        request_id: str,
        sample: P2CanarySample,
        settings: P2Settings,
        ledger: P2CallLedger,
    ) -> AgentOutcome:
        candidate = dict(sample.command_candidate)
        command = _text(candidate.get("command"))
        if (
            not command
            or not command_is_readonly(command)
            or DANGEROUS_COMMAND_RE.search(command)
            or "{" in command
            or "}" in command
        ):
            raise P2RealCanaryError(
                "selected Device command is not frozen read-only"
            )

        candidate["readonly"] = True
        try:
            existing_timeout = int(
                candidate.get("timeout_sec")
                or settings.device_timeout_seconds
            )
        except (TypeError, ValueError):
            existing_timeout = settings.device_timeout_seconds
        candidate["timeout_sec"] = max(
            1,
            min(
                existing_timeout,
                settings.device_timeout_seconds,
                30,
            ),
        )
        evaluation = evaluate_candidate(
            candidate,
            safety_config(),
        )
        if not evaluation.get("safe"):
            raise P2RealCanaryError(
                "selected Device command failed Safety Policy"
            )

        ledger.reserve(
            P2CallKind.DEVICE,
            operation_id=(
                "playbook-command:"
                + hashlib.sha256(
                    command.encode("utf-8")
                ).hexdigest()[:16]
            ),
            provider="netmiko-mcp-10000",
        )
        runtime = _netmiko_runtime(
            self.production_config,
            self.project_root,
        )

        request_ref = build_contract_ref(
            "artifact",
            request_id,
            "external_request",
            "netmiko-readonly-command",
        )
        started_at = _aware_now()
        old_env = {
            key: os.environ.get(key)
            for key in runtime
        }
        try:
            os.environ.update(runtime)
            loop = asyncio.get_running_loop()
            results = await loop.run_in_executor(
                None,
                lambda: run_mcp_commands_placeholder(
                    request_id=request_id,
                    target_scope=dict(sample.target_scope),
                    execution_candidates=[candidate],
                ),
            )
        finally:
            for key, value in old_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        finished_at = _aware_now()

        if not (
            isinstance(results, list)
            and len(results) == 1
            and isinstance(results[0], Mapping)
        ):
            raise P2RealCanaryError(
                "Netmiko MCP wrapper did not return one result"
            )
        item = dict(results[0])
        status = _text(item.get("dispatch_status")).lower()
        raw_output = _text(item.get("output"))
        raw_error = _text(item.get("error"))
        judge = dict(_mapping(item.get("judge")))

        digest = hashlib.sha256(
            (
                command
                + "\n"
                + raw_output
                + "\n"
                + raw_error
                + "\n"
                + stable_json_dumps(judge)
            ).encode("utf-8")
        ).hexdigest()[:24]
        evidence_ref = build_evidence_ref(
            request_id,
            "device",
            f"netmiko-{digest}",
        )
        response_ref = build_contract_ref(
            "artifact",
            request_id,
            "external_response",
            f"netmiko-{digest}",
        )

        if status not in {"completed", "partial"}:
            error = _notice(
                "p2_netmiko_mcp_failed",
                "Netmiko MCP read-only command failed",
                stage="device_evidence",
                details={
                    "error_present": bool(raw_error),
                    "final_status": status or "unknown",
                },
            )
            external = _external_record(
                request_id=request_id,
                system="netmiko_mcp",
                operation="execute_readonly_command",
                status=ExternalCallStatus.FAILED,
                started_at=started_at,
                finished_at=finished_at,
                request_ref=request_ref,
                response_ref=response_ref,
                error=error,
            )
            envelope = EvidenceEnvelope(
                schema_version="v12.1",
                request_id=request_id,
                source=EvidenceSource.DEVICE,
                evidence_kind="evidence",
                status=EvidenceStatus.FAILED,
                summary="Netmiko MCP read-only command failed.",
                facts={
                    "netmiko_mcp_called": True,
                    "command_sha256": hashlib.sha256(
                        command.encode("utf-8")
                    ).hexdigest(),
                    "write_command_executed": False,
                    "raw_output_forwarded": False,
                },
                scope=dict(sample.target_scope),
                errors=[error],
                collected_at=finished_at,
                reason="netmiko_mcp_command_failed",
            )
            return AgentOutcome(
                status=AgentStatus.FAILED,
                output_refs=(response_ref,),
                output={
                    "device_evidence": envelope.model_dump(
                        mode="json"
                    ),
                    "netmiko_mcp_called": True,
                    "command_generation_performed": False,
                    "write_command_executed": False,
                    "raw_output_forwarded": False,
                    "safety_policy_bypassed": False,
                },
                errors=(error,),
                external_calls=(external,),
            )

        evidence_status = (
            EvidenceStatus.SUCCESS
            if status == "completed"
            else EvidenceStatus.PARTIAL
        )
        agent_status = (
            AgentStatus.SUCCESS
            if status == "completed"
            else AgentStatus.PARTIAL
        )
        external = _external_record(
            request_id=request_id,
            system="netmiko_mcp",
            operation="execute_readonly_command",
            status=ExternalCallStatus.SUCCESS,
            started_at=started_at,
            finished_at=finished_at,
            request_ref=request_ref,
            response_ref=response_ref,
        )
        envelope = EvidenceEnvelope(
            schema_version="v12.1",
            request_id=request_id,
            source=EvidenceSource.DEVICE,
            evidence_kind="evidence",
            status=evidence_status,
            summary=(
                "Netmiko MCP completed one existing read-only "
                "Playbook command."
            ),
            facts={
                "netmiko_mcp_called": True,
                "command_sha256": hashlib.sha256(
                    command.encode("utf-8")
                ).hexdigest(),
                "command_prefix": command.split(" ", 1)[0].lower(),
                "output_size_bytes": len(
                    raw_output.encode("utf-8")
                ),
                "judge": sanitize_sensitive_data(judge),
                "write_command_executed": False,
                "raw_output_forwarded": False,
            },
            scope=dict(sample.target_scope),
            evidence_refs=[evidence_ref],
            collected_at=finished_at,
        )
        return AgentOutcome(
            status=agent_status,
            output_refs=(response_ref, evidence_ref),
            output={
                "device_evidence": envelope.model_dump(mode="json"),
                "netmiko_mcp_called": True,
                "command_generation_performed": False,
                "write_command_executed": False,
                "raw_output_forwarded": False,
                "safety_policy_bypassed": False,
            },
            external_calls=(external,),
        )


def _compact_rca_prompt(
    *,
    event: Mapping[str, Any],
    bundle: Mapping[str, Any],
    judge: Mapping[str, Any],
) -> str:
    evidence = _mapping(bundle.get("evidence"))
    compact_evidence: dict[str, Any] = {}
    for source in ("metrics", "device", "logs"):
        envelope = _mapping(evidence.get(source))
        compact_evidence[source] = {
            "status": envelope.get("status"),
            "summary": envelope.get("summary"),
            "facts": envelope.get("facts"),
            "scope": envelope.get("scope"),
            "reason": envelope.get("reason"),
            "evidence_refs": envelope.get("evidence_refs") or [],
        }

    allowed_refs = sorted(
        set(
            ref
            for source in ("metrics", "device", "logs")
            for ref in (
                _mapping(evidence.get(source)).get(
                    "evidence_refs"
                )
                or []
            )
        )
        & set(judge.get("evidence_refs") or [])
    )
    missing = [
        _text(item)
        for item in (
            (judge.get("missing_required_sources") or [])
            + (judge.get("missing_optional_sources") or [])
        )
        if _text(item)
    ]
    cap = float(judge.get("confidence_cap") or 0.0)
    if not allowed_refs:
        raise P2RealCanaryError(
            "RCA prompt has no Judge-approved evidence_ref"
        )
    skeleton = {
        "candidates": [
            {
                "statement": "请基于所引用证据给出一个候选根因。",
                "confidence": min(0.6, cap),
                "supporting_evidence_refs": [allowed_refs[0]],
                "contradicting_evidence_refs": [],
                "missing_evidence": missing,
                "uncertainties": [
                    "结论受当前缺失证据限制。"
                ],
                "scope": {
                    "device": _mapping(event.get("device")),
                    "alert_object": _mapping(
                        event.get("alert_object")
                    ),
                },
            }
        ],
        "missing_evidence": missing,
        "uncertainties": [
            "必须仅依据给定证据，不能自动补查。"
        ],
    }

    return (
        "你是受控网络运维 RCA Agent。只能依据下方结构化证据输出，"
        "不得调用工具，不得补查，不得声称日志正常，不得虚构命令执行。"
        "请只输出一个 JSON 对象，不要代码围栏和解释。\n"
        "JSON 顶层必须精确包含 candidates、missing_evidence、"
        "uncertainties。candidates 为 1 至 3 项；每项必须包含 "
        "statement、confidence、supporting_evidence_refs、"
        "contradicting_evidence_refs、missing_evidence、uncertainties、"
        "scope。supporting_evidence_refs 只能从 allowed_evidence_refs "
        "选择且至少一个。每项 confidence 不得超过 confidence_cap。"
        "missing_evidence 必须完整继承 required_missing_evidence。"
        "uncertainties 不能为空。\n"
        f"confidence_cap={cap}\n"
        "allowed_evidence_refs="
        + stable_json_dumps(allowed_refs)
        + "\nrequired_missing_evidence="
        + stable_json_dumps(missing)
        + "\nevent="
        + stable_json_dumps(
            {
                "alert_name": event.get("alert_name"),
                "family": event.get("family"),
                "device": event.get("device"),
                "alert_object": event.get("alert_object"),
                "labels": event.get("labels"),
                "annotations": event.get("annotations"),
            }
        )
        + "\nevidence="
        + stable_json_dumps(compact_evidence)
        + "\noutput_skeleton="
        + stable_json_dumps(skeleton)
        + "\njudge="
        + stable_json_dumps(
            {
                "status": judge.get("status"),
                "rca_allowed": judge.get("rca_allowed"),
                "confidence_cap": cap,
                "missing_required_sources": (
                    judge.get("missing_required_sources") or []
                ),
                "missing_optional_sources": (
                    judge.get("missing_optional_sources") or []
                ),
                "evidence_refs": judge.get("evidence_refs") or [],
                "conflicts": judge.get("conflicts") or [],
            }
        )
    )


def _one_call_llm_config(
    production_config: Mapping[str, Any],
    timeout_seconds: int,
) -> dict[str, Any]:
    raw = dict(_mapping(production_config.get("llm")))
    if not bool(raw.get("enabled", False)):
        raise P2RealCanaryError(
            "production llm.enabled is not true"
        )
    if _text(raw.get("provider")) != "openai_compatible":
        raise P2RealCanaryError(
            "production LLM provider is not openai_compatible"
        )
    if _text(raw.get("model")) != "glm-5.2":
        raise P2RealCanaryError(
            "production LLM model is not glm-5.2"
        )

    endpoints = raw.get("endpoints") or raw.get("base_urls") or []
    if isinstance(endpoints, (str, Mapping)):
        endpoints = [endpoints]
    if endpoints:
        raw["endpoints"] = [endpoints[0]]
        raw.pop("base_urls", None)
        first = endpoints[0]
        if isinstance(first, Mapping):
            raw["base_url"] = _text(
                first.get("base_url") or first.get("url")
            )
        else:
            raw["base_url"] = _text(first)
    if not _text(raw.get("base_url")):
        raise P2RealCanaryError(
            "production LLM endpoint is empty"
        )

    raw["retry"] = 0
    raw["retries"] = 0
    raw["timeout"] = min(
        int(timeout_seconds),
        int(raw.get("timeout") or timeout_seconds),
    )
    raw["read_timeout"] = raw["timeout"]
    raw["temperature"] = 0
    raw["max_tokens"] = max(
        1200,
        min(2400, int(raw.get("max_tokens") or 1200)),
    )
    return {"llm": raw}


def _llm_required_env_names(
    config: Mapping[str, Any],
) -> set[str]:
    llm = _mapping(config.get("llm"))
    names: set[str] = set()
    global_name = _text(llm.get("api_key_env"))
    if global_name:
        names.add(global_name)
    endpoints = llm.get("endpoints") or llm.get("base_urls") or []
    if isinstance(endpoints, (str, Mapping)):
        endpoints = [endpoints]
    for endpoint in endpoints:
        if not isinstance(endpoint, Mapping):
            continue
        name = _text(endpoint.get("api_key_env"))
        if name:
            names.add(name)
    return names


class RealGLMRCACollector:
    def __init__(
        self,
        *,
        production_config: Mapping[str, Any],
    ) -> None:
        self.production_config = dict(production_config)

    async def collect(
        self,
        *,
        request_id: str,
        outputs: Mapping[str, Mapping[str, Any]],
        output_refs: tuple[str, ...],
        settings: P2Settings,
        ledger: P2CallLedger,
    ) -> AgentOutcome:
        event = _mapping(
            _mapping(outputs.get(AgentName.TRIAGE.value)).get(
                "unified_event"
            )
        )
        bundle = _mapping(
            _mapping(outputs.get("evidence_bundle")).get(
                "evidence_bundle"
            )
        )
        judge = _mapping(
            _mapping(
                outputs.get(AgentName.EVIDENCE_JUDGE.value)
            ).get("judge_result")
        )
        if not event or not bundle or not judge:
            raise P2RealCanaryError(
                "RCA input contracts are missing"
            )
        if judge.get("rca_allowed") is not True:
            raise P2RealCanaryError(
                "Judge did not allow real RCA generation"
            )
        if _text(judge.get("status")) in {
            JudgeStatus.INSUFFICIENT.value,
            JudgeStatus.BLOCKED.value,
        }:
            raise P2RealCanaryError(
                "insufficient or blocked evidence cannot call GLM"
            )

        bundle_ref = _one_ref(
            output_refs,
            "artifact",
            "evidence_bundle",
        )
        judge_ref = _one_ref(
            output_refs,
            "artifact",
            "judge_result",
        )
        event_ref = _one_ref(
            output_refs,
            "event",
            None,
        )
        prompt = _compact_rca_prompt(
            event=event,
            bundle=bundle,
            judge=judge,
        )

        ledger.reserve(
            P2CallKind.RCA,
            operation_id=(
                "glm-rca:"
                + hashlib.sha256(
                    prompt.encode("utf-8")
                ).hexdigest()[:16]
            ),
            provider="glm-5.2",
        )
        config = _one_call_llm_config(
            self.production_config,
            settings.rca_timeout_seconds,
        )
        request_ref = build_contract_ref(
            "artifact",
            request_id,
            "external_request",
            "glm-rca-request",
        )
        started_at = _aware_now()
        env_names = _llm_required_env_names(
            self.production_config
        )
        service_env = _systemd_service_environment(env_names)
        old_env = {
            name: os.environ.get(name)
            for name in env_names
        }
        try:
            for name in env_names:
                if not os.environ.get(name) and service_env.get(name):
                    os.environ[name] = service_env[name]
            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(
                None,
                lambda: call_llm(prompt, config=config),
            )
        finally:
            for name, value in old_env.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
        finished_at = _aware_now()

        metadata = _mapping(response.get("llm_metadata"))
        if (
            _text(metadata.get("call_status")) != "success"
            or _text(metadata.get("parse_status")) != "ok"
            or int(metadata.get("total_attempts") or 0) != 1
        ):
            error = _notice(
                "p2_glm_rca_failed",
                "GLM 5.2 did not return valid structured JSON",
                stage="rca",
                details={
                    "call_status": metadata.get("call_status"),
                    "parse_status": metadata.get("parse_status"),
                    "total_attempts": metadata.get("total_attempts"),
                },
            )
            external = _external_record(
                request_id=request_id,
                system="glm_5_2",
                operation="generate_evidence_grounded_rca",
                status=ExternalCallStatus.FAILED,
                started_at=started_at,
                finished_at=finished_at,
                request_ref=request_ref,
                response_ref=None,
                error=error,
            )
            return AgentOutcome(
                status=AgentStatus.FAILED,
                output={
                    "production_glm_called": True,
                    "mcp_called": False,
                    "tool_called": False,
                    "automatic_followup_queries": False,
                },
                errors=(error,),
                external_calls=(external,),
            )

        raw_analysis = response.get("analysis")
        if not isinstance(raw_analysis, Mapping):
            raise P2RealCanaryError(
                "GLM structured analysis root is not an object"
            )

        from .contracts import EvidenceBundle, EvidenceJudgeResult

        bundle_model = EvidenceBundle.model_validate(bundle)
        judge_model = EvidenceJudgeResult.model_validate(judge)
        provider = "production-glm-5.2"
        result = validate_rca_response(
            raw_analysis,
            bundle=bundle_model,
            judge=judge_model,
            event_ref=event_ref,
            bundle_ref=bundle_ref,
            judge_ref=judge_ref,
            generated_at=finished_at,
            provider=provider,
        )
        digest = hashlib.sha256(
            stable_json_dumps(
                result.model_dump(mode="json")
            ).encode("utf-8")
        ).hexdigest()[:24]
        response_ref = build_contract_ref(
            "artifact",
            request_id,
            "external_response",
            f"glm-rca-{digest}",
        )
        output_ref = build_contract_ref(
            "artifact",
            request_id,
            "rca_result",
            f"rca-{digest}",
        )
        external = _external_record(
            request_id=request_id,
            system="glm_5_2",
            operation="generate_evidence_grounded_rca",
            status=ExternalCallStatus.SUCCESS,
            started_at=started_at,
            finished_at=finished_at,
            request_ref=request_ref,
            response_ref=response_ref,
        )
        return AgentOutcome(
            status=result.status,
            output_refs=(output_ref, response_ref),
            output={
                "rca_result": result.model_dump(mode="json"),
                "prompt_version": "p2_real_rca_v1",
                "prompt_sha256": hashlib.sha256(
                    prompt.encode("utf-8")
                ).hexdigest(),
                "production_glm_called": True,
                "mcp_called": False,
                "tool_called": False,
                "automatic_followup_queries": False,
            },
            external_calls=(external,),
        )


def _one_ref(
    references: tuple[str, ...] | list[str],
    scheme: str,
    kind: str | None,
) -> str:
    matches: list[str] = []
    for reference in references:
        parsed = parse_contract_ref(reference)
        if parsed["scheme"] != scheme:
            continue
        if kind is not None and parsed["kind"] != kind:
            continue
        matches.append(reference)
    if len(matches) != 1:
        raise P2RealCanaryError(
            f"expected exactly one {scheme}/{kind or '*'} ref; "
            f"observed={len(matches)}"
        )
    return matches[0]


class P2RealCanaryRunner:
    def __init__(
        self,
        *,
        settings: P2Settings,
        sample: P2CanarySample,
        project_root: str | Path,
        trace_root: str | Path,
        governance_root: str | Path,
        work_root: str | Path,
        production_config: Mapping[str, Any],
        metrics_collector: MetricsCollector | None = None,
        device_collector: DeviceCollector | None = None,
        rca_collector: RCACollector | None = None,
    ) -> None:
        self.settings = settings
        self.sample = sample
        self.project_root = Path(project_root)
        self.trace_root = Path(trace_root)
        self.governance_root = Path(governance_root)
        self.work_root = Path(work_root)
        self.production_config = dict(production_config)
        self.metrics_collector = (
            metrics_collector
            or RealPrometheusCollector(
                project_root=self.project_root,
                work_root=self.work_root,
                production_config=self.production_config,
            )
        )
        self.device_collector = (
            device_collector
            or RealNetmikoCollector(
                project_root=self.project_root,
                production_config=self.production_config,
            )
        )
        self.rca_collector = (
            rca_collector
            or RealGLMRCACollector(
                production_config=self.production_config,
            )
        )

    async def run(self, request_id: str) -> dict[str, Any]:
        validate_request_id(request_id)
        self.settings.validate_frozen_boundary()
        decision = P2CanaryPolicy(self.settings).evaluate(
            request_id=request_id,
            family=self.sample.family,
            event_count=1,
            alert_status="firing",
        )
        if not decision.allowed:
            raise P2RealCanaryError(
                "P2 policy rejected the Canary: "
                + decision.reason
            )

        ledger = P2CallLedger(
            settings=self.settings,
            request_id=request_id,
            family=self.sample.family,
        )
        outputs: dict[str, Mapping[str, Any]] = {}
        output_refs: list[str] = []
        runs: list[AgentRunRecord] = []
        started_clock = time.monotonic()

        agents: dict[AgentName, Any] = {
            AgentName.TRIAGE: TriageAgent(
                source=self.sample.source,
                payload=self.sample.raw_payload,
                event_index=0,
                received_at=_aware_now(),
            ),
            AgentName.STATIC_PLANNER: StaticPlannerAgent(),
            AgentName.LOGS_EVIDENCE: LogsEvidenceAgent(),
            AgentName.KNOWLEDGE_CONTEXT: KnowledgeContextAgent(),
            AgentName.EVIDENCE_JUDGE: EvidenceJudgeAgent(),
            AgentName.NOTIFICATION_REPORT: NotificationReportAgent(),
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

        async def invoke(
            name: AgentName,
        ) -> AgentOutcome:
            invocation = AgentInvocation(
                request_id=request_id,
                agent_name=name,
                orchestration_state=states[name],
                prior_output_refs=tuple(output_refs),
                prior_outputs=dict(outputs),
            )
            started_at = _aware_now()
            started = time.monotonic()
            if name == AgentName.METRICS_EVIDENCE:
                coro = self.metrics_collector.collect(
                    request_id=request_id,
                    sample=self.sample,
                    settings=self.settings,
                    ledger=ledger,
                )
                timeout = self.settings.metrics_timeout_seconds + 5
            elif name == AgentName.DEVICE_EVIDENCE:
                coro = self.device_collector.collect(
                    request_id=request_id,
                    sample=self.sample,
                    settings=self.settings,
                    ledger=ledger,
                )
                timeout = self.settings.device_timeout_seconds + 5
            elif name == AgentName.RCA:
                coro = self.rca_collector.collect(
                    request_id=request_id,
                    outputs=dict(outputs),
                    output_refs=tuple(output_refs),
                    settings=self.settings,
                    ledger=ledger,
                )
                timeout = self.settings.rca_timeout_seconds + 5
            else:
                coro = agents[name].run(invocation)
                timeout = 15

            try:
                outcome = await asyncio.wait_for(
                    coro,
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                notice = _notice(
                    "p2_agent_timeout",
                    "P2 Agent exceeded its timeout",
                    stage=name.value,
                )
                outcome = AgentOutcome(
                    status=AgentStatus.FAILED,
                    errors=(notice,),
                )
            finished_at = _aware_now()

            record = AgentRunRecord(
                schema_version="v12.1",
                request_id=request_id,
                agent_name=name,
                status=outcome.status,
                started_at=started_at,
                finished_at=finished_at,
                duration_ms=max(
                    0,
                    int((time.monotonic() - started) * 1000),
                ),
                inputs_ref=list(invocation.prior_output_refs),
                outputs_ref=list(outcome.output_refs),
                warnings=list(outcome.warnings),
                errors=list(outcome.errors),
                external_calls=list(outcome.external_calls),
            )
            runs.append(record)
            outputs[name.value] = dict(outcome.output)
            output_refs.extend(outcome.output_refs)
            return outcome

        triage = await invoke(AgentName.TRIAGE)
        if triage.status == AgentStatus.FAILED:
            raise P2RealCanaryError("P2 Triage failed")

        planner = await invoke(AgentName.STATIC_PLANNER)
        if planner.status == AgentStatus.FAILED:
            raise P2RealCanaryError("P2 Static Planner failed")
        planned_family = _text(
            _mapping(planner.output).get("family")
        )
        if planned_family != self.sample.family:
            raise P2RealCanaryError(
                "P2 planned Family drifted from discovery"
            )

        metrics = await invoke(AgentName.METRICS_EVIDENCE)
        if metrics.status == AgentStatus.FAILED:
            raise P2RealCanaryError(
                "P2 real Prometheus Agent failed"
            )

        device = await invoke(AgentName.DEVICE_EVIDENCE)
        if device.status == AgentStatus.FAILED:
            raise P2RealCanaryError(
                "P2 real Device Agent failed"
            )

        logs = await invoke(AgentName.LOGS_EVIDENCE)
        knowledge = await invoke(AgentName.KNOWLEDGE_CONTEXT)
        if (
            logs.status != AgentStatus.NOT_AVAILABLE
            or knowledge.status != AgentStatus.NOT_AVAILABLE
        ):
            raise P2RealCanaryError(
                "P2 Logs/Knowledge boundary drifted"
            )

        partial = OrchestrationResult(
            request_id=request_id,
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
                int((time.monotonic() - started_clock) * 1000),
            ),
        )
        artifacts = EvidenceBundleBuilder().build(partial)
        bundle_ref = build_contract_ref(
            "artifact",
            request_id,
            "evidence_bundle",
            "bundle-p2",
        )
        outputs["evidence_bundle"] = {
            "evidence_bundle": (
                artifacts.evidence_bundle.model_dump(mode="json")
            )
        }
        output_refs.append(bundle_ref)

        judge = await invoke(AgentName.EVIDENCE_JUDGE)
        if judge.status == AgentStatus.FAILED:
            raise P2RealCanaryError("P2 Judge failed")
        judge_payload = _mapping(judge.output).get(
            "judge_result"
        )
        if not isinstance(judge_payload, Mapping):
            raise P2RealCanaryError(
                "P2 Judge contract is missing"
            )
        if (
            judge_payload.get("rca_allowed") is not True
            or _text(judge_payload.get("status"))
            in {
                JudgeStatus.INSUFFICIENT.value,
                JudgeStatus.BLOCKED.value,
            }
        ):
            raise P2RealCanaryError(
                "P2 evidence did not permit real RCA"
            )

        rca = await invoke(AgentName.RCA)
        if rca.status not in {
            AgentStatus.SUCCESS,
            AgentStatus.PARTIAL,
        }:
            raise P2RealCanaryError(
                "P2 real GLM RCA failed"
            )

        report = await invoke(AgentName.NOTIFICATION_REPORT)
        if report.status == AgentStatus.FAILED:
            raise P2RealCanaryError("P2 Report failed")
        notification_plan = _mapping(report.output).get(
            "notification_plan"
        )
        if not isinstance(notification_plan, Mapping):
            raise P2RealCanaryError(
                "P2 notification plan is missing"
            )
        if (
            notification_plan.get("send_notification") is not False
            or int(
                notification_plan.get(
                    "notification_count",
                    -1,
                )
            )
            != 0
            or notification_plan.get("second_card_sent")
            is not False
            or notification_plan.get("production_card_replaced")
            is not False
        ):
            raise P2RealCanaryError(
                "P2 notification boundary drifted"
            )

        ledger_snapshot = ledger.snapshot()
        call_counts = ledger_snapshot["call_counts"]
        if ledger_snapshot["total_calls"] != 3:
            raise P2RealCanaryError(
                "P2 total external call count is not three"
            )
        for kind in EXPECTED_CALL_KINDS:
            if int(call_counts.get(kind.value, 0)) != 1:
                raise P2RealCanaryError(
                    f"P2 call count mismatch: {kind.value}"
                )

        final = OrchestrationResult(
            request_id=request_id,
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
                int((time.monotonic() - started_clock) * 1000),
            ),
        )
        stored = AgentTraceStore(self.trace_root).persist(
            final,
            BundleArtifacts(
                unified_event=artifacts.unified_event,
                evidence_plan=artifacts.evidence_plan,
                evidence_bundle=artifacts.evidence_bundle,
            ),
        )
        writer = AtomicJsonWriter(stored.directory)
        rca_payload = _mapping(rca.output).get("rca_result")
        report_payload = dict(report.output)
        if not all(
            isinstance(item, Mapping)
            for item in (
                judge_payload,
                rca_payload,
                report_payload.get("report_artifact"),
            )
        ):
            raise P2RealCanaryError(
                "P2 supplemental trace contract is missing"
            )

        public_sample = self.sample.public_dict()
        canary_payload = {
            "schema_version": P2_REAL_SCHEMA_VERSION,
            "request_id": request_id,
            "status": "completed",
            "activation_id": self.settings.activation_id,
            "family": self.sample.family,
            "sample": public_sample,
            "call_ledger": ledger_snapshot,
            "judge_status": judge_payload.get("status"),
            "rca_status": rca_payload.get("status"),
            "notification_sent": False,
            "notification_count": 0,
            "second_card_sent": False,
            "production_card_replaced": False,
            "prometheus_mcp_called": True,
            "netmiko_mcp_called": True,
            "production_glm_called": True,
            "evidence_mcp_called": False,
            "ops_es_api_called": False,
            "analytics_mcp_called": False,
            "fastmcp_called": False,
            "elasticsearch_called": False,
            "write_command_executed": False,
            "command_generation_performed": False,
            "promql_generation_performed": False,
            "dsl_generation_performed": False,
            "automatic_followup_queries": False,
            "trace_written": True,
            "report_generated": True,
            "completed_at": _aware_now().isoformat(),
        }
        writer.write_many(
            {
                "judge_result.json": {
                    "schema_version": "v12.1",
                    "request_id": request_id,
                    "judge_result": judge_payload,
                },
                "rca_result.json": {
                    "schema_version": "v12.1",
                    "request_id": request_id,
                    "rca_result": rca_payload,
                },
                "report.json": {
                    "schema_version": "v12.1",
                    "request_id": request_id,
                    **report_payload,
                },
                "shadow_integration.json": {
                    "schema_version": P2_REAL_SCHEMA_VERSION,
                    "request_id": request_id,
                    "status": "completed",
                    "mode": "manual_controlled_shadow_canary",
                    "legacy_preserved": True,
                    "notification_sent": False,
                    "trace_written": True,
                },
                "p2_canary.json": canary_payload,
            }
        )
        governance = AgentTraceGovernanceAdapter(
            trace_service=AgentTraceReadService(
                self.trace_root
            ),
            governance_root=self.governance_root,
        ).persist_for_request_safe(request_id)
        if governance.get("ok") is not True:
            raise P2RealCanaryError(
                "P2 isolated Governance persistence failed"
            )

        actual_files = {
            path.name
            for path in stored.directory.glob("*.json")
            if path.is_file()
        }
        missing_files = sorted(EXPECTED_TRACE_FILES - actual_files)
        if missing_files:
            raise P2RealCanaryError(
                "P2 trace is incomplete: "
                + ", ".join(missing_files)
            )

        return {
            "schema_version": P2_REAL_SCHEMA_VERSION,
            "status": "completed",
            "request_id": request_id,
            "family": self.sample.family,
            "sample": public_sample,
            "trace_dir": str(stored.directory),
            "governance_ok": True,
            "call_ledger": ledger_snapshot,
            "judge_status": judge_payload.get("status"),
            "rca_status": rca_payload.get("status"),
            "evidence_refs": sorted(
                set(
                    bundle_evidence_refs(
                        artifacts.evidence_bundle
                    )
                )
            ),
            "notification_sent": False,
            "second_card_sent": False,
            "production_card_replaced": False,
            "logs_status": logs.status.value,
            "knowledge_status": knowledge.status.value,
            "service_restart": False,
        }


def load_production_config(
    path: str | Path = DEFAULT_CONFIG_PATH,
) -> Mapping[str, Any]:
    value = Path(path)
    if value.is_symlink() or not value.is_file():
        raise P2RealCanaryError(
            "production config.yaml is unavailable"
        )
    try:
        config = yaml.safe_load(
            value.read_text(encoding="utf-8")
        ) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise P2RealCanaryError(
            "production config.yaml cannot be decoded"
        ) from exc
    if not isinstance(config, Mapping):
        raise P2RealCanaryError(
            "production config.yaml root is not an object"
        )
    return config


def run_real_canary(
    *,
    state_dir: str | Path,
    project_root: str | Path = DEFAULT_PROJECT_ROOT,
) -> dict[str, Any]:
    state = Path(state_dir)
    state.mkdir(parents=True, exist_ok=True)
    os.chmod(state, 0o700)
    sample_path = state / "discovery.json"
    if sample_path.is_file():
        discovery = _safe_json_read(sample_path)
        original_id = _text(
            _mapping(discovery.get("sample")).get(
                "original_request_id"
            )
        )
        sample = discover_real_canary_sample(
            project_root,
            preferred_request_id=original_id or None,
        )
        if (
            original_id
            and sample.original_request_id != original_id
        ):
            raise P2RealCanaryError(
                "pinned discovery sample could not be reloaded"
            )
    else:
        sample = discover_real_canary_sample(project_root)

    activation_id = (
        "p2-"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + hashlib.sha256(
            sample.original_request_id.encode("utf-8")
        ).hexdigest()[:8]
    )
    request_id = (
        "p2-canary-"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + hashlib.sha256(
            (
                activation_id
                + sample.original_request_id
            ).encode("utf-8")
        ).hexdigest()[:10]
    )
    settings = build_active_p2_settings(activation_id)
    project = Path(project_root)
    workspace = state / "workspace"
    trace_root = (
        workspace
        / "data"
        / "evidence_hub"
        / "requests"
    )
    governance_root = (
        workspace
        / "data"
        / "governance"
        / "agent_traces"
    )
    production_config = load_production_config(
        project / "config.yaml"
    )
    runner = P2RealCanaryRunner(
        settings=settings,
        sample=sample,
        project_root=project,
        trace_root=trace_root,
        governance_root=governance_root,
        work_root=workspace,
        production_config=production_config,
    )
    try:
        result = asyncio.run(runner.run(request_id))
    except Exception as exc:
        failure = {
            "schema_version": P2_REAL_SCHEMA_VERSION,
            "status": "failed",
            "request_id": request_id,
            "activation_id": activation_id,
            "sample": sample.public_dict(),
            "error_type": type(exc).__name__,
            "error": str(exc),
            "traceback": traceback.format_exc(),
            "notification_sent": False,
            "evidence_mcp_called": False,
            "analytics_mcp_called": False,
            "fastmcp_called": False,
            "elasticsearch_called": False,
            "write_command_executed": False,
            "service_restart": False,
            "failed_at": _aware_now().isoformat(),
        }
        (state / "P2_FAILURE_REPORT.json").write_text(
            json.dumps(
                sanitize_sensitive_data(failure),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        raise

    (state / "real_canary_result.json").write_text(
        json.dumps(
            sanitize_sensitive_data(result),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return result


def discovery_report(
    *,
    state_dir: str | Path,
    project_root: str | Path = DEFAULT_PROJECT_ROOT,
) -> dict[str, Any]:
    state = Path(state_dir)
    state.mkdir(parents=True, exist_ok=True)
    os.chmod(state, 0o700)
    sample = discover_real_canary_sample(project_root)
    report = {
        "schema_version": P2_REAL_SCHEMA_VERSION,
        "status": "pass",
        "sample": sample.public_dict(),
        "external_calls": {
            "prometheus_mcp": False,
            "netmiko_mcp": False,
            "glm_5_2": False,
            "evidence_mcp": False,
            "analytics_mcp": False,
            "fastmcp": False,
        },
        "notification_sent": False,
        "created_at": _aware_now().isoformat(),
    }
    (state / "discovery.json").write_text(
        json.dumps(
            report,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return report


def evaluate_real_canary_gate(
    *,
    state_dir: str | Path,
    project_root: str | Path = DEFAULT_PROJECT_ROOT,
) -> dict[str, Any]:
    state = Path(state_dir)
    result = _safe_json_read(
        state / "real_canary_result.json"
    )
    violations: list[str] = []

    if result.get("status") != "completed":
        violations.append("canary_not_completed")
    ledger = _mapping(result.get("call_ledger"))
    counts = _mapping(ledger.get("call_counts"))
    if int(ledger.get("total_calls") or -1) != 3:
        violations.append("total_external_call_count_not_three")
    for kind in EXPECTED_CALL_KINDS:
        if int(counts.get(kind.value) or 0) != 1:
            violations.append(
                f"{kind.value}_call_count_not_one"
            )
    if result.get("notification_sent") is not False:
        violations.append("notification_sent")
    if result.get("second_card_sent") is not False:
        violations.append("second_card_sent")
    if result.get("production_card_replaced") is not False:
        violations.append("production_card_replaced")
    if result.get("logs_status") != "not_available":
        violations.append("logs_agent_not_placeholder")
    if result.get("knowledge_status") != "not_available":
        violations.append("knowledge_agent_not_placeholder")
    if _text(result.get("judge_status")) not in {
        "ready",
        "partial",
    }:
        violations.append("judge_did_not_allow_rca")
    if _text(result.get("rca_status")) not in {
        "success",
        "partial",
    }:
        violations.append("real_rca_not_successful")

    trace_dir = Path(_text(result.get("trace_dir")))
    if not trace_dir.is_dir():
        violations.append("trace_directory_missing")
    else:
        actual = {
            path.name
            for path in trace_dir.glob("*.json")
            if path.is_file()
        }
        for name in sorted(EXPECTED_TRACE_FILES - actual):
            violations.append(f"trace_missing:{name}")

    request_id = _text(result.get("request_id"))
    if request_id:
        production_root = Path(project_root) / "data"
        leaked = [
            str(path)
            for path in production_root.rglob(
                f"*{request_id}*"
            )
            if path.is_file()
        ]
        if leaked:
            violations.append(
                "canary_artifact_leaked_to_production_data"
            )

    gate = {
        "schema_version": P2_REAL_SCHEMA_VERSION,
        "status": "passed" if not violations else "failed",
        "request_id": request_id,
        "violation_count": len(violations),
        "violations": violations,
        "call_counts": dict(counts),
        "total_calls": ledger.get("total_calls"),
        "notification_sent": result.get(
            "notification_sent"
        ),
        "service_restart": False,
        "evaluated_at": _aware_now().isoformat(),
    }
    (state / "gate.json").write_text(
        json.dumps(
            gate,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return gate


def validate_mock_rca_fixture(
    *,
    request_id: str,
    evidence_ref: str,
    confidence_cap: float = 0.85,
) -> Mapping[str, Any]:
    """Small deterministic fixture used by P2 fault-injection tests."""
    if not 0.0 <= confidence_cap <= 1.0:
        raise P2RealCanaryError("confidence cap is invalid")
    parsed = parse_contract_ref(evidence_ref)
    if (
        parsed["scheme"] != "evidence"
        or parsed["request_id"] != request_id
    ):
        raise P2RealCanaryError(
            "mock RCA evidence_ref is invalid"
        )
    return {
        "candidates": [
            {
                "statement": (
                    "The observed interface evidence is consistent "
                    "with the alert condition."
                ),
                "confidence": min(0.7, confidence_cap),
                "supporting_evidence_refs": [evidence_ref],
                "contradicting_evidence_refs": [],
                "missing_evidence": ["logs", "knowledge"],
                "uncertainties": [
                    "Logs and knowledge context remain unavailable."
                ],
                "scope": {"mode": "mock-contract-only"},
            }
        ],
        "missing_evidence": ["logs", "knowledge"],
        "uncertainties": [
            "This fixture validates only the frozen RCA schema."
        ],
    }
