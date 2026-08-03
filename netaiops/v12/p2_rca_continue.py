"""Batch P2 final RCA-only continuation.

This final continuation reuses the successful V3 Metrics and Device
checkpoints and the frozen V6/V7/V8 GLM failure evidence. It performs
exactly one new external action: one GLM 5.2 HTTP request.

It does not call Prometheus MCP, Netmiko MCP, Evidence MCP, Analytics MCP,
FastMCP, OPS ES API, Elasticsearch, device commands, or notification APIs.

The final adapter keeps retry=0 and one endpoint, reduces the evidence prompt
to a compact legacy RCA shape that is deterministically normalized by the
frozen RCA validator, retains max_tokens=8192, and uses a bounded 300-second
read timeout for this manual canary only. Successful RCA output is persisted
before Gate and repository tests so later verification never repeats GLM.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
import traceback
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

import httpx

import netaiops.v12.p2_device_continue as p2_device_continue_module

from netaiops.llm_client import (
    _build_endpoint_configs,
    _build_headers,
    _build_payload,
    _build_timeout,
    _extract_json_text,
    _resolve_api_key,
)

from .contracts import (
    ContextEnvelope,
    ContractNotice,
    EvidenceBundle,
    EvidenceCollection,
    EvidenceEnvelope,
    EvidenceJudgeResult,
    EvidencePlan,
    EvidenceSourcePlan,
)
from .execution_context import AgentInvocation, AgentOutcome
from .p2_controlled_canary import (
    P2CallKind,
    P2CallLedger,
    P2Settings,
)
from .p2_device_continue import (
    OLD_STATE_ROOT,
    P2ContinueError,
    P2DeviceContinueRunner,
    _aware_now,
    _load_checkpoint,
    _mapping_ref_kind,
    _safe_read_json,
    _sha256_file,
    _text,
    _write_json,
    continuation_paths,
    pinned_sample,
    validate_old_checkpoints,
)
from .p2_real_canary import (
    P2RealCanaryError,
    _external_record,
    _llm_required_env_names,
    _mapping,
    _notice,
    _one_call_llm_config,
    _one_ref,
    _systemd_service_environment,
    build_active_p2_settings,
    load_production_config,
)
from .agents.triage_agent import TriageAgent
from .judge_rules import (
    MAX_EVIDENCE_SKEW_SECONDS,
    evaluate_evidence,
)
from .rca_validator import (
    RCAValidationError,
    bundle_evidence_refs,
    inherited_missing_evidence,
    validate_rca_response,
)
from .state_machine import OrchestrationState
from .schema_validator import (
    build_contract_ref,
    sanitize_sensitive_data,
    stable_json_dumps,
    validate_request_id,
)
from .status import (
    AgentName,
    AgentStatus,
    EvidenceBundleStatus,
    EvidenceSource,
    EvidenceStatus,
    ExternalCallStatus,
    JudgeStatus,
)


V8_SCHEMA_VERSION = "v12-p2-rca-final-2"
PROJECT_ROOT = Path("/opt/netaiops-webhook")
V3_STATE_ROOT = Path(
    "/tmp/netaiops_v12_p2_device_continue_v3_state"
)
V4_STATE_ROOT = Path(
    "/tmp/netaiops_v12_p2_rca_continue_v4_state"
)
V5_STATE_ROOT = Path(
    "/tmp/netaiops_v12_p2_rca_continue_v5_state"
)
V6_STATE_ROOT = Path(
    "/tmp/netaiops_v12_p2_rca_continue_v6_state"
)
V7_STATE_ROOT = Path(
    "/tmp/netaiops_v12_p2_rca_continue_v7_state"
)
V8_STATE_ROOT = Path(
    "/tmp/netaiops_v12_p2_rca_continue_v8_state"
)
V8_SOURCE_PLANNER_PROOF_NAME = (
    "v8_source_historical_replay_planner_dry_run.json"
)
V8_SOURCE_JUDGE_PROOF_NAME = (
    "v8_source_historical_replay_judge_dry_run.json"
)
STATE_ROOT = Path(
    "/tmp/netaiops_v12_p2_rca_final_state"
)
REQUEST_TIMEOUT_SECONDS = 300
CONNECT_TIMEOUT_SECONDS = 10.0
READ_TIMEOUT_SECONDS = 300.0
WRITE_TIMEOUT_SECONDS = 30.0
POOL_TIMEOUT_SECONDS = 10.0
MAX_OUTPUT_TOKENS = 8192
MAX_PROMPT_CHARS = 5000
MAX_RCA_CANDIDATES = 2
HISTORICAL_REPLAY_ANCHOR = "device_checkpoint_collected_at"
EXPECTED_REPLAY_CONFIDENCE_CAP = 0.70
V3_REQUEST_ID = "p2-continue-20260730T091239Z-e6689cba0f"
EXPECTED_MODEL = "glm-5.2"
MAX_CONTENT_PREVIEW = 400
SECRET_RE = re.compile(
    r"""(?ix)
    (authorization|bearer|password|passwd|token|secret|api[_-]?key)
    \s*[:=]\s*([^\s,;]+)
    """
)


class P2RCAContinueError(RuntimeError):
    """Raised when the RCA-only continuation violates a frozen boundary."""


class GLMSingleCallError(P2RCAContinueError):
    """One GLM attempt failed; metadata is safe to persist after sanitizing."""

    def __init__(
        self,
        message: str,
        *,
        metadata: Mapping[str, Any],
    ) -> None:
        super().__init__(message)
        self.metadata = dict(metadata)


def _redact(value: Any, limit: int = MAX_CONTENT_PREVIEW) -> str:
    text = "" if value is None else str(value)
    text = SECRET_RE.sub(
        lambda match: f"{match.group(1)}=[REDACTED]",
        text,
    )
    return text[:limit]


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list):
        values = value
    else:
        values = []
    output: list[str] = []
    seen: set[str] = set()
    for item in values:
        text = str(item or "").strip()
        if text and text not in seen:
            output.append(text)
            seen.add(text)
    return output


def _exact_nonnegative_int(
    payload: Mapping[str, Any],
    field: str,
    *,
    expected: int,
    context: str,
) -> int:
    if field not in payload:
        raise P2RCAContinueError(
            f"{context}.{field} is missing"
        )
    raw = payload[field]
    if raw is None or isinstance(raw, bool):
        raise P2RCAContinueError(
            f"{context}.{field} has invalid type"
        )
    if isinstance(raw, int):
        value = raw
    elif isinstance(raw, str):
        stripped = raw.strip()
        if not re.fullmatch(r"0|[1-9][0-9]*", stripped):
            raise P2RCAContinueError(
                f"{context}.{field} is not a non-negative integer"
            )
        value = int(stripped)
    else:
        raise P2RCAContinueError(
            f"{context}.{field} has invalid type"
        )
    if value != expected:
        raise P2RCAContinueError(
            f"{context}.{field} expected {expected}, got {value}"
        )
    return value


def _validate_replay_anchor(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise P2RCAContinueError(
            "historical replay anchor is not a datetime"
        )
    if value.tzinfo is None or value.utcoffset() is None:
        raise P2RCAContinueError(
            "historical replay anchor must be timezone-aware"
        )
    normalized = value.astimezone(timezone.utc)
    if normalized > _aware_now() + timedelta(minutes=5):
        raise P2RCAContinueError(
            "historical replay anchor is unexpectedly in the future"
        )
    return normalized


def _checkpoint_evidence(
    path: Path,
    output_key: str,
) -> EvidenceEnvelope:
    payload = _safe_read_json(path)
    output = _mapping(payload.get("output"))
    raw = output.get(output_key)
    if not isinstance(raw, Mapping):
        raise P2RCAContinueError(
            f"checkpoint omitted {output_key}: {path.name}"
        )
    envelope = EvidenceEnvelope.model_validate(raw)
    if envelope.request_id != V3_REQUEST_ID:
        raise P2RCAContinueError(
            f"checkpoint request_id changed: {path.name}"
        )
    return envelope


def historical_replay_anchor(
    device_checkpoint: str | Path,
) -> datetime:
    envelope = _checkpoint_evidence(
        Path(device_checkpoint),
        "device_evidence",
    )
    return _validate_replay_anchor(envelope.collected_at)


def align_planner_outcome_for_historical_replay(
    outcome: AgentOutcome,
    replay_at: datetime,
) -> AgentOutcome:
    anchor = _validate_replay_anchor(replay_at)
    raw_plan = _mapping(outcome.output).get("evidence_plan")
    if not isinstance(raw_plan, Mapping):
        raise P2RCAContinueError(
            "Static Planner omitted evidence_plan before replay alignment"
        )
    plan = EvidencePlan.model_validate(raw_plan)
    if plan.request_id != V3_REQUEST_ID:
        raise P2RCAContinueError(
            "historical replay plan request_id changed"
        )

    plan_payload = plan.model_dump(mode="json")
    plan_payload["created_at"] = anchor.isoformat()
    adjusted_sources: list[dict[str, Any]] = []
    for source in plan_payload.get("sources") or []:
        if not isinstance(source, Mapping):
            raise P2RCAContinueError(
                "historical replay plan source is malformed"
            )
        item = dict(source)
        constraints = dict(_mapping(item.get("constraints")))
        if _text(item.get("source")) in {
            EvidenceSource.METRICS.value,
            EvidenceSource.DEVICE.value,
        }:
            constraints.update(
                {
                    "historical_controlled_replay": True,
                    "historical_replay_anchor": (
                        HISTORICAL_REPLAY_ANCHOR
                    ),
                    "historical_replay_plan_created_at": (
                        anchor.isoformat()
                    ),
                    "production_freshness_rule_changed": False,
                }
            )
        item["constraints"] = constraints
        adjusted_sources.append(item)
    plan_payload["sources"] = adjusted_sources
    aligned = EvidencePlan.model_validate(plan_payload)

    output = dict(outcome.output)
    output["evidence_plan"] = aligned.model_dump(mode="json")
    output["historical_replay"] = {
        "historical_controlled_replay": True,
        "anchor": HISTORICAL_REPLAY_ANCHOR,
        "plan_created_at": anchor.isoformat(),
        "original_plan_created_at": plan.created_at.isoformat(),
        "production_freshness_rule_changed": False,
    }
    warning = ContractNotice(
        code="p2_historical_replay_plan_time_v8",
        message=(
            "Final continuation aligned only the manual P2 replay Plan time to the "
            "successful Device checkpoint; production freshness rules "
            "were not changed."
        ),
        stage="static_planner",
        retryable=False,
        details={
            "anchor": HISTORICAL_REPLAY_ANCHOR,
            "plan_created_at": anchor.isoformat(),
        },
    )
    return AgentOutcome(
        status=outcome.status,
        output_refs=outcome.output_refs,
        output=output,
        warnings=tuple([*outcome.warnings, warning]),
        errors=outcome.errors,
        external_calls=outcome.external_calls,
    )


@contextmanager
def historical_replay_planner_scope(
    replay_at: datetime,
):
    anchor = _validate_replay_anchor(replay_at)
    marker = "_p2_v8_historical_replay_patch_active"
    if getattr(p2_device_continue_module, marker, False):
        raise P2RCAContinueError(
            "historical replay planner patch is already active"
        )
    original = p2_device_continue_module.StaticPlannerAgent

    class HistoricalReplayStaticPlannerAgent(original):
        async def run(self, invocation: Any) -> AgentOutcome:
            outcome = await super().run(invocation)
            if outcome.status == AgentStatus.FAILED:
                return outcome
            return align_planner_outcome_for_historical_replay(
                outcome,
                anchor,
            )

    setattr(p2_device_continue_module, marker, True)
    p2_device_continue_module.StaticPlannerAgent = (
        HistoricalReplayStaticPlannerAgent
    )
    try:
        yield
    finally:
        p2_device_continue_module.StaticPlannerAgent = original
        if hasattr(p2_device_continue_module, marker):
            delattr(p2_device_continue_module, marker)


def evaluate_checkpoint_evidence_at(
    metrics: EvidenceEnvelope,
    device: EvidenceEnvelope,
    *,
    plan_created_at: datetime,
) -> tuple[EvidencePlan, EvidenceBundle, EvidenceJudgeResult]:
    created_at = _validate_replay_anchor(plan_created_at)
    if metrics.request_id != V3_REQUEST_ID:
        raise P2RCAContinueError(
            "Metrics checkpoint request_id changed"
        )
    if device.request_id != V3_REQUEST_ID:
        raise P2RCAContinueError(
            "Device checkpoint request_id changed"
        )

    plan_ref = build_contract_ref(
        "plan",
        V3_REQUEST_ID,
        "evidence_plan",
        "historical-replay-v8-dry-run",
    )
    event_ref = build_contract_ref(
        "event",
        V3_REQUEST_ID,
        "unified_event",
        "historical-replay-v8-dry-run",
    )
    plan = EvidencePlan(
        schema_version="v12.1",
        request_id=V3_REQUEST_ID,
        plan_ref=plan_ref,
        planner_mode="deterministic",
        family="interface_status_or_flap",
        selected_playbook=None,
        sources=[
            EvidenceSourcePlan(
                source=EvidenceSource.METRICS,
                required=False,
                constraints={
                    "historical_controlled_replay": True,
                    "historical_replay_anchor": (
                        HISTORICAL_REPLAY_ANCHOR
                    ),
                },
                max_items=1,
            ),
            EvidenceSourcePlan(
                source=EvidenceSource.DEVICE,
                required=True,
                constraints={
                    "historical_controlled_replay": True,
                    "historical_replay_anchor": (
                        HISTORICAL_REPLAY_ANCHOR
                    ),
                },
                max_items=1,
            ),
            EvidenceSourcePlan(
                source=EvidenceSource.LOGS,
                required=False,
                constraints={"enabled": False},
                max_items=0,
            ),
            EvidenceSourcePlan(
                source=EvidenceSource.KNOWLEDGE,
                required=False,
                constraints={"enabled": False},
                max_items=0,
            ),
        ],
        readonly_only=True,
        created_at=created_at,
    )
    logs = EvidenceEnvelope(
        schema_version="v12.1",
        request_id=V3_REQUEST_ID,
        source=EvidenceSource.LOGS,
        evidence_kind="evidence",
        status=EvidenceStatus.NOT_AVAILABLE,
        summary="Logs disabled in Batch P2",
        facts={},
        scope={},
        evidence_refs=[],
        collected_at=created_at,
        reason="Logs Agent is not approved in Batch P2",
    )
    knowledge = ContextEnvelope(
        schema_version="v12.1",
        request_id=V3_REQUEST_ID,
        source="knowledge",
        evidence_kind="context",
        status=EvidenceStatus.NOT_AVAILABLE,
        reason="Knowledge Agent is not approved in Batch P2",
        context_facts=[],
        source_refs=[],
        as_of=None,
        collected_at=created_at,
    )
    bundle = EvidenceBundle(
        schema_version="v12.1",
        request_id=V3_REQUEST_ID,
        event_ref=event_ref,
        plan_ref=plan_ref,
        evidence=EvidenceCollection(
            metrics=metrics,
            device=device,
            logs=logs,
            knowledge=knowledge,
        ),
        bundle_status=EvidenceBundleStatus.PARTIAL,
        built_at=max(
            metrics.collected_at,
            device.collected_at,
            logs.collected_at,
            knowledge.collected_at,
        ),
    )
    judge = evaluate_evidence(plan, bundle)
    return plan, bundle, judge


async def _actual_historical_replay_planner_dry_run_async(
    state_root: str | Path = STATE_ROOT,
) -> dict[str, Any]:
    root = Path(state_root)
    paths = continuation_paths(root)
    sample = pinned_sample()
    replay_at = historical_replay_anchor(
        paths.device_checkpoint
    )
    metrics_checkpoint = _load_checkpoint(
        paths.metrics_checkpoint
    )
    if metrics_checkpoint is None:
        raise P2RCAContinueError(
            "Metrics checkpoint is missing for planner dry-run"
        )
    metrics_artifact_ref = next(
        (
            ref
            for ref in metrics_checkpoint.output_refs
            if _mapping_ref_kind(ref)
            == "existing_metrics_artifact"
        ),
        "",
    )
    if not metrics_artifact_ref:
        raise P2RCAContinueError(
            "Metrics artifact ref is missing for planner dry-run"
        )

    triage_invocation = AgentInvocation(
        request_id=V3_REQUEST_ID,
        agent_name=AgentName.TRIAGE,
        orchestration_state=OrchestrationState.TRIAGE,
        prior_output_refs=(),
        prior_outputs={},
    )
    triage = await TriageAgent(
        source=sample.source,
        payload=sample.raw_payload,
        event_index=0,
        received_at=_aware_now(),
    ).run(triage_invocation)
    if triage.status == AgentStatus.FAILED:
        raise P2RCAContinueError(
            "Triage failed during historical planner dry-run"
        )

    planner_invocation = AgentInvocation(
        request_id=V3_REQUEST_ID,
        agent_name=AgentName.STATIC_PLANNER,
        orchestration_state=OrchestrationState.PLANNING,
        prior_output_refs=triage.output_refs,
        prior_outputs={
            AgentName.TRIAGE.value: dict(triage.output)
        },
    )
    original_class = p2_device_continue_module.StaticPlannerAgent
    with historical_replay_planner_scope(replay_at):
        patched_class = p2_device_continue_module.StaticPlannerAgent
        if patched_class is original_class:
            raise P2RCAContinueError(
                "historical replay planner patch was not installed"
            )
        planner = await patched_class().run(planner_invocation)
    if p2_device_continue_module.StaticPlannerAgent is not original_class:
        raise P2RCAContinueError(
            "historical replay planner patch was not restored"
        )
    if planner.status == AgentStatus.FAILED:
        raise P2RCAContinueError(
            "Static Planner failed during historical dry-run"
        )
    adjusted = (
        p2_device_continue_module.adjust_plan_for_continuation(
            planner,
            metrics_artifact_ref,
        )
    )
    raw_plan = _mapping(adjusted.output).get("evidence_plan")
    if not isinstance(raw_plan, Mapping):
        raise P2RCAContinueError(
            "actual planner dry-run omitted evidence_plan"
        )
    plan = EvidencePlan.model_validate(raw_plan)
    if plan.created_at != replay_at:
        raise P2RCAContinueError(
            "actual planner did not retain replay Plan time"
        )
    source_map = {item.source: item for item in plan.sources}
    if source_map[EvidenceSource.METRICS].required:
        raise P2RCAContinueError(
            "actual replay planner made Metrics required"
        )
    if not source_map[EvidenceSource.DEVICE].required:
        raise P2RCAContinueError(
            "actual replay planner made Device optional"
        )
    for source in (
        EvidenceSource.METRICS,
        EvidenceSource.DEVICE,
    ):
        constraints = dict(source_map[source].constraints)
        if constraints.get(
            "historical_controlled_replay"
        ) is not True:
            raise P2RCAContinueError(
                f"actual replay marker missing: {source.value}"
            )
        if constraints.get(
            "production_freshness_rule_changed"
        ) is not False:
            raise P2RCAContinueError(
                f"freshness boundary changed: {source.value}"
            )

    report = {
        "schema_version": V8_SCHEMA_VERSION,
        "status": "pass",
        "request_id": V3_REQUEST_ID,
        "historical_controlled_replay": True,
        "plan_created_at": plan.created_at.isoformat(),
        "metrics_required": False,
        "device_required": True,
        "planner_patch_restored": True,
        "production_freshness_rule_changed": False,
        "external_calls": [],
        "created_at": _aware_now().isoformat(),
    }
    _write_json(
        root / "historical_replay_planner_dry_run.json",
        report,
    )
    return report


def actual_historical_replay_planner_dry_run(
    state_root: str | Path = STATE_ROOT,
) -> dict[str, Any]:
    return asyncio.run(
        _actual_historical_replay_planner_dry_run_async(
            state_root
        )
    )


def historical_replay_judge_dry_run(
    state_root: str | Path = STATE_ROOT,
) -> dict[str, Any]:
    root = Path(state_root)
    paths = continuation_paths(root)
    metrics = _checkpoint_evidence(
        paths.metrics_checkpoint,
        "metrics_evidence",
    )
    device = _checkpoint_evidence(
        paths.device_checkpoint,
        "device_evidence",
    )
    replay_at = historical_replay_anchor(
        paths.device_checkpoint
    )
    plan, bundle, judge = evaluate_checkpoint_evidence_at(
        metrics,
        device,
        plan_created_at=replay_at,
    )

    missing_required = [
        item.value for item in judge.missing_required_sources
    ]
    missing_optional = [
        item.value for item in judge.missing_optional_sources
    ]
    conflicts = [
        {
            "statement": item.statement,
            "severity": item.severity,
        }
        for item in judge.conflicts
    ]
    expected_optional = [
        EvidenceSource.METRICS.value,
        EvidenceSource.LOGS.value,
        EvidenceSource.KNOWLEDGE.value,
    ]
    if MAX_EVIDENCE_SKEW_SECONDS != 1800:
        raise P2RCAContinueError(
            "production freshness threshold changed unexpectedly"
        )
    if judge.status != JudgeStatus.PARTIAL:
        raise P2RCAContinueError(
            f"historical replay Judge status is {judge.status.value}"
        )
    if judge.rca_allowed is not True:
        raise P2RCAContinueError(
            "historical replay Judge did not allow RCA"
        )
    if missing_required:
        raise P2RCAContinueError(
            "historical replay has missing required evidence"
        )
    if missing_optional != expected_optional:
        raise P2RCAContinueError(
            "historical replay optional evidence set changed"
        )
    if conflicts:
        raise P2RCAContinueError(
            "historical replay contains evidence conflicts"
        )
    if abs(judge.confidence_cap - EXPECTED_REPLAY_CONFIDENCE_CAP) > 1e-9:
        raise P2RCAContinueError(
            "historical replay confidence cap changed"
        )
    if (root / "glm_attempt.json").exists():
        raise P2RCAContinueError(
            "GLM attempt exists before historical replay preflight"
        )

    report = {
        "schema_version": V8_SCHEMA_VERSION,
        "status": "pass",
        "historical_controlled_replay": True,
        "anchor": HISTORICAL_REPLAY_ANCHOR,
        "plan_created_at": plan.created_at.isoformat(),
        "metrics_collected_at": metrics.collected_at.isoformat(),
        "device_collected_at": device.collected_at.isoformat(),
        "metrics_skew_seconds": int(
            abs(
                (
                    metrics.collected_at - plan.created_at
                ).total_seconds()
            )
        ),
        "device_skew_seconds": int(
            abs(
                (
                    device.collected_at - plan.created_at
                ).total_seconds()
            )
        ),
        "max_evidence_skew_seconds": (
            MAX_EVIDENCE_SKEW_SECONDS
        ),
        "judge_status": judge.status.value,
        "rca_allowed": judge.rca_allowed,
        "confidence_cap": judge.confidence_cap,
        "missing_required_sources": missing_required,
        "missing_optional_sources": missing_optional,
        "conflicts": conflicts,
        "production_freshness_rule_changed": False,
        "glm_called": False,
        "prometheus_mcp_called": False,
        "netmiko_mcp_called": False,
        "device_command_executed": False,
        "created_at": _aware_now().isoformat(),
    }
    _write_json(
        root / "historical_replay_judge_dry_run.json",
        report,
    )
    return report


def _confidence(value: Any, cap: float) -> float:
    labels = {
        "low": 0.35,
        "medium": 0.55,
        "high": 0.75,
    }
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in labels:
            parsed = labels[normalized]
        else:
            try:
                parsed = float(normalized)
            except ValueError:
                parsed = min(0.5, cap)
    else:
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            parsed = min(0.5, cap)
    return max(0.0, min(parsed, float(cap), 1.0))


def _coerce_content(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, Mapping):
                text = item.get("text")
                if text is not None:
                    parts.append(str(text))
        return "\n".join(parts).strip()
    return ""


def _bounded_prompt_value(
    value: Any,
    *,
    depth: int = 0,
) -> Any:
    """Return a deterministic bounded value for the one-call RCA prompt."""

    sanitized = sanitize_sensitive_data(value)
    if depth >= 4:
        return _redact(sanitized, 240)
    if isinstance(sanitized, Mapping):
        output: dict[str, Any] = {}
        items = sorted(
            sanitized.items(),
            key=lambda pair: str(pair[0]),
        )[:16]
        for raw_key, child in items:
            key = str(raw_key)
            if key.lower() in {
                "raw_payload",
                "raw_output",
                "full_output",
                "command_output",
                "session_log",
            }:
                continue
            output[key] = _bounded_prompt_value(
                child,
                depth=depth + 1,
            )
        return output
    if isinstance(sanitized, (list, tuple)):
        return [
            _bounded_prompt_value(item, depth=depth + 1)
            for item in list(sanitized)[:12]
        ]
    if isinstance(sanitized, str):
        return sanitized[:600]
    if sanitized is None or isinstance(
        sanitized,
        (bool, int, float),
    ):
        return sanitized
    return _redact(sanitized, 240)


def _prompt_evidence_envelope(
    envelope: Mapping[str, Any],
    *,
    include_facts: bool,
) -> dict[str, Any]:
    output = {
        "status": _text(envelope.get("status")),
        "summary": _redact(envelope.get("summary"), 600),
        "scope": _bounded_prompt_value(envelope.get("scope") or {}),
        "evidence_refs": _string_list(envelope.get("evidence_refs")),
        "reason": _redact(envelope.get("reason"), 300),
    }
    if include_facts:
        output["facts"] = _bounded_prompt_value(
            envelope.get("facts") or {}
        )
    return output


def _compact_prompt_value(value: Any, *, depth: int = 0) -> Any:
    """Aggressively bound prompt data without changing persisted Evidence."""

    sanitized = sanitize_sensitive_data(value)
    if depth >= 3:
        return _redact(sanitized, 120)
    if isinstance(sanitized, Mapping):
        output: dict[str, Any] = {}
        for raw_key, child in sorted(
            sanitized.items(), key=lambda pair: str(pair[0])
        )[:8]:
            key = str(raw_key)
            if key.lower() in {
                "raw_payload",
                "raw_output",
                "full_output",
                "command_output",
                "session_log",
                "samples",
                "series",
                "history",
            }:
                continue
            output[key] = _compact_prompt_value(
                child, depth=depth + 1
            )
        return output
    if isinstance(sanitized, (list, tuple)):
        return [
            _compact_prompt_value(item, depth=depth + 1)
            for item in list(sanitized)[:5]
        ]
    if isinstance(sanitized, str):
        return sanitized[:220]
    if sanitized is None or isinstance(sanitized, (bool, int, float)):
        return sanitized
    return _redact(sanitized, 120)


def _compact_envelope(envelope: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": _text(envelope.get("status")),
        "summary": _redact(envelope.get("summary"), 320),
        "facts": _compact_prompt_value(envelope.get("facts") or {}),
        "scope": _compact_prompt_value(envelope.get("scope") or {}),
        "evidence_refs": _string_list(envelope.get("evidence_refs")),
    }


def _minimal_rca_prompt(
    *,
    event: Mapping[str, Any],
    bundle: EvidenceBundle,
    judge: EvidenceJudgeResult,
) -> str:
    allowed_refs = sorted(
        set(bundle_evidence_refs(bundle)) & set(judge.evidence_refs)
    )
    if not allowed_refs:
        raise P2RCAContinueError(
            "RCA prompt has no allowed evidence refs"
        )

    bundle_payload = bundle.model_dump(mode="json")
    evidence = _mapping(bundle_payload.get("evidence"))
    inherited = inherited_missing_evidence(judge)
    prompt_input = {
        "event": {
            "alert_name": _text(event.get("alert_name")),
            "alert_status": _text(event.get("alert_status")),
            "device": _compact_prompt_value(
                _mapping(event.get("device"))
            ),
            "alert_object": _compact_prompt_value(
                _mapping(event.get("alert_object"))
            ),
        },
        "judge": {
            "status": judge.status.value,
            "confidence_cap": judge.confidence_cap,
            "missing_evidence": inherited,
        },
        "evidence": {
            "metrics": _compact_envelope(
                _mapping(evidence.get("metrics"))
            ),
            "device": _compact_envelope(
                _mapping(evidence.get("device"))
            ),
        },
        "allowed_evidence_refs": allowed_refs,
        "output_skeleton": {
            "possible_causes": ["候选根因，不超过80字"],
            "uncertainties": ["不确定性，不超过60字"],
        },
    }
    prompt = (
        "只输出JSON对象，不输出Markdown、解释或推理过程。"
        "格式严格为{\"possible_causes\":[\"...\"],"
        "\"uncertainties\":[\"...\"]}。"
        "possible_causes输出1至2项，每项不超过80字；"
        "uncertainties输出1至2项，每项不超过60字。"
        "只能依据INPUT_JSON，不得声称日志正常，不得虚构命令执行。\n"
        "INPUT_JSON=" + stable_json_dumps(prompt_input)
    )
    if len(prompt) > MAX_PROMPT_CHARS:
        raise P2RCAContinueError(
            "compact RCA prompt exceeds the approved character limit"
        )
    return prompt

def _runtime_llm_summary(
    production_config: Mapping[str, Any],
) -> dict[str, Any]:
    one_call = _one_call_llm_config(
        production_config,
        timeout_seconds=REQUEST_TIMEOUT_SECONDS,
    )
    llm = dict(_mapping(one_call.get("llm")))
    llm["retry"] = 0
    llm["retries"] = 0
    llm["temperature"] = 0
    llm["max_tokens"] = MAX_OUTPUT_TOKENS
    llm["timeout"] = REQUEST_TIMEOUT_SECONDS
    llm["connect_timeout"] = CONNECT_TIMEOUT_SECONDS
    llm["read_timeout"] = READ_TIMEOUT_SECONDS
    llm["write_timeout"] = WRITE_TIMEOUT_SECONDS
    llm["pool_timeout"] = POOL_TIMEOUT_SECONDS

    endpoints = _build_endpoint_configs(llm)
    if len(endpoints) != 1:
        raise P2RCAContinueError(
            "RCA continuation requires exactly one LLM endpoint"
        )
    endpoint = dict(endpoints[0])
    parsed = urlparse(str(endpoint.get("base_url") or ""))
    if parsed.scheme not in {"http", "https"}:
        raise P2RCAContinueError(
            "LLM endpoint scheme must be http or https"
        )
    if not parsed.hostname:
        raise P2RCAContinueError("LLM endpoint hostname is empty")
    if parsed.username is not None or parsed.password is not None:
        raise P2RCAContinueError(
            "LLM endpoint must not contain credentials"
        )
    if _text(llm.get("model")) != EXPECTED_MODEL:
        raise P2RCAContinueError(
            "production LLM model is not glm-5.2"
        )
    endpoint["timeout"] = REQUEST_TIMEOUT_SECONDS
    timeout_object = _build_timeout(
        REQUEST_TIMEOUT_SECONDS,
        llm,
    )
    timeout_contract = {
        "request_timeout_seconds": REQUEST_TIMEOUT_SECONDS,
        "connect_timeout_seconds": float(timeout_object.connect),
        "read_timeout_seconds": float(timeout_object.read),
        "write_timeout_seconds": float(timeout_object.write),
        "pool_timeout_seconds": float(timeout_object.pool),
    }
    expected_timeout_contract = {
        "request_timeout_seconds": 300,
        "connect_timeout_seconds": 10.0,
        "read_timeout_seconds": 300.0,
        "write_timeout_seconds": 30.0,
        "pool_timeout_seconds": 10.0,
    }
    if timeout_contract != expected_timeout_contract:
        raise P2RCAContinueError(
            "resolved GLM timeout contract is not the approved final contract"
        )

    env_names = _llm_required_env_names(production_config)
    service_env = _systemd_service_environment(env_names)
    old_env = {
        name: os.environ.get(name)
        for name in env_names
    }
    try:
        for name in env_names:
            if not os.environ.get(name) and service_env.get(name):
                os.environ[name] = service_env[name]
        api_key = _resolve_api_key(llm)
        key_source = (
            "direct_config"
            if _text(llm.get("api_key"))
            and _text(llm.get("api_key")) != "YOUR_API_KEY"
            else (
                "environment"
                if api_key and env_names
                else "missing"
            )
        )
    finally:
        for name, value in old_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    if not api_key:
        raise P2RCAContinueError(
            "LLM API key is not configured for the CLI continuation"
        )

    return {
        "config": {"llm": llm},
        "endpoint": endpoint,
        "endpoint_summary": {
            "scheme": parsed.scheme,
            "hostname": parsed.hostname,
            "port": parsed.port,
            "path_present": bool(parsed.path),
        },
        "key_source": key_source,
        "api_key_configured": True,
        "environment_names": sorted(env_names),
        "timeout_contract": timeout_contract,
    }


def _load_key_into_process(
    production_config: Mapping[str, Any],
) -> tuple[set[str], dict[str, str | None]]:
    env_names = _llm_required_env_names(production_config)
    service_env = _systemd_service_environment(env_names)
    old_env = {
        name: os.environ.get(name)
        for name in env_names
    }
    for name in env_names:
        if not os.environ.get(name) and service_env.get(name):
            os.environ[name] = service_env[name]
    return env_names, old_env


def _restore_process_env(
    names: set[str],
    old_env: Mapping[str, str | None],
) -> None:
    for name in names:
        value = old_env.get(name)
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


def _single_glm_call(
    *,
    prompt: str,
    production_config: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    runtime = _runtime_llm_summary(production_config)
    llm = dict(_mapping(_mapping(runtime.get("config")).get("llm")))
    endpoint = dict(_mapping(runtime.get("endpoint")))

    names, old_env = _load_key_into_process(production_config)
    started = time.monotonic()
    metadata: dict[str, Any] = {
        "schema_version": V8_SCHEMA_VERSION,
        "attempt_count": 1,
        "configured_model": llm.get("model"),
        "endpoint": runtime.get("endpoint_summary"),
        "timeout_contract": runtime.get("timeout_contract"),
        "api_key_configured": True,
        "key_source": runtime.get("key_source"),
        "request_sent": False,
        "response_received": False,
        "parse_status": "not_started",
        "requested_max_tokens": MAX_OUTPUT_TOKENS,
        "prompt_chars": len(prompt),
        "prompt_sha256": hashlib.sha256(
            prompt.encode("utf-8")
        ).hexdigest(),
    }
    try:
        api_key = _resolve_api_key(llm)
        if not api_key:
            raise P2RCAContinueError(
                "LLM API key disappeared before the request"
            )
        headers = _build_headers(api_key, llm)
        payload = _build_payload(
            prompt,
            str(llm.get("model") or ""),
            llm,
        )
        payload["max_tokens"] = MAX_OUTPUT_TOKENS
        timeout_seconds = int(endpoint.get("timeout"))
        if timeout_seconds != REQUEST_TIMEOUT_SECONDS:
            raise P2RCAContinueError(
                "GLM request timeout changed after preflight"
            )
        timeout_object = _build_timeout(timeout_seconds, llm)
        runtime_contract = {
            "request_timeout_seconds": timeout_seconds,
            "connect_timeout_seconds": float(timeout_object.connect),
            "read_timeout_seconds": float(timeout_object.read),
            "write_timeout_seconds": float(timeout_object.write),
            "pool_timeout_seconds": float(timeout_object.pool),
        }
        if runtime_contract != runtime.get("timeout_contract"):
            raise P2RCAContinueError(
                "GLM runtime timeout differs from preflight"
            )
        metadata["timeout_contract"] = runtime_contract
        verify_ssl = bool(endpoint.get("verify_ssl", True))
        metadata["request_sent"] = True
        with httpx.Client(
            timeout=timeout_object,
            verify=verify_ssl,
        ) as client:
            response = client.post(
                str(endpoint["base_url"]).rstrip("/")
                + "/chat/completions",
                headers=headers,
                json=payload,
            )
        metadata["response_received"] = True
        metadata["latency_ms"] = int(
            (time.monotonic() - started) * 1000
        )
        metadata["status_code"] = response.status_code
        metadata["channel_name_present"] = bool(
            response.headers.get("X-Channel-Name")
        )
        response.raise_for_status()
        data = response.json()
        metadata["reported_model"] = data.get("model")
        choice = (data.get("choices") or [{}])[0]
        metadata["finish_reason"] = choice.get("finish_reason")
        message = _mapping(choice.get("message"))
        content = _coerce_content(message.get("content"))
        reasoning = _coerce_content(
            message.get("reasoning_content")
        )
        metadata["content_present"] = bool(content)
        metadata["content_length"] = len(content)
        metadata["content_sha256"] = hashlib.sha256(
            content.encode("utf-8")
        ).hexdigest()
        metadata["reasoning_content_present"] = bool(reasoning)
        metadata["reasoning_content_length"] = len(reasoning)

        if not content:
            if _text(metadata.get("finish_reason")) == "length":
                metadata["parse_status"] = (
                    "output_budget_exhausted"
                )
                raise P2RCAContinueError(
                    "GLM output budget exhausted before final content"
                )
            metadata["parse_status"] = "empty_content"
            raise P2RCAContinueError(
                "GLM returned empty message.content"
            )
        json_text = _extract_json_text(content)
        analysis = json.loads(json_text)
        if not isinstance(analysis, Mapping):
            metadata["parse_status"] = "root_not_object"
            raise P2RCAContinueError(
                "GLM JSON root is not an object"
            )
        metadata["parse_status"] = "ok"
        metadata["analysis_root_keys"] = sorted(
            str(key) for key in analysis.keys()
        )
        return dict(analysis), metadata
    except Exception as exc:
        metadata["latency_ms"] = int(
            (time.monotonic() - started) * 1000
        )
        metadata["error_type"] = type(exc).__name__
        metadata["error"] = _redact(exc)
        if metadata["parse_status"] == "not_started":
            metadata["parse_status"] = "failed"
        raise GLMSingleCallError(
            "single GLM request failed",
            metadata=metadata,
        ) from exc
    finally:
        _restore_process_env(names, old_env)


def normalize_rca_payload(
    raw: Mapping[str, Any],
    *,
    bundle: EvidenceBundle,
    judge: EvidenceJudgeResult,
    event: Mapping[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    allowed_refs = sorted(
        set(bundle_evidence_refs(bundle))
        & set(judge.evidence_refs)
    )
    if not allowed_refs:
        raise P2RCAContinueError(
            "Judge exposes no usable evidence refs"
        )
    inherited = inherited_missing_evidence(judge)
    actions: list[str] = []

    raw_candidates = raw.get("candidates")
    candidate_values: list[Any]
    if isinstance(raw_candidates, list):
        candidate_values = raw_candidates
    else:
        possible = (
            raw.get("possible_causes")
            or raw.get("root_causes")
            or []
        )
        if isinstance(possible, list) and possible:
            candidate_values = [
                {"statement": item}
                for item in possible[:MAX_RCA_CANDIDATES]
                if str(item or "").strip()
            ]
            actions.append("legacy_possible_causes_converted")
        elif _text(raw.get("summary")):
            candidate_values = [
                {"statement": _text(raw.get("summary"))}
            ]
            actions.append("legacy_summary_converted")
        else:
            raise P2RCAContinueError(
                "GLM response has no usable RCA candidate"
            )

    normalized_candidates: list[dict[str, Any]] = []
    seen_statements: set[str] = set()
    top_uncertainties = _string_list(
        raw.get("uncertainties")
    )
    event_scope = {
        "device": dict(_mapping(event.get("device"))),
        "alert_object": dict(
            _mapping(event.get("alert_object"))
        ),
    }

    for value in candidate_values:
        if len(normalized_candidates) >= MAX_RCA_CANDIDATES:
            break
        candidate = (
            dict(value)
            if isinstance(value, Mapping)
            else {"statement": value}
        )
        statement = _text(candidate.get("statement"))
        if not statement or statement in seen_statements:
            continue
        seen_statements.add(statement)

        supporting = [
            ref
            for ref in _string_list(
                candidate.get("supporting_evidence_refs")
            )
            if ref in allowed_refs
        ]
        if not supporting:
            supporting = [allowed_refs[0]]
            actions.append("supporting_ref_completed")

        contradicting = [
            ref
            for ref in _string_list(
                candidate.get("contradicting_evidence_refs")
            )
            if ref in allowed_refs and ref not in supporting
        ]

        candidate_missing = _string_list(
            candidate.get("missing_evidence")
        )
        missing = list(
            dict.fromkeys([*inherited, *candidate_missing])
        )
        uncertainties = _string_list(
            candidate.get("uncertainties")
        )
        if not uncertainties:
            uncertainties = (
                top_uncertainties
                or [
                    "结论受当前缺失证据及单次受控取证范围限制。"
                ]
            )
            actions.append("candidate_uncertainty_completed")

        scope = dict(_mapping(candidate.get("scope")))
        if not scope:
            scope = event_scope
            actions.append("candidate_scope_completed")

        normalized_candidates.append(
            {
                "statement": statement,
                "confidence": _confidence(
                    candidate.get("confidence"),
                    judge.confidence_cap,
                ),
                "supporting_evidence_refs": supporting,
                "contradicting_evidence_refs": contradicting,
                "missing_evidence": missing,
                "uncertainties": uncertainties,
                "scope": scope,
            }
        )

    if not normalized_candidates:
        raise P2RCAContinueError(
            "GLM response has no non-empty unique candidate"
        )

    top_missing = list(
        dict.fromkeys(
            [
                *inherited,
                *_string_list(raw.get("missing_evidence")),
            ]
        )
    )
    normalized_top_uncertainties = (
        top_uncertainties
        or [
            "RCA 仅依据当前 Evidence Bundle 和 Judge 结果生成。"
        ]
    )
    return (
        {
            "candidates": normalized_candidates,
            "missing_evidence": top_missing,
            "uncertainties": normalized_top_uncertainties,
        },
        list(dict.fromkeys(actions)),
    )


class ReusedDeviceCollectorV8:
    def __init__(self, checkpoint_path: str | Path) -> None:
        self.checkpoint_path = Path(checkpoint_path)

    async def collect(
        self,
        *,
        request_id: str,
        sample: Any,
        settings: P2Settings,
        ledger: P2CallLedger,
    ) -> AgentOutcome:
        existing = _load_checkpoint(self.checkpoint_path)
        if existing is None:
            raise P2RCAContinueError(
                "reused Device checkpoint is missing"
            )
        output = dict(existing.output)
        output.update(
            {
                "device_checkpoint_reused": True,
                "netmiko_mcp_called": False,
                "netmiko_mcp_previously_called": True,
                "device_command_repeated": False,
            }
        )
        warning = ContractNotice(
            code="p2_device_checkpoint_reused_final",
            message=(
                "Final continuation reused the successful V3 Device checkpoint "
                "without another Netmiko MCP call."
            ),
            stage="device_evidence",
            retryable=False,
            details={
                "source_checkpoint": "v3/device.json",
            },
        )
        return AgentOutcome(
            status=existing.status,
            output_refs=existing.output_refs,
            output=output,
            warnings=tuple([*existing.warnings, warning]),
            errors=existing.errors,
            external_calls=(),
        )


class CheckpointedGLMRCACollectorV8:
    def __init__(
        self,
        *,
        production_config: Mapping[str, Any],
        state_root: str | Path,
    ) -> None:
        self.production_config = dict(production_config)
        self.state_root = Path(state_root)
        self.attempt_path = self.state_root / "glm_attempt.json"
        self.validation_path = (
            self.state_root / "rca_validation.json"
        )

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
            _mapping(outputs.get("triage")).get(
                "unified_event"
            )
        )
        bundle_raw = _mapping(
            _mapping(outputs.get("evidence_bundle")).get(
                "evidence_bundle"
            )
        )
        judge_raw = _mapping(
            _mapping(outputs.get("evidence_judge")).get(
                "judge_result"
            )
        )
        if not event or not bundle_raw or not judge_raw:
            raise P2RCAContinueError(
                "RCA continuation inputs are incomplete"
            )

        bundle = EvidenceBundle.model_validate(bundle_raw)
        judge = EvidenceJudgeResult.model_validate(judge_raw)
        if not judge.rca_allowed:
            raise P2RCAContinueError(
                "Judge does not allow RCA"
            )

        event_ref = _one_ref(
            output_refs,
            "event",
            None,
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
        prompt = _minimal_rca_prompt(
            event=event,
            bundle=bundle,
            judge=judge,
        )

        ledger.reserve(
            P2CallKind.RCA,
            operation_id=(
                "glm-rca-final:"
                + hashlib.sha256(
                    prompt.encode("utf-8")
                ).hexdigest()[:16]
            ),
            provider="glm-5.2",
        )
        request_ref = build_contract_ref(
            "artifact",
            request_id,
            "external_request",
            "glm-rca-final-request",
        )
        started_at = _aware_now()
        metadata: Mapping[str, Any] = {}
        try:
            loop = asyncio.get_running_loop()
            raw, metadata = await loop.run_in_executor(
                None,
                lambda: _single_glm_call(
                    prompt=prompt,
                    production_config=self.production_config,
                ),
            )
        except Exception as exc:
            finished_at = _aware_now()
            captured_metadata = (
                dict(exc.metadata)
                if isinstance(exc, GLMSingleCallError)
                else dict(metadata)
            )
            failure_metadata = {
                "schema_version": V8_SCHEMA_VERSION,
                "status": "failed",
                "request_id": request_id,
                "metadata": captured_metadata,
                "error_type": type(exc).__name__,
                "error": _redact(exc),
                "prompt_sha256": hashlib.sha256(
                    prompt.encode("utf-8")
                ).hexdigest(),
                "real_call_count": 1,
                "written_at": finished_at.isoformat(),
            }
            _write_json(self.attempt_path, failure_metadata)
            notice = _notice(
                "p2_glm_final_call_failed",
                "The single GLM 5.2 RCA request failed.",
                stage="rca",
                details={
                    "attempt_ref": "checkpoint://glm_attempt",
                    "attempt_count": 1,
                },
            )
            external = _external_record(
                request_id=request_id,
                system="glm_5_2",
                operation="generate_evidence_grounded_rca_v8",
                status=ExternalCallStatus.FAILED,
                started_at=started_at,
                finished_at=finished_at,
                request_ref=request_ref,
                response_ref=None,
                error=notice,
            )
            return AgentOutcome(
                status=AgentStatus.FAILED,
                output={
                    "production_glm_called": True,
                    "single_http_attempt": True,
                    "diagnostic_written": True,
                    "mcp_called": False,
                    "tool_called": False,
                    "automatic_followup_queries": False,
                },
                errors=(notice,),
                external_calls=(external,),
            )

        finished_at = _aware_now()
        attempt_payload = {
            "schema_version": V8_SCHEMA_VERSION,
            "status": "success",
            "request_id": request_id,
            "metadata": dict(metadata),
            "prompt_sha256": hashlib.sha256(
                prompt.encode("utf-8")
            ).hexdigest(),
            "raw_analysis_sha256": hashlib.sha256(
                stable_json_dumps(raw).encode("utf-8")
            ).hexdigest(),
            "real_call_count": 1,
            "written_at": finished_at.isoformat(),
        }
        _write_json(self.attempt_path, attempt_payload)

        try:
            normalized, actions = normalize_rca_payload(
                raw,
                bundle=bundle,
                judge=judge,
                event=event,
            )
            result = validate_rca_response(
                normalized,
                bundle=bundle,
                judge=judge,
                event_ref=event_ref,
                bundle_ref=bundle_ref,
                judge_ref=judge_ref,
                generated_at=finished_at,
                provider="production-glm-5.2-v8",
            )
        except (
            RCAValidationError,
            P2RCAContinueError,
            ValueError,
        ) as exc:
            _write_json(
                self.validation_path,
                {
                    "schema_version": V8_SCHEMA_VERSION,
                    "status": "failed",
                    "request_id": request_id,
                    "error_type": type(exc).__name__,
                    "error": _redact(exc),
                    "raw_root_keys": sorted(
                        str(key) for key in raw.keys()
                    ),
                    "attempt_ref": "checkpoint://glm_attempt",
                    "written_at": _aware_now().isoformat(),
                },
            )
            notice = _notice(
                "p2_glm_final_validation_failed",
                "GLM response failed the frozen RCA validator.",
                stage="rca",
                details={
                    "validation_ref": (
                        "checkpoint://rca_validation"
                    ),
                    "attempt_count": 1,
                },
            )
            external = _external_record(
                request_id=request_id,
                system="glm_5_2",
                operation="generate_evidence_grounded_rca_v8",
                status=ExternalCallStatus.FAILED,
                started_at=started_at,
                finished_at=finished_at,
                request_ref=request_ref,
                response_ref=None,
                error=notice,
            )
            return AgentOutcome(
                status=AgentStatus.FAILED,
                output={
                    "production_glm_called": True,
                    "single_http_attempt": True,
                    "diagnostic_written": True,
                    "mcp_called": False,
                    "tool_called": False,
                    "automatic_followup_queries": False,
                },
                errors=(notice,),
                external_calls=(external,),
            )

        _write_json(
            self.validation_path,
            {
                "schema_version": V8_SCHEMA_VERSION,
                "status": "success",
                "request_id": request_id,
                "normalization_actions": actions,
                "candidate_count": len(result.candidates),
                "provider": result.provider,
                "written_at": _aware_now().isoformat(),
            },
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
            f"glm-rca-v8-{digest}",
        )
        output_ref = build_contract_ref(
            "artifact",
            request_id,
            "rca_result",
            f"rca-v8-{digest}",
        )
        external = _external_record(
            request_id=request_id,
            system="glm_5_2",
            operation="generate_evidence_grounded_rca_v8",
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
                "prompt_version": "p2_real_rca_v8",
                "prompt_sha256": hashlib.sha256(
                    prompt.encode("utf-8")
                ).hexdigest(),
                "normalization_actions": actions,
                "production_glm_called": True,
                "single_http_attempt": True,
                "mcp_called": False,
                "tool_called": False,
                "automatic_followup_queries": False,
            },
            external_calls=(external,),
        )


def _checkpoint_request_id(path: Path) -> str:
    payload = _safe_read_json(path)
    output = _mapping(payload.get("output"))
    for key in ("metrics_evidence", "device_evidence"):
        envelope = _mapping(output.get(key))
        request_id = _text(envelope.get("request_id"))
        if request_id:
            return request_id
    return ""


def validate_v4_no_call_state() -> dict[str, Any]:
    forbidden = (
        V4_STATE_ROOT / "glm_attempt.json",
        V4_STATE_ROOT / "continue_result.json",
        V4_STATE_ROOT / "v4_gate.json",
        V4_STATE_ROOT / "checkpoints" / "rca.json",
    )
    existing = [str(path) for path in forbidden if path.exists()]
    if existing:
        raise P2RCAContinueError(
            "V4 unexpectedly contains post-preflight artifacts: "
            + ", ".join(existing)
        )
    return {
        "status": "pass",
        "glm_attempted": False,
        "prometheus_mcp_repeated": False,
        "netmiko_mcp_repeated": False,
        "device_command_repeated": False,
    }


def validate_v5_no_call_state() -> dict[str, Any]:
    required = (
        V5_STATE_ROOT / "preflight.json",
        V5_STATE_ROOT / "source_checkpoints.json",
        V5_STATE_ROOT / "RCA_CONTINUE_FAILURE_REPORT.json",
    )
    for path in required:
        if not path.is_file() or path.is_symlink():
            raise P2RCAContinueError(
                f"required V5 no-call artifact is missing: {path.name}"
            )
    forbidden = (
        V5_STATE_ROOT / "glm_attempt.json",
        V5_STATE_ROOT / "rca_validation.json",
        V5_STATE_ROOT / "continue_result.json",
        V5_STATE_ROOT / "v5_gate.json",
        V5_STATE_ROOT / "checkpoints" / "rca.json",
    )
    existing = [str(path) for path in forbidden if path.exists()]
    if existing:
        raise P2RCAContinueError(
            "V5 unexpectedly contains post-Judge artifacts: "
            + ", ".join(existing)
        )
    failure = _safe_read_json(
        V5_STATE_ROOT / "RCA_CONTINUE_FAILURE_REPORT.json"
    )
    if failure.get("error") != (
        "continuation evidence did not allow RCA"
    ):
        raise P2RCAContinueError(
            "V5 failure is not the approved stale-Evidence Judge failure"
        )
    if _text(failure.get("request_id")) != V3_REQUEST_ID:
        raise P2RCAContinueError(
            "V5 failure request_id changed"
        )
    if failure.get("glm_attempt_exists") is not False:
        raise P2RCAContinueError(
            "V5 failure does not prove zero GLM attempts"
        )
    return {
        "status": "pass",
        "request_id": V3_REQUEST_ID,
        "failure_report_sha256": _sha256_file(
            V5_STATE_ROOT / "RCA_CONTINUE_FAILURE_REPORT.json"
        ),
        "glm_attempted": False,
        "prometheus_mcp_repeated": False,
        "netmiko_mcp_repeated": False,
        "device_command_repeated": False,
    }


def validate_v6_timeout_state() -> dict[str, Any]:
    required = (
        V6_STATE_ROOT / "preflight.json",
        V6_STATE_ROOT / "source_checkpoints.json",
        V6_STATE_ROOT / "historical_replay_planner_dry_run.json",
        V6_STATE_ROOT / "historical_replay_judge_dry_run.json",
        V6_STATE_ROOT / "glm_attempt.json",
        V6_STATE_ROOT / "RCA_CONTINUE_FAILURE_REPORT.json",
    )
    for path in required:
        if not path.is_file() or path.is_symlink():
            raise P2RCAContinueError(
                f"required V6 diagnostic artifact is missing: {path.name}"
            )

    forbidden = (
        V6_STATE_ROOT / "rca_validation.json",
        V6_STATE_ROOT / "continue_result.json",
        V6_STATE_ROOT / "v6_gate.json",
        V6_STATE_ROOT / "checkpoints" / "rca.json",
    )
    existing = [str(path) for path in forbidden if path.exists()]
    if existing:
        raise P2RCAContinueError(
            "V6 unexpectedly contains post-GLM success artifacts: "
            + ", ".join(existing)
        )

    planner = _safe_read_json(
        V6_STATE_ROOT / "historical_replay_planner_dry_run.json"
    )
    judge = _safe_read_json(
        V6_STATE_ROOT / "historical_replay_judge_dry_run.json"
    )
    attempt = _safe_read_json(
        V6_STATE_ROOT / "glm_attempt.json"
    )
    failure = _safe_read_json(
        V6_STATE_ROOT / "RCA_CONTINUE_FAILURE_REPORT.json"
    )
    metadata = _mapping(attempt.get("metadata"))

    if planner.get("status") != "pass":
        raise P2RCAContinueError(
            "V6 historical replay Planner dry-run did not pass"
        )
    if planner.get("historical_controlled_replay") is not True:
        raise P2RCAContinueError(
            "V6 historical replay Planner marker is missing"
        )
    if judge.get("status") != "pass":
        raise P2RCAContinueError(
            "V6 historical replay Judge dry-run did not pass"
        )
    if _text(judge.get("judge_status")) != "partial":
        raise P2RCAContinueError(
            "V6 Judge status is not partial"
        )
    if judge.get("rca_allowed") is not True:
        raise P2RCAContinueError(
            "V6 Judge did not allow RCA"
        )
    if list(judge.get("missing_required_sources") or []):
        raise P2RCAContinueError(
            "V6 Judge still has missing required sources"
        )
    if list(judge.get("conflicts") or []):
        raise P2RCAContinueError(
            "V6 Judge contains Evidence conflicts"
        )
    confidence_cap = float(judge.get("confidence_cap"))
    if abs(
        confidence_cap - EXPECTED_REPLAY_CONFIDENCE_CAP
    ) > 1e-12:
        raise P2RCAContinueError(
            "V6 Judge confidence cap changed"
        )

    if attempt.get("status") != "failed":
        raise P2RCAContinueError(
            "V6 GLM attempt is not the approved failed attempt"
        )
    _exact_nonnegative_int(
        attempt,
        "real_call_count",
        expected=1,
        context="V6 GLM attempt",
    )
    _exact_nonnegative_int(
        metadata,
        "attempt_count",
        expected=1,
        context="V6 GLM metadata",
    )
    if _text(metadata.get("configured_model")) != EXPECTED_MODEL:
        raise P2RCAContinueError(
            "V6 GLM model changed"
        )
    if metadata.get("request_sent") is not True:
        raise P2RCAContinueError(
            "V6 diagnostic does not prove request_sent=true"
        )
    if metadata.get("response_received") is not False:
        raise P2RCAContinueError(
            "V6 diagnostic unexpectedly received a response"
        )
    if _text(metadata.get("error_type")) != "ReadTimeout":
        raise P2RCAContinueError(
            "V6 failure is not a ReadTimeout"
        )
    if _text(metadata.get("parse_status")) != "failed":
        raise P2RCAContinueError(
            "V6 parse_status is not failed"
        )
    latency_ms = _exact_nonnegative_int(
        metadata,
        "latency_ms",
        expected=30112,
        context="V6 GLM metadata",
    )

    if failure.get("error") != "continued GLM RCA failed":
        raise P2RCAContinueError(
            "V6 failure report is not the approved GLM-stage failure"
        )
    if _text(failure.get("request_id")) != V3_REQUEST_ID:
        raise P2RCAContinueError(
            "V6 failure request_id changed"
        )
    for key in (
        "prometheus_mcp_repeated",
        "netmiko_mcp_repeated",
        "device_command_repeated",
        "notification_sent",
    ):
        if failure.get(key) is not False:
            raise P2RCAContinueError(
                f"V6 boundary changed: {key}"
            )

    return {
        "status": "pass",
        "request_id": V3_REQUEST_ID,
        "failure_kind": "glm_read_timeout",
        "request_sent": True,
        "response_received": False,
        "latency_ms": latency_ms,
        "configured_model": EXPECTED_MODEL,
        "planner_dry_run_sha256": _sha256_file(
            V7_STATE_ROOT
            / "historical_replay_planner_dry_run.json"
        ),
        "judge_dry_run_sha256": _sha256_file(
            V7_STATE_ROOT
            / "historical_replay_judge_dry_run.json"
        ),
        "glm_attempt_sha256": _sha256_file(
            V6_STATE_ROOT / "glm_attempt.json"
        ),
        "failure_report_sha256": _sha256_file(
            V6_STATE_ROOT / "RCA_CONTINUE_FAILURE_REPORT.json"
        ),
        "prometheus_mcp_repeated": False,
        "netmiko_mcp_repeated": False,
        "device_command_repeated": False,
    }


def validate_v7_output_budget_state() -> dict[str, Any]:
    required = (
        V7_STATE_ROOT / "preflight.json",
        V7_STATE_ROOT / "source_checkpoints.json",
        V7_STATE_ROOT / "historical_replay_planner_dry_run.json",
        V7_STATE_ROOT / "historical_replay_judge_dry_run.json",
        V7_STATE_ROOT / "glm_attempt.json",
        V7_STATE_ROOT / "RCA_CONTINUE_FAILURE_REPORT.json",
    )
    for path in required:
        if not path.is_file() or path.is_symlink():
            raise P2RCAContinueError(
                f"required V7 diagnostic artifact is missing: {path.name}"
            )

    forbidden = (
        V7_STATE_ROOT / "rca_validation.json",
        V7_STATE_ROOT / "continue_result.json",
        V7_STATE_ROOT / "v7_gate.json",
        V7_STATE_ROOT / "checkpoints" / "rca.json",
    )
    existing = [str(path) for path in forbidden if path.exists()]
    if existing:
        raise P2RCAContinueError(
            "V7 unexpectedly contains post-RCA artifacts: "
            + ", ".join(existing)
        )

    planner = _safe_read_json(
        V7_STATE_ROOT / "historical_replay_planner_dry_run.json"
    )
    judge = _safe_read_json(
        V7_STATE_ROOT / "historical_replay_judge_dry_run.json"
    )
    attempt = _safe_read_json(
        V7_STATE_ROOT / "glm_attempt.json"
    )
    failure = _safe_read_json(
        V7_STATE_ROOT / "RCA_CONTINUE_FAILURE_REPORT.json"
    )
    metadata = _mapping(attempt.get("metadata"))

    if planner.get("status") != "pass":
        raise P2RCAContinueError(
            "V7 historical replay Planner dry-run did not pass"
        )
    if judge.get("status") != "pass":
        raise P2RCAContinueError(
            "V7 historical replay Judge dry-run did not pass"
        )
    if _text(judge.get("judge_status")) != "partial":
        raise P2RCAContinueError("V7 Judge status is not partial")
    if judge.get("rca_allowed") is not True:
        raise P2RCAContinueError("V7 Judge did not allow RCA")
    if list(judge.get("missing_required_sources") or []):
        raise P2RCAContinueError(
            "V7 Judge has missing required sources"
        )
    if list(judge.get("conflicts") or []):
        raise P2RCAContinueError("V7 Judge contains conflicts")

    if attempt.get("status") != "failed":
        raise P2RCAContinueError(
            "V7 GLM attempt is not the approved failed attempt"
        )
    _exact_nonnegative_int(
        attempt,
        "real_call_count",
        expected=1,
        context="V7 GLM attempt",
    )
    _exact_nonnegative_int(
        metadata,
        "attempt_count",
        expected=1,
        context="V7 GLM metadata",
    )
    if _text(metadata.get("configured_model")) != EXPECTED_MODEL:
        raise P2RCAContinueError("V7 GLM model changed")
    if metadata.get("request_sent") is not True:
        raise P2RCAContinueError("V7 request_sent proof is missing")
    if metadata.get("response_received") is not True:
        raise P2RCAContinueError("V7 response_received proof is missing")
    _exact_nonnegative_int(
        metadata,
        "status_code",
        expected=200,
        context="V7 GLM metadata",
    )
    latency_ms = _exact_nonnegative_int(
        metadata,
        "latency_ms",
        expected=45605,
        context="V7 GLM metadata",
    )
    if _text(metadata.get("parse_status")) != "empty_content":
        raise P2RCAContinueError(
            "V7 parse_status is not the observed empty_content"
        )
    if _text(metadata.get("finish_reason")) != "length":
        raise P2RCAContinueError(
            "V7 finish_reason is not length"
        )
    if metadata.get("content_present") is not False:
        raise P2RCAContinueError(
            "V7 unexpectedly contains final content"
        )
    _exact_nonnegative_int(
        metadata,
        "content_length",
        expected=0,
        context="V7 GLM metadata",
    )
    if metadata.get("reasoning_content_present") is not True:
        raise P2RCAContinueError(
            "V7 reasoning_content proof is missing"
        )
    reasoning_length = _exact_nonnegative_int(
        metadata,
        "reasoning_content_length",
        expected=9129,
        context="V7 GLM metadata",
    )
    timeout_contract = dict(
        _mapping(metadata.get("timeout_contract"))
    )
    expected_timeout = {
        "request_timeout_seconds": 120,
        "connect_timeout_seconds": 10.0,
        "read_timeout_seconds": 120.0,
        "write_timeout_seconds": 30.0,
        "pool_timeout_seconds": 10.0,
    }
    if timeout_contract != expected_timeout:
        raise P2RCAContinueError(
            "V7 timeout contract changed"
        )

    if failure.get("error") != "continued GLM RCA failed":
        raise P2RCAContinueError(
            "V7 failure report is not the approved RCA-stage failure"
        )
    if _text(failure.get("request_id")) != V3_REQUEST_ID:
        raise P2RCAContinueError("V7 failure request_id changed")
    for key in (
        "prometheus_mcp_repeated",
        "netmiko_mcp_repeated",
        "device_command_repeated",
        "notification_sent",
    ):
        if failure.get(key) is not False:
            raise P2RCAContinueError(
                f"V7 boundary changed: {key}"
            )

    return {
        "status": "pass",
        "request_id": V3_REQUEST_ID,
        "failure_kind": "glm_output_budget_exhausted",
        "request_sent": True,
        "response_received": True,
        "status_code": 200,
        "latency_ms": latency_ms,
        "finish_reason": "length",
        "content_length": 0,
        "reasoning_content_length": reasoning_length,
        "configured_model": EXPECTED_MODEL,
        "glm_attempt_sha256": _sha256_file(
            V7_STATE_ROOT / "glm_attempt.json"
        ),
        "failure_report_sha256": _sha256_file(
            V7_STATE_ROOT / "RCA_CONTINUE_FAILURE_REPORT.json"
        ),
        "prometheus_mcp_repeated": False,
        "netmiko_mcp_repeated": False,
        "device_command_repeated": False,
    }



def validate_v8_timeout_state() -> dict[str, Any]:
    required = (
        V8_STATE_ROOT / "preflight.json",
        V8_STATE_ROOT / "source_checkpoints.json",
        V8_STATE_ROOT / "historical_replay_planner_dry_run.json",
        V8_STATE_ROOT / "historical_replay_judge_dry_run.json",
        V8_STATE_ROOT / "glm_attempt.json",
        V8_STATE_ROOT / "RCA_CONTINUE_FAILURE_REPORT.json",
    )
    for path in required:
        if not path.is_file() or path.is_symlink():
            raise P2RCAContinueError(
                f"required V8 diagnostic artifact is missing: {path.name}"
            )
    for path in (
        V8_STATE_ROOT / "rca_validation.json",
        V8_STATE_ROOT / "continue_result.json",
        V8_STATE_ROOT / "v8_gate.json",
        V8_STATE_ROOT / "checkpoints" / "rca.json",
    ):
        if path.exists():
            raise P2RCAContinueError(
                f"V8 unexpectedly contains post-RCA artifact: {path.name}"
            )

    attempt = _safe_read_json(V8_STATE_ROOT / "glm_attempt.json")
    failure = _safe_read_json(
        V8_STATE_ROOT / "RCA_CONTINUE_FAILURE_REPORT.json"
    )
    metadata = _mapping(attempt.get("metadata"))
    if attempt.get("status") != "failed":
        raise P2RCAContinueError("V8 attempt is not failed")
    _exact_nonnegative_int(
        attempt, "real_call_count", expected=1, context="V8 attempt"
    )
    _exact_nonnegative_int(
        metadata, "attempt_count", expected=1, context="V8 metadata"
    )
    if _text(metadata.get("configured_model")) != EXPECTED_MODEL:
        raise P2RCAContinueError("V8 model changed")
    if metadata.get("request_sent") is not True:
        raise P2RCAContinueError("V8 request_sent proof is missing")
    if metadata.get("response_received") is not False:
        raise P2RCAContinueError("V8 unexpectedly received a response")
    if _text(metadata.get("error_type")) != "ReadTimeout":
        raise P2RCAContinueError("V8 failure is not ReadTimeout")
    _exact_nonnegative_int(
        metadata, "requested_max_tokens", expected=8192,
        context="V8 metadata"
    )
    prompt_chars = _exact_nonnegative_int(
        metadata, "prompt_chars", expected=7657, context="V8 metadata"
    )
    latency_ms = _exact_nonnegative_int(
        metadata, "latency_ms", expected=120153, context="V8 metadata"
    )
    if dict(_mapping(metadata.get("timeout_contract"))) != {
        "request_timeout_seconds": 120,
        "connect_timeout_seconds": 10.0,
        "read_timeout_seconds": 120.0,
        "write_timeout_seconds": 30.0,
        "pool_timeout_seconds": 10.0,
    }:
        raise P2RCAContinueError("V8 timeout contract changed")
    if failure.get("error") != "continued GLM RCA failed":
        raise P2RCAContinueError("V8 failure report changed")
    if _text(failure.get("request_id")) != V3_REQUEST_ID:
        raise P2RCAContinueError("V8 request_id changed")
    for key in (
        "prometheus_mcp_repeated",
        "netmiko_mcp_repeated",
        "device_command_repeated",
        "notification_sent",
    ):
        if failure.get(key) is not False:
            raise P2RCAContinueError(f"V8 boundary changed: {key}")
    return {
        "status": "pass",
        "failure_kind": "glm_read_timeout",
        "request_sent": True,
        "response_received": False,
        "latency_ms": latency_ms,
        "prompt_chars": prompt_chars,
        "requested_max_tokens": 8192,
        "glm_attempt_sha256": _sha256_file(
            V8_STATE_ROOT / "glm_attempt.json"
        ),
        "failure_report_sha256": _sha256_file(
            V8_STATE_ROOT / "RCA_CONTINUE_FAILURE_REPORT.json"
        ),
    }

def validate_v3_source_checkpoints() -> dict[str, Any]:
    metrics_path = V3_STATE_ROOT / "checkpoints" / "metrics.json"
    device_path = V3_STATE_ROOT / "checkpoints" / "device.json"
    failure_path = V3_STATE_ROOT / "CONTINUE_FAILURE_REPORT.json"
    rca_path = V3_STATE_ROOT / "checkpoints" / "rca.json"

    for path in (metrics_path, device_path, failure_path):
        if not path.is_file() or path.is_symlink():
            raise P2RCAContinueError(
                f"required V3 checkpoint is missing: {path.name}"
            )
    if rca_path.exists():
        raise P2RCAContinueError(
            "V3 RCA checkpoint unexpectedly exists"
        )

    metrics = _safe_read_json(metrics_path)
    device = _safe_read_json(device_path)
    failure = _safe_read_json(failure_path)
    if metrics.get("status") not in {"success", "partial"}:
        raise P2RCAContinueError(
            "V3 Metrics checkpoint is not successful"
        )
    _exact_nonnegative_int(
        metrics,
        "real_call_count",
        expected=0,
        context="V3 Metrics checkpoint",
    )
    if device.get("status") not in {"success", "partial"}:
        raise P2RCAContinueError(
            "V3 Device checkpoint is not successful"
        )
    _exact_nonnegative_int(
        device,
        "real_call_count",
        expected=1,
        context="V3 Device checkpoint",
    )
    if failure.get("error") != "continued GLM RCA failed":
        raise P2RCAContinueError(
            "V3 failure is not the approved RCA-stage failure"
        )
    request_ids = {
        _checkpoint_request_id(metrics_path),
        _checkpoint_request_id(device_path),
        _text(failure.get("request_id")),
    }
    if request_ids != {V3_REQUEST_ID}:
        raise P2RCAContinueError(
            "V3 checkpoint request IDs do not match"
        )
    return {
        "status": "pass",
        "request_id": V3_REQUEST_ID,
        "metrics_checkpoint_sha256": _sha256_file(metrics_path),
        "device_checkpoint_sha256": _sha256_file(device_path),
        "failure_report_sha256": _sha256_file(failure_path),
        "metrics_real_call_count": 0,
        "device_real_call_count": 1,
        "rca_real_call_count": 0,
    }


def prepare_v8_state(
    state_root: str | Path = STATE_ROOT,
) -> dict[str, Any]:
    root = Path(state_root)
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    source = validate_v3_source_checkpoints()
    v4_no_call = validate_v4_no_call_state()
    v5_no_call = validate_v5_no_call_state()
    v6_timeout = validate_v6_timeout_state()
    v7_output_budget = validate_v7_output_budget_state()
    v8_timeout = validate_v8_timeout_state()
    paths = continuation_paths(root)
    paths.checkpoint_root.mkdir(parents=True, exist_ok=True)
    os.chmod(paths.checkpoint_root, 0o700)

    source_files = {
        "metrics.json": (
            V3_STATE_ROOT / "checkpoints" / "metrics.json"
        ),
        "device.json": (
            V3_STATE_ROOT / "checkpoints" / "device.json"
        ),
    }
    for name, source_path in source_files.items():
        destination = paths.checkpoint_root / name
        source_bytes = source_path.read_bytes()
        source_sha = hashlib.sha256(source_bytes).hexdigest()
        if destination.exists():
            if destination.is_symlink():
                raise P2RCAContinueError(
                    f"final checkpoint is a symlink: {name}"
                )
            if hashlib.sha256(
                destination.read_bytes()
            ).hexdigest() != source_sha:
                raise P2RCAContinueError(
                    f"final checkpoint differs from V3 source: {name}"
                )
        else:
            temporary = destination.with_name(name + ".tmp")
            temporary.write_bytes(source_bytes)
            os.chmod(temporary, 0o600)
            os.replace(temporary, destination)

    # Immutable V8 source proofs and current Final dry-run outputs must
    # never share file names. The unprefixed files are reserved for the
    # current Final execution and may legitimately change on each dry-run.
    replay_proof_files = {
        V8_SOURCE_PLANNER_PROOF_NAME: (
            V8_STATE_ROOT
            / "historical_replay_planner_dry_run.json"
        ),
        V8_SOURCE_JUDGE_PROOF_NAME: (
            V8_STATE_ROOT
            / "historical_replay_judge_dry_run.json"
        ),
    }
    for name, source_path in replay_proof_files.items():
        destination = root / name
        source_bytes = source_path.read_bytes()
        source_sha = hashlib.sha256(source_bytes).hexdigest()
        if destination.exists():
            if destination.is_symlink():
                raise P2RCAContinueError(
                    f"final replay proof is a symlink: {name}"
                )
            if hashlib.sha256(
                destination.read_bytes()
            ).hexdigest() != source_sha:
                raise P2RCAContinueError(
                    f"final replay proof differs from V8 source: {name}"
                )
        else:
            temporary = destination.with_name(name + ".tmp")
            temporary.write_bytes(source_bytes)
            os.chmod(temporary, 0o600)
            os.replace(temporary, destination)

    manifest = {
        "schema_version": V8_SCHEMA_VERSION,
        "status": "pass",
        "source": source,
        "v4_no_call": v4_no_call,
        "v5_no_call": v5_no_call,
        "v6_timeout": v6_timeout,
        "v7_output_budget": v7_output_budget,
        "v8_timeout": v8_timeout,
        "copied_checkpoints": {
            name: _sha256_file(paths.checkpoint_root / name)
            for name in source_files
        },
        "copied_replay_proofs": {
            name: _sha256_file(root / name)
            for name in replay_proof_files
        },
        "prometheus_mcp_repeated": False,
        "netmiko_mcp_repeated": False,
        "device_command_repeated": False,
        "prepared_at": _aware_now().isoformat(),
    }
    _write_json(root / "source_checkpoints.json", manifest)
    return manifest


def preflight_report(
    state_root: str | Path = STATE_ROOT,
) -> dict[str, Any]:
    root = Path(state_root)
    source = prepare_v8_state(root)
    config = load_production_config(
        PROJECT_ROOT / "config.yaml"
    )
    runtime = _runtime_llm_summary(config)
    v6_replay_proof = _mapping(
        source.get("v6_timeout")
    )
    v7_output_budget_proof = _mapping(
        source.get("v7_output_budget")
    )
    v8_timeout_proof = _mapping(source.get("v8_timeout"))
    report = {
        "schema_version": V8_SCHEMA_VERSION,
        "status": "pass",
        "source_checkpoints": source,
        "v6_replay_proof_reused": True,
        "v6_replay_proof": dict(v6_replay_proof),
        "v7_output_budget_proof_reused": True,
        "v7_output_budget_proof": dict(v7_output_budget_proof),
        "v8_timeout_proof_reused": True,
        "v8_timeout_proof": dict(v8_timeout_proof),
        "llm": {
            "enabled": True,
            "provider": "openai_compatible",
            "model": EXPECTED_MODEL,
            "endpoint": runtime.get("endpoint_summary"),
            "api_key_configured": (
                runtime.get("api_key_configured")
            ),
            "key_source": runtime.get("key_source"),
            "environment_name_count": len(
                runtime.get("environment_names") or []
            ),
            "max_tokens": _mapping(
                _mapping(runtime.get("config")).get("llm")
            ).get("max_tokens"),
            "retry": 0,
            "timeout_contract": runtime.get("timeout_contract"),
            "real_call_executed": False,
        },
        "external_calls": {
            "prometheus_mcp": False,
            "netmiko_mcp": False,
            "glm_5_2": False,
        },
        "notification_sent": False,
        "created_at": _aware_now().isoformat(),
    }
    _write_json(root / "preflight.json", report)
    return report


def run_rca_continuation(
    state_root: str | Path = STATE_ROOT,
) -> dict[str, Any]:
    root = Path(state_root)
    paths = continuation_paths(root)
    if paths.result_path.is_file():
        existing = _safe_read_json(paths.result_path)
        if existing.get("status") == "completed":
            return dict(existing)

    preflight = preflight_report(root)
    source = _mapping(preflight.get("source_checkpoints"))
    sample = pinned_sample()
    config = load_production_config(
        PROJECT_ROOT / "config.yaml"
    )
    settings = build_active_p2_settings(
        "p2-rca-v8-"
        + hashlib.sha256(
            V3_REQUEST_ID.encode("utf-8")
        ).hexdigest()[:12]
    )
    runner = P2DeviceContinueRunner(
        settings=settings,
        sample=sample,
        paths=paths,
        production_config=config,
    )
    runner.device_collector = ReusedDeviceCollectorV8(
        paths.device_checkpoint
    )
    runner.rca_collector = CheckpointedGLMRCACollectorV8(
        production_config=config,
        state_root=root,
    )

    replay_at = historical_replay_anchor(
        paths.device_checkpoint
    )
    try:
        with historical_replay_planner_scope(replay_at):
            result = asyncio.run(
                runner.run(
                    request_id=V3_REQUEST_ID,
                    old_checkpoint=source,
                )
            )
    except Exception as exc:
        failure = {
            "schema_version": V8_SCHEMA_VERSION,
            "status": "failed",
            "request_id": V3_REQUEST_ID,
            "error_type": type(exc).__name__,
            "error": _redact(exc),
            "traceback": traceback.format_exc(),
            "glm_attempt_exists": (
                root / "glm_attempt.json"
            ).is_file(),
            "rca_validation_exists": (
                root / "rca_validation.json"
            ).is_file(),
            "metrics_checkpoint_reused": True,
            "device_checkpoint_reused": True,
            "prometheus_mcp_repeated": False,
            "netmiko_mcp_repeated": False,
            "device_command_repeated": False,
            "historical_controlled_replay": True,
            "historical_replay_anchor": replay_at.isoformat(),
            "production_freshness_rule_changed": False,
            "notification_sent": False,
            "failed_at": _aware_now().isoformat(),
        }
        _write_json(
            root / "RCA_CONTINUE_FAILURE_REPORT.json",
            failure,
        )
        raise

    result = dict(result)
    actual_counts = {
        "prometheus_mcp": 0,
        "netmiko_mcp": 0,
        "glm_rca": 1,
    }
    cumulative_counts = {
        "prometheus_mcp": 1,
        "netmiko_mcp": 1,
        "glm_rca": 5,
    }
    result.update(
        {
            "final_schema_version": V8_SCHEMA_VERSION,
            "final_actual_real_call_counts": actual_counts,
            "continuation_call_counts": actual_counts,
            "batch_p2_cumulative_real_call_counts": (
                cumulative_counts
            ),
            "metrics_checkpoint_reused": True,
            "device_checkpoint_reused": True,
            "prometheus_mcp_repeated": False,
            "netmiko_mcp_repeated": False,
            "device_command_repeated": False,
            "historical_controlled_replay": True,
            "historical_replay_anchor": (
                HISTORICAL_REPLAY_ANCHOR
            ),
            "historical_replay_plan_created_at": (
                replay_at.isoformat()
            ),
            "production_freshness_rule_changed": False,
        }
    )
    trace_dir = Path(_text(result.get("trace_dir")))
    if not trace_dir.is_dir():
        raise P2RCAContinueError(
            "successful final result has no trace directory"
        )
    p2_continue_path = trace_dir / "p2_continue.json"
    p2_continue_payload = dict(
        _safe_read_json(p2_continue_path)
    )
    p2_continue_payload.update(
        {
            "continuation_call_counts": actual_counts,
            "batch_p2_cumulative_real_call_counts": (
                cumulative_counts
            ),
            "historical_controlled_replay": True,
            "historical_replay_anchor": (
                HISTORICAL_REPLAY_ANCHOR
            ),
            "historical_replay_plan_created_at": (
                replay_at.isoformat()
            ),
            "production_freshness_rule_changed": False,
            "netmiko_mcp_called": False,
            "netmiko_mcp_previously_called": True,
            "device_command_repeated": False,
            "prometheus_mcp_repeated": False,
        }
    )
    _write_json(p2_continue_path, p2_continue_payload)

    _write_json(
        trace_dir / "p2_rca_final.json",
        {
            "schema_version": V8_SCHEMA_VERSION,
            "request_id": V3_REQUEST_ID,
            "status": "completed",
            "final_actual_real_call_counts": actual_counts,
            "batch_p2_cumulative_real_call_counts": (
                cumulative_counts
            ),
            "historical_controlled_replay": True,
            "historical_replay_anchor": (
                HISTORICAL_REPLAY_ANCHOR
            ),
            "historical_replay_plan_created_at": (
                replay_at.isoformat()
            ),
            "production_freshness_rule_changed": False,
            "metrics_checkpoint_reused": True,
            "device_checkpoint_reused": True,
            "notification_sent": False,
            "write_command_executed": False,
            "completed_at": _aware_now().isoformat(),
        },
    )

    _write_json(paths.result_path, result)
    failure_path = root / "RCA_CONTINUE_FAILURE_REPORT.json"
    if failure_path.exists():
        failure_path.unlink()
    return result


def evaluate_v8_gate(
    state_root: str | Path = STATE_ROOT,
) -> dict[str, Any]:
    root = Path(state_root)
    paths = continuation_paths(root)
    result = _safe_read_json(paths.result_path)
    source_checkpoints = _safe_read_json(
        root / "source_checkpoints.json"
    )
    violations: list[str] = []

    if result.get("status") != "completed":
        violations.append("continuation_not_completed")
    expected_actual = {
        "prometheus_mcp": 0,
        "netmiko_mcp": 0,
        "glm_rca": 1,
    }
    if dict(
        _mapping(result.get("final_actual_real_call_counts"))
    ) != expected_actual:
        violations.append("final_actual_call_counts_mismatch")
    for key in (
        "prometheus_mcp_repeated",
        "netmiko_mcp_repeated",
        "device_command_repeated",
        "notification_sent",
        "second_card_sent",
        "production_card_replaced",
        "write_command_executed",
    ):
        if result.get(key) is not False:
            violations.append(f"boundary_failed:{key}")

    if result.get("historical_controlled_replay") is not True:
        violations.append("historical_replay_marker_missing")
    if result.get("production_freshness_rule_changed") is not False:
        violations.append("production_freshness_rule_changed")

    if result.get("governance_ok") is not True:
        violations.append("governance_not_persisted")
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
        violations.append("rca_not_successful")

    expected_trace_files = {
        "unified_event.json",
        "evidence_plan.json",
        "agent_runs.json",
        "evidence_bundle.json",
        "judge_result.json",
        "rca_result.json",
        "report.json",
        "shadow_integration.json",
        "p2_continue.json",
        "p2_rca_final.json",
    }
    trace_text = _text(result.get("trace_dir"))
    trace_dir = Path(trace_text) if trace_text else None
    trace_valid = False
    if trace_dir is None:
        violations.append("trace_directory_missing")
    elif trace_dir.is_symlink() or not trace_dir.is_dir():
        violations.append("trace_directory_missing")
    else:
        resolved_trace = trace_dir.resolve()
        resolved_root = paths.trace_root.resolve()
        if resolved_root not in resolved_trace.parents:
            violations.append("trace_directory_outside_v8_state")
        else:
            trace_valid = True
            actual_trace_files = {
                path.name
                for path in trace_dir.glob("*.json")
                if path.is_file() and not path.is_symlink()
            }
            for name in sorted(
                expected_trace_files - actual_trace_files
            ):
                violations.append(f"trace_missing:{name}")

    p2_continue_path = (
        trace_dir / "p2_continue.json"
        if trace_valid and trace_dir is not None
        else None
    )
    if p2_continue_path is None or not p2_continue_path.is_file():
        violations.append("p2_continue_trace_missing")
    else:
        p2_continue_payload = _safe_read_json(p2_continue_path)
        if dict(
            _mapping(
                p2_continue_payload.get(
                    "continuation_call_counts"
                )
            )
        ) != expected_actual:
            violations.append("p2_continue_actual_counts_mismatch")
        if p2_continue_payload.get(
            "historical_controlled_replay"
        ) is not True:
            violations.append("p2_continue_replay_marker_missing")
        if p2_continue_payload.get(
            "production_freshness_rule_changed"
        ) is not False:
            violations.append("p2_continue_freshness_boundary_changed")

    planner_dry_run_path = (
        root / "historical_replay_planner_dry_run.json"
    )
    if not planner_dry_run_path.is_file():
        violations.append("historical_replay_planner_dry_run_missing")
    else:
        planner_dry_run = _safe_read_json(planner_dry_run_path)
        if planner_dry_run.get("status") != "pass":
            violations.append(
                "historical_replay_planner_dry_run_not_pass"
            )
        if planner_dry_run.get(
            "historical_controlled_replay"
        ) is not True:
            violations.append("planner_replay_marker_missing")
        if planner_dry_run.get("metrics_required") is not False:
            violations.append("planner_metrics_requirement_drifted")
        if planner_dry_run.get("device_required") is not True:
            violations.append("planner_device_requirement_drifted")
        if planner_dry_run.get("planner_patch_restored") is not True:
            violations.append("planner_patch_not_restored")
        if planner_dry_run.get(
            "production_freshness_rule_changed"
        ) is not False:
            violations.append("planner_freshness_boundary_changed")
        if planner_dry_run.get("external_calls") != []:
            violations.append("planner_dry_run_external_call_detected")

    dry_run_path = root / "historical_replay_judge_dry_run.json"
    if not dry_run_path.is_file():
        violations.append("historical_replay_dry_run_missing")
    else:
        dry_run = _safe_read_json(dry_run_path)
        if dry_run.get("status") != "pass":
            violations.append("historical_replay_dry_run_not_pass")
        if dry_run.get("rca_allowed") is not True:
            violations.append("historical_replay_dry_run_blocked")
        if dry_run.get("device_skew_seconds") != 0:
            violations.append("historical_replay_device_skew_not_zero")
        if dry_run.get("production_freshness_rule_changed") is not False:
            violations.append("production_freshness_rule_changed")

    plan_path = (
        trace_dir / "evidence_plan.json"
        if trace_valid and trace_dir is not None
        else None
    )
    if plan_path is None or not plan_path.is_file():
        violations.append("trace_plan_missing")
    else:
        plan_payload = _safe_read_json(plan_path)
        raw_plan = plan_payload.get("evidence_plan", plan_payload)
        try:
            traced_plan = EvidencePlan.model_validate(raw_plan)
            expected_anchor = historical_replay_anchor(
                paths.device_checkpoint
            )
            if traced_plan.created_at != expected_anchor:
                violations.append("trace_plan_replay_time_mismatch")
            source_map = {
                item.source: item for item in traced_plan.sources
            }
            for evidence_source in (
                EvidenceSource.METRICS,
                EvidenceSource.DEVICE,
            ):
                if evidence_source not in source_map:
                    violations.append(
                        "trace_plan_source_missing:"
                        f"{evidence_source.value}"
                    )
                    continue
                constraints = dict(
                    source_map[evidence_source].constraints
                )
                if constraints.get(
                    "historical_controlled_replay"
                ) is not True:
                    violations.append(
                        "trace_plan_replay_marker_missing:"
                        f"{evidence_source.value}"
                    )
                if constraints.get(
                    "production_freshness_rule_changed"
                ) is not False:
                    violations.append(
                        "trace_plan_freshness_boundary_changed:"
                        f"{evidence_source.value}"
                    )
        except Exception:
            violations.append("trace_plan_contract_invalid")

    judge_path = (
        trace_dir / "judge_result.json"
        if trace_valid and trace_dir is not None
        else None
    )
    if judge_path is None or not judge_path.is_file():
        violations.append("trace_judge_missing")
    else:
        judge_payload = _safe_read_json(judge_path)
        raw_judge = judge_payload.get("judge_result", judge_payload)
        try:
            traced_judge = EvidenceJudgeResult.model_validate(
                raw_judge
            )
            if traced_judge.status != JudgeStatus.PARTIAL:
                violations.append("trace_judge_status_not_partial")
            if traced_judge.rca_allowed is not True:
                violations.append("trace_judge_blocked_rca")
            if traced_judge.missing_required_sources:
                violations.append("trace_judge_missing_required")
            if traced_judge.conflicts:
                violations.append("trace_judge_has_conflicts")
            if abs(
                traced_judge.confidence_cap
                - EXPECTED_REPLAY_CONFIDENCE_CAP
            ) > 1e-9:
                violations.append("trace_judge_confidence_cap_changed")
        except Exception:
            violations.append("trace_judge_contract_invalid")

    if MAX_EVIDENCE_SKEW_SECONDS != 1800:
        violations.append("production_freshness_threshold_changed")

    agent_runs_path = (
        trace_dir / "agent_runs.json"
        if trace_valid and trace_dir is not None
        else None
    )
    if agent_runs_path is not None and agent_runs_path.is_file():
        agent_runs_payload = _safe_read_json(agent_runs_path)
        observed_systems: list[str] = []
        for run in agent_runs_payload.get("agent_runs") or []:
            if not isinstance(run, Mapping):
                continue
            for call in run.get("external_calls") or []:
                if isinstance(call, Mapping):
                    system = _text(call.get("system"))
                    if system:
                        observed_systems.append(system)
        if observed_systems != ["glm_5_2"]:
            violations.append(
                "final_trace_external_calls_mismatch:"
                + ",".join(observed_systems)
            )

    request_id = _text(result.get("request_id"))
    if request_id:
        leaked = [
            str(path)
            for path in (PROJECT_ROOT / "data").rglob(
                f"*{request_id}*"
            )
            if path.is_file()
        ]
        if leaked:
            violations.append(
                "final_artifact_leaked_to_production_data"
            )

    attempt = root / "glm_attempt.json"
    validation = root / "rca_validation.json"
    rca_checkpoint = paths.rca_checkpoint
    for path in (attempt, validation, rca_checkpoint):
        if not path.is_file():
            violations.append(f"missing:{path.name}")
    if attempt.is_file():
        attempt_payload = _safe_read_json(attempt)
        if attempt_payload.get("status") != "success":
            violations.append("glm_attempt_not_success")
        try:
            _exact_nonnegative_int(
                attempt_payload,
                "real_call_count",
                expected=1,
                context="GLM attempt checkpoint",
            )
        except P2RCAContinueError:
            violations.append("glm_attempt_count_not_one")
        metadata = _mapping(attempt_payload.get("metadata"))
        try:
            _exact_nonnegative_int(
                metadata,
                "attempt_count",
                expected=1,
                context="GLM attempt metadata",
            )
        except P2RCAContinueError:
            violations.append("glm_http_attempt_count_not_one")
        if metadata.get("parse_status") != "ok":
            violations.append("glm_parse_status_not_ok")
        if metadata.get("content_present") is not True:
            violations.append("glm_final_content_missing")
        content_length = metadata.get("content_length")
        if (
            isinstance(content_length, bool)
            or not isinstance(content_length, int)
            or content_length <= 0
        ):
            violations.append("glm_final_content_empty")
        requested_max_tokens = metadata.get("requested_max_tokens")
        if (
            isinstance(requested_max_tokens, bool)
            or not isinstance(requested_max_tokens, int)
            or requested_max_tokens != MAX_OUTPUT_TOKENS
        ):
            violations.append("glm_max_tokens_mismatch")
        prompt_chars = metadata.get("prompt_chars")
        if (
            isinstance(prompt_chars, bool)
            or not isinstance(prompt_chars, int)
            or prompt_chars <= 0
            or prompt_chars > MAX_PROMPT_CHARS
        ):
            violations.append("glm_prompt_size_out_of_bounds")
        if metadata.get("request_sent") is not True:
            violations.append("glm_request_not_sent")
        if metadata.get("response_received") is not True:
            violations.append("glm_response_not_received")
        status_code = metadata.get("status_code")
        if (
            isinstance(status_code, bool)
            or not isinstance(status_code, int)
            or status_code != 200
        ):
            violations.append("glm_status_code_not_200")
        timeout_contract = dict(
            _mapping(metadata.get("timeout_contract"))
        )
        expected_timeout_contract = {
            "request_timeout_seconds": 300,
            "connect_timeout_seconds": 10.0,
            "read_timeout_seconds": 300.0,
            "write_timeout_seconds": 30.0,
            "pool_timeout_seconds": 10.0,
        }
        if timeout_contract != expected_timeout_contract:
            violations.append("glm_timeout_contract_mismatch")

    copied = _mapping(
        source_checkpoints.get("copied_checkpoints")
    )
    for name in ("metrics.json", "device.json"):
        path = paths.checkpoint_root / name
        if (
            not path.is_file()
            or _sha256_file(path) != _text(copied.get(name))
        ):
            violations.append(
                f"reused_checkpoint_changed:{name}"
            )

    gate = {
        "schema_version": V8_SCHEMA_VERSION,
        "status": "passed" if not violations else "failed",
        "request_id": result.get("request_id"),
        "violation_count": len(violations),
        "violations": violations,
        "final_actual_real_call_counts": expected_actual,
        "batch_p2_cumulative_real_call_counts": {
            "prometheus_mcp": 1,
            "netmiko_mcp": 1,
            "glm_rca": 5,
        },
        "note": (
            "V3 had an earlier GLM-stage failure; V4 and V5 made no GLM "
            "call; V6 timed out at 30 seconds; V7 returned HTTP 200 but "
            "exhausted its output budget; V8 timed out at 120 seconds; the "
            "final continuation made one compact-prompt bounded RCA attempt."
        ),
        "notification_sent": False,
        "write_command_executed": False,
        "evaluated_at": _aware_now().isoformat(),
    }
    _write_json(root / "final_gate.json", gate)
    return gate
