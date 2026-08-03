"""Batch P2 Device/RCA continuation with Agent-level checkpoints.

This continuation deliberately does not repeat the already completed Batch P2
control-plane apply, historical sample discovery, the first real Prometheus MCP
Canary call, or the previous 38/732/1281 test gates.

It reuses a pre-existing Prometheus evidence artifact for the pinned historical
request, runs exactly one Netmiko MCP read-only command after restoring the
missing MCP_HELPER_CMD contract, then runs exactly one GLM 5.2 RCA call. Device
and RCA results are checkpointed independently so a later-stage failure does
not repeat an already successful external call.

The module never posts to the production webhook route, never sends a
notification, never calls Evidence MCP 10002, Analytics MCP 10004, FastMCP,
OPS ES API, or Elasticsearch, and never executes a device write command.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from agent_runner.executors import run_mcp_commands_placeholder
from netaiops.plan_builder import command_is_readonly
from netaiops.safety_policy import (
    evaluate_candidate,
    safety_config,
)

from .adapters.prometheus_evidence_adapter import (
    NormalizedPrometheusEvidence,
    PrometheusEvidenceAdapter,
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
    EvidencePlan,
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
    P2CallKind,
    P2CallLedger,
    P2Settings,
)
from .p2_real_canary import (
    DANGEROUS_COMMAND_RE,
    P2CanarySample,
    P2RealCanaryError,
    RealGLMRCACollector,
    _external_record,
    _mapping,
    _netmiko_runtime,
    _notice,
    _systemd_service_environment,
    _text,
    build_active_p2_settings,
    discover_real_canary_sample,
    load_production_config,
)
from .schema_validator import (
    build_contract_ref,
    build_evidence_ref,
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


CONTINUE_SCHEMA_VERSION = "v12-p2-device-continue-3"
PROJECT_ROOT = Path("/opt/netaiops-webhook")
OLD_STATE_ROOT = Path("/tmp/netaiops_v12_p2_real_canary_state")
STATE_ROOT = Path("/tmp/netaiops_v12_p2_device_continue_v3_state")
DOCUMENTED_HELPER = Path("/opt/netaiops-mcp-helper/bridge_helper.py")
PINNED_ORIGINAL_REQUEST_ID = "20260727_145842_790277_86d84bf2"
PINNED_DEVICE_IP = "10.187.251.61"
PINNED_INTERFACE = "Ethernet1/1"
PINNED_COMMAND = "show interface Ethernet1/1"
PINNED_COMMAND_SHA256 = (
    "aa079c0d06e331e4f41e3fff733c533edf4ddb8482205773fcce842ca3f1b032"
)
PINNED_WRAPPER_SHA256 = (
    "b6e8727658e329776f91bde96f1695e2a61f2d260343a75584495f19704d0556"
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
        "p2_continue.json",
    }
)
TEXT_SECRET_RE = re.compile(
    r"""(?ix)
    (authorization|bearer|password|passwd|token|secret|api[_-]?key)
    \s*[:=]\s*([^\s,;]+)
    """
)


class P2ContinueError(RuntimeError):
    """Raised when the continuation violates a frozen boundary."""


@dataclass(frozen=True, slots=True)
class ContinuePaths:
    state_root: Path
    checkpoint_root: Path
    trace_root: Path
    governance_root: Path
    result_path: Path
    gate_path: Path
    failure_path: Path
    metrics_checkpoint: Path
    device_checkpoint: Path
    rca_checkpoint: Path
    device_attempt: Path


def continuation_paths(
    state_root: str | Path = STATE_ROOT,
) -> ContinuePaths:
    root = Path(state_root)
    checkpoint = root / "checkpoints"
    workspace = root / "workspace"
    return ContinuePaths(
        state_root=root,
        checkpoint_root=checkpoint,
        trace_root=(
            workspace
            / "data"
            / "evidence_hub"
            / "requests"
        ),
        governance_root=(
            workspace
            / "data"
            / "governance"
            / "agent_traces"
        ),
        result_path=root / "continue_result.json",
        gate_path=root / "gate.json",
        failure_path=root / "CONTINUE_FAILURE_REPORT.json",
        metrics_checkpoint=checkpoint / "metrics.json",
        device_checkpoint=checkpoint / "device.json",
        rca_checkpoint=checkpoint / "rca.json",
        device_attempt=checkpoint / "device_attempt.json",
    )


def _aware_now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_read_json(path: Path) -> Mapping[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise P2ContinueError(f"missing or unsafe JSON file: {path}")
    if path.stat().st_size > 16 * 1024 * 1024:
        raise P2ContinueError(f"JSON file too large: {path.name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise P2ContinueError(
            f"JSON file is unreadable: {path.name}"
        ) from exc
    if not isinstance(value, Mapping):
        raise P2ContinueError(
            f"JSON root must be an object: {path.name}"
        )
    return value


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(
            sanitize_sensitive_data(dict(value)),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _redact_text(value: Any, limit: int = 700) -> str:
    text = _text(value)
    text = TEXT_SECRET_RE.sub(
        lambda match: f"{match.group(1)}=[REDACTED]",
        text,
    )
    return text[:limit]


def resolve_helper_path(
    production_config: Mapping[str, Any],
) -> Path:
    service_env = _systemd_service_environment(
        {"MCP_HELPER_CMD"}
    )
    config_mcp = _mapping(production_config.get("mcp"))
    candidates = (
        _text(os.environ.get("MCP_HELPER_CMD")),
        _text(service_env.get("MCP_HELPER_CMD")),
        _text(config_mcp.get("helper_cmd")),
        str(DOCUMENTED_HELPER),
    )
    selected = next((item for item in candidates if item), "")
    if not selected:
        raise P2ContinueError("MCP_HELPER_CMD cannot be resolved")
    path = Path(selected)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    if path.is_symlink():
        raise P2ContinueError(
            "MCP helper path must not be a symlink"
        )
    path = path.resolve()
    if path != DOCUMENTED_HELPER.resolve():
        raise P2ContinueError(
            "MCP helper path differs from the documented production path"
        )
    if path.is_symlink() or not path.is_file():
        raise P2ContinueError(
            "documented MCP helper is missing or is a symlink"
        )
    if path.stat().st_size <= 0 or path.stat().st_size > 4 * 1024 * 1024:
        raise P2ContinueError("MCP helper size is outside the safe range")
    return path


def build_netmiko_runtime_v2(
    production_config: Mapping[str, Any],
) -> dict[str, str]:
    runtime = _netmiko_runtime(
        production_config,
        PROJECT_ROOT,
    )
    runtime["MCP_HELPER_CMD"] = str(
        resolve_helper_path(production_config)
    )
    return runtime


def sanitize_device_target(
    sample: P2CanarySample,
) -> dict[str, Any]:
    source = dict(sample.target_scope)
    device_ip = _text(
        source.get("device_ip")
        or source.get("ip")
    )
    interface = _text(
        source.get("interface")
        or source.get("if_name")
        or source.get("ifName")
    )
    if device_ip != PINNED_DEVICE_IP:
        raise P2ContinueError("pinned device_ip changed")
    if interface != PINNED_INTERFACE:
        raise P2ContinueError("pinned interface changed")

    target: dict[str, Any] = {
        "device_ip": device_ip,
        "ip": device_ip,
        "vendor": _text(source.get("vendor")) or "CISCO",
        "platform": _text(source.get("platform")),
        "interface": interface,
        "if_name": interface,
        "ifName": interface,
        "interface_name": interface,
        "interfaces": [interface],
        "object_name": _text(source.get("object_name")),
        "ifAlias": _text(
            source.get("ifAlias") or source.get("if_alias")
        ),
        "job": _text(source.get("job")),
        "vrf": _text(source.get("vrf")) or "default",
    }
    mcp_name = _text(source.get("mcp_device_name"))
    if mcp_name:
        target["mcp_device_name"] = mcp_name

    # Prometheus exporter identity is intentionally excluded from the Device
    # target. The Helper resolves the real device from device_ip/inventory.
    if "hostname" in target or "instance" in target:
        raise P2ContinueError(
            "sanitized Device target retained exporter identity"
        )
    return target


def pinned_sample() -> P2CanarySample:
    sample = discover_real_canary_sample(
        PROJECT_ROOT,
        preferred_request_id=PINNED_ORIGINAL_REQUEST_ID,
    )
    command = _text(sample.command_candidate.get("command"))
    if sample.original_request_id != PINNED_ORIGINAL_REQUEST_ID:
        raise P2ContinueError("pinned request changed")
    if command != PINNED_COMMAND:
        raise P2ContinueError("pinned command changed")
    if hashlib.sha256(command.encode("utf-8")).hexdigest() != (
        PINNED_COMMAND_SHA256
    ):
        raise P2ContinueError("pinned command SHA-256 changed")
    sanitize_device_target(sample)
    return sample


def validate_old_checkpoints() -> dict[str, Any]:
    apply_result = (
        OLD_STATE_ROOT / "results" / "P2_APPLY_RESULT.txt"
    )
    discovery = OLD_STATE_ROOT / "canary" / "discovery.json"
    failure = (
        OLD_STATE_ROOT / "canary" / "P2_FAILURE_REPORT.json"
    )
    directed = OLD_STATE_ROOT / "results" / "directed.log"
    all_v12 = OLD_STATE_ROOT / "results" / "all_v12.log"
    full = OLD_STATE_ROOT / "results" / "full.log"
    required = (
        apply_result,
        discovery,
        failure,
        directed,
        all_v12,
        full,
    )
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise P2ContinueError(
            "previous successful checkpoint is missing: "
            + ", ".join(missing)
        )

    if "status=PASS" not in apply_result.read_text(
        encoding="utf-8",
        errors="replace",
    ):
        raise P2ContinueError("previous P2 apply was not PASS")

    failure_data = _safe_read_json(failure)
    if failure_data.get("error") != "P2 real Device Agent failed":
        raise P2ContinueError(
            "previous failure is not the approved Device-stage failure"
        )
    if (
        _mapping(failure_data.get("sample")).get(
            "original_request_id"
        )
        != PINNED_ORIGINAL_REQUEST_ID
    ):
        raise P2ContinueError("previous failure request changed")

    expected_counts = {
        directed: 38,
        all_v12: 732,
        full: 1281,
    }
    for path, expected in expected_counts.items():
        text = path.read_text(encoding="utf-8", errors="replace")
        if f"Ran {expected} tests" not in text or "\nOK" not in text:
            raise P2ContinueError(
                f"previous test checkpoint is invalid: {path.name}"
            )

    return {
        "apply_checkpoint": True,
        "discovery_checkpoint": True,
        "previous_failure": "device_agent_failed",
        "previous_request_id": failure_data.get("request_id"),
        "previous_prometheus_stage_completed": True,
        "previous_prometheus_mcp_calls": 1,
        "previous_wrapper_invocations": 1,
        "previous_netmiko_mcp_calls": 0,
        "previous_glm_calls": 0,
        "checkpoint_sha256": {
            path.name: _sha256_file(path) for path in required
        },
    }


def load_reused_metrics(
    *,
    request_id: str,
    original_request_id: str,
) -> AgentOutcome:
    adapter = PrometheusEvidenceAdapter(
        PROJECT_ROOT / "data" / "prometheus_evidence"
    )
    normalized = adapter.load_existing(original_request_id)
    if normalized is None:
        raise P2ContinueError(
            "existing Prometheus artifact is unavailable; "
            "the continuation will not repeat the real query"
        )
    if normalized.status in {
        EvidenceStatus.FAILED,
        EvidenceStatus.NOT_AVAILABLE,
        EvidenceStatus.SKIPPED,
    }:
        raise P2ContinueError(
            "existing Prometheus artifact is not usable"
        )
    return remap_metrics_outcome(
        request_id=request_id,
        original_request_id=original_request_id,
        normalized=normalized,
    )


def remap_metrics_outcome(
    *,
    request_id: str,
    original_request_id: str,
    normalized: NormalizedPrometheusEvidence,
) -> AgentOutcome:
    digest = hashlib.sha256(
        (
            original_request_id
            + ":"
            + normalized.source_filename
        ).encode("utf-8")
    ).hexdigest()[:24]
    artifact_ref = build_contract_ref(
        "artifact",
        request_id,
        "existing_metrics_artifact",
        f"reused-{digest}",
    )
    refs: list[str] = []
    if normalized.status in {
        EvidenceStatus.SUCCESS,
        EvidenceStatus.PARTIAL,
    }:
        refs.append(
            build_evidence_ref(
                request_id,
                "metrics",
                f"reused-{digest}",
            )
        )

    warnings = list(normalized.warnings)
    warnings.append(
        ContractNotice(
            code="p2_metrics_reused_for_continuation",
            message=(
                "The Device/RCA continuation reused the existing "
                "Prometheus artifact and did not repeat MCP."
            ),
            stage="metrics_evidence",
            retryable=False,
            details={
                "original_request_id": original_request_id,
                "source_collected_at": (
                    normalized.collected_at.isoformat()
                ),
            },
        )
    )
    envelope = EvidenceEnvelope(
        schema_version="v12.1",
        request_id=request_id,
        source=EvidenceSource.METRICS,
        evidence_kind="evidence",
        status=normalized.status,
        summary=normalized.summary,
        facts={
            **dict(normalized.facts),
            "existing_artifact_reused": True,
            "real_prometheus_call_repeated": False,
            "original_request_id": original_request_id,
            "source_filename_sha256": hashlib.sha256(
                normalized.source_filename.encode("utf-8")
            ).hexdigest(),
        },
        scope=dict(normalized.scope),
        errors=list(normalized.errors),
        warnings=warnings,
        evidence_refs=refs,
        collected_at=normalized.collected_at,
        reason=normalized.reason,
    )
    agent_status = (
        AgentStatus.SUCCESS
        if normalized.status == EvidenceStatus.SUCCESS
        else AgentStatus.PARTIAL
    )
    return AgentOutcome(
        status=agent_status,
        output_refs=tuple([artifact_ref, *refs]),
        output={
            "metrics_evidence": envelope.model_dump(mode="json"),
            "existing_artifact_reused": True,
            "prometheus_mcp_called": False,
            "promql_generation_performed": False,
            "real_prometheus_call_repeated": False,
        },
        warnings=tuple(warnings),
        errors=tuple(normalized.errors),
        external_calls=(),
    )


def adjust_plan_for_continuation(
    outcome: AgentOutcome,
    metrics_artifact_ref: str,
) -> AgentOutcome:
    raw_plan = _mapping(outcome.output).get("evidence_plan")
    if not isinstance(raw_plan, Mapping):
        raise P2ContinueError("Static Planner omitted evidence_plan")
    plan = dict(raw_plan)
    sources: list[dict[str, Any]] = []
    for raw_source in plan.get("sources") or []:
        if not isinstance(raw_source, Mapping):
            continue
        source = dict(raw_source)
        name = _text(source.get("source"))
        if name == EvidenceSource.METRICS.value:
            source["required"] = False
            source["existing_artifact_refs"] = [
                metrics_artifact_ref
            ]
            constraints = dict(
                _mapping(source.get("constraints"))
            )
            constraints.update(
                {
                    "continuation_mode": (
                        "reuse_existing_artifact_without_requery"
                    ),
                    "historical_metrics_optional": True,
                }
            )
            source["constraints"] = constraints
        elif name == EvidenceSource.DEVICE.value:
            source["required"] = True
        elif name in {
            EvidenceSource.LOGS.value,
            EvidenceSource.KNOWLEDGE.value,
        }:
            source["required"] = False
        sources.append(source)
    plan["sources"] = sources
    validated = EvidencePlan.model_validate(plan)
    output = dict(outcome.output)
    output["evidence_plan"] = validated.model_dump(mode="json")
    output["p2_continuation_plan"] = {
        "metrics_required": False,
        "device_required": True,
        "real_prometheus_call_repeated": False,
    }
    return AgentOutcome(
        status=outcome.status,
        output_refs=outcome.output_refs,
        output=output,
        warnings=outcome.warnings,
        errors=outcome.errors,
        external_calls=outcome.external_calls,
    )


def serialize_outcome(
    outcome: AgentOutcome,
    *,
    checkpoint_kind: str,
    real_call_count: int,
) -> dict[str, Any]:
    return {
        "schema_version": CONTINUE_SCHEMA_VERSION,
        "checkpoint_kind": checkpoint_kind,
        "status": outcome.status.value,
        "output_refs": list(outcome.output_refs),
        "output": dict(outcome.output),
        "warnings": [
            item.model_dump(mode="json")
            for item in outcome.warnings
        ],
        "errors": [
            item.model_dump(mode="json")
            for item in outcome.errors
        ],
        "external_calls": [
            item.model_dump(mode="json")
            for item in outcome.external_calls
        ],
        "real_call_count": real_call_count,
        "written_at": _aware_now().isoformat(),
    }


def deserialize_outcome(
    payload: Mapping[str, Any],
) -> AgentOutcome:
    return AgentOutcome(
        status=AgentStatus(_text(payload.get("status"))),
        output_refs=tuple(
            _text(item)
            for item in (payload.get("output_refs") or [])
            if _text(item)
        ),
        output=dict(_mapping(payload.get("output"))),
        warnings=tuple(
            ContractNotice.model_validate(item)
            for item in (payload.get("warnings") or [])
        ),
        errors=tuple(
            ContractNotice.model_validate(item)
            for item in (payload.get("errors") or [])
        ),
        external_calls=tuple(
            ExternalCallRecord.model_validate(item)
            for item in (payload.get("external_calls") or [])
        ),
    )


def _load_checkpoint(path: Path) -> AgentOutcome | None:
    if not path.is_file():
        return None
    payload = _safe_read_json(path)
    outcome = deserialize_outcome(payload)
    if outcome.status not in {
        AgentStatus.SUCCESS,
        AgentStatus.PARTIAL,
    }:
        raise P2ContinueError(
            f"checkpoint is not successful: {path.name}"
        )
    return outcome


class ContinueNetmikoCollector:
    def __init__(
        self,
        *,
        production_config: Mapping[str, Any],
        paths: ContinuePaths,
    ) -> None:
        self.production_config = dict(production_config)
        self.paths = paths

    async def collect(
        self,
        *,
        request_id: str,
        sample: P2CanarySample,
        settings: P2Settings,
        ledger: P2CallLedger,
    ) -> AgentOutcome:
        existing = _load_checkpoint(
            self.paths.device_checkpoint
        )
        if existing is not None:
            return existing

        candidate = dict(sample.command_candidate)
        command = _text(candidate.get("command"))
        if command != PINNED_COMMAND:
            raise P2ContinueError("Device command is not pinned")
        if (
            DANGEROUS_COMMAND_RE.search(command)
            or "{" in command
            or "}" in command
            or candidate.get("readonly") is not True
            or not command_is_readonly(command)
        ):
            raise P2ContinueError(
                "Device command failed the frozen read-only boundary"
            )
        candidate["readonly"] = True
        safety = evaluate_candidate(
            candidate,
            safety_config(),
        )
        if safety.get("safe") is not True:
            raise P2ContinueError(
                "Device command failed the existing Safety Policy"
            )
        candidate["timeout_sec"] = min(
            30,
            int(
                candidate.get("timeout_sec")
                or settings.device_timeout_seconds
            ),
        )
        target = sanitize_device_target(sample)
        runtime = build_netmiko_runtime_v2(
            self.production_config
        )

        ledger.reserve(
            P2CallKind.DEVICE,
            operation_id=(
                "continued-playbook-command:"
                + PINNED_COMMAND_SHA256[:16]
            ),
            provider="netmiko-mcp-10000",
        )
        request_ref = build_contract_ref(
            "artifact",
            request_id,
            "external_request",
            "netmiko-continuation-readonly",
        )
        started_at = _aware_now()
        old_env = {
            key: os.environ.get(key) for key in runtime
        }
        try:
            os.environ.update(runtime)
            loop = asyncio.get_running_loop()
            results = await loop.run_in_executor(
                None,
                lambda: run_mcp_commands_placeholder(
                    request_id=request_id,
                    target_scope=target,
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
            raise P2ContinueError(
                "Netmiko Wrapper did not return exactly one result"
            )
        item = dict(results[0])
        status = _text(item.get("dispatch_status")).lower()
        error_text = _redact_text(item.get("error"))
        output_text = _text(item.get("output"))
        judge = dict(_mapping(item.get("judge")))
        judge_summary = {
            "final_status": judge.get("final_status"),
            "hard_error": judge.get("hard_error"),
            "matched_rule_id": judge.get("matched_rule_id"),
            "judge_reason": judge.get("judge_reason"),
        }
        diagnostic = {
            "schema_version": CONTINUE_SCHEMA_VERSION,
            "request_id": request_id,
            "dispatch_status": status or "unknown",
            "judge_final_status": judge_summary.get(
                "final_status"
            ),
            "judge_reason": judge_summary.get("judge_reason"),
            "judge_matched_rule_id": judge_summary.get(
                "matched_rule_id"
            ),
            "error_present": bool(error_text),
            "error_preview": error_text,
            "output_size_bytes": len(
                output_text.encode("utf-8")
            ),
            "output_sha256": hashlib.sha256(
                output_text.encode("utf-8")
            ).hexdigest(),
            "command_sha256": PINNED_COMMAND_SHA256,
            "target": {
                "device_ip": target.get("device_ip"),
                "interface": target.get("interface"),
                "vendor": target.get("vendor"),
                "platform": target.get("platform"),
                "hostname_present": "hostname" in target,
                "instance_present": "instance" in target,
            },
            "helper_path": str(
                resolve_helper_path(self.production_config)
            ),
            "helper_sha256": _sha256_file(
                resolve_helper_path(self.production_config)
            ),
            "write_command_executed": False,
            "recorded_at": finished_at.isoformat(),
        }
        _write_json(self.paths.device_attempt, diagnostic)

        digest = hashlib.sha256(
            (
                command
                + "\n"
                + output_text
                + "\n"
                + error_text
                + "\n"
                + stable_json_dumps(judge_summary)
            ).encode("utf-8")
        ).hexdigest()[:24]
        evidence_ref = build_evidence_ref(
            request_id,
            "device",
            f"netmiko-continue-{digest}",
        )
        response_ref = build_contract_ref(
            "artifact",
            request_id,
            "external_response",
            f"netmiko-continue-{digest}",
        )

        if status not in {"completed", "partial"}:
            error = _notice(
                "p2_continue_netmiko_failed",
                "Netmiko MCP continuation command failed",
                stage="device_evidence",
                details={
                    "dispatch_status": status or "unknown",
                    "error_present": bool(error_text),
                    "device_attempt_ref": (
                        "checkpoint://device_attempt"
                    ),
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
            return AgentOutcome(
                status=AgentStatus.FAILED,
                output={
                    "netmiko_mcp_called": True,
                    "write_command_executed": False,
                    "raw_output_forwarded": False,
                    "device_attempt_written": True,
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
                "Netmiko MCP completed the pinned existing "
                "read-only Playbook command."
            ),
            facts={
                "netmiko_mcp_called": True,
                "mcp_helper_contract_restored": True,
                "command_sha256": PINNED_COMMAND_SHA256,
                "command_prefix": "show",
                "output_size_bytes": len(
                    output_text.encode("utf-8")
                ),
                "output_sha256": hashlib.sha256(
                    output_text.encode("utf-8")
                ).hexdigest(),
                "judge": judge_summary,
                "write_command_executed": False,
                "raw_output_forwarded": False,
                "exporter_identity_removed": True,
            },
            scope=target,
            evidence_refs=[evidence_ref],
            collected_at=finished_at,
        )
        outcome = AgentOutcome(
            status=agent_status,
            output_refs=(response_ref, evidence_ref),
            output={
                "device_evidence": envelope.model_dump(mode="json"),
                "netmiko_mcp_called": True,
                "mcp_helper_contract_restored": True,
                "command_generation_performed": False,
                "write_command_executed": False,
                "raw_output_forwarded": False,
                "safety_policy_bypassed": False,
            },
            external_calls=(external,),
        )
        _write_json(
            self.paths.device_checkpoint,
            serialize_outcome(
                outcome,
                checkpoint_kind="device",
                real_call_count=1,
            ),
        )
        return outcome


class P2DeviceContinueRunner:
    def __init__(
        self,
        *,
        settings: P2Settings,
        sample: P2CanarySample,
        paths: ContinuePaths,
        production_config: Mapping[str, Any],
    ) -> None:
        self.settings = settings
        self.sample = sample
        self.paths = paths
        self.production_config = dict(production_config)
        self.device_collector = ContinueNetmikoCollector(
            production_config=self.production_config,
            paths=self.paths,
        )
        self.rca_collector = RealGLMRCACollector(
            production_config=self.production_config
        )

    async def run(
        self,
        *,
        request_id: str,
        old_checkpoint: Mapping[str, Any],
    ) -> dict[str, Any]:
        validate_request_id(request_id)
        ledger = P2CallLedger(
            settings=self.settings,
            request_id=request_id,
            family=self.sample.family,
        )
        outputs: dict[str, Mapping[str, Any]] = {}
        output_refs: list[str] = []
        runs: list[AgentRunRecord] = []
        started_clock = time.monotonic()

        metrics_checkpoint = _load_checkpoint(
            self.paths.metrics_checkpoint
        )
        if metrics_checkpoint is None:
            metrics_checkpoint = load_reused_metrics(
                request_id=request_id,
                original_request_id=(
                    self.sample.original_request_id
                ),
            )
            _write_json(
                self.paths.metrics_checkpoint,
                serialize_outcome(
                    metrics_checkpoint,
                    checkpoint_kind="metrics_reuse",
                    real_call_count=0,
                ),
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
            raise P2ContinueError(
                "metrics checkpoint artifact ref is missing"
            )

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
            AgentName.NOTIFICATION_REPORT: (
                NotificationReportAgent()
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
                request_id=request_id,
                agent_name=name,
                orchestration_state=states[name],
                prior_output_refs=tuple(output_refs),
                prior_outputs=dict(outputs),
            )
            started_at = _aware_now()
            started = time.monotonic()

            if name == AgentName.METRICS_EVIDENCE:
                outcome = metrics_checkpoint
            elif name == AgentName.DEVICE_EVIDENCE:
                outcome = await self.device_collector.collect(
                    request_id=request_id,
                    sample=self.sample,
                    settings=self.settings,
                    ledger=ledger,
                )
            elif name == AgentName.RCA:
                checkpoint = _load_checkpoint(
                    self.paths.rca_checkpoint
                )
                if checkpoint is not None:
                    outcome = checkpoint
                else:
                    outcome = await self.rca_collector.collect(
                        request_id=request_id,
                        outputs=dict(outputs),
                        output_refs=tuple(output_refs),
                        settings=self.settings,
                        ledger=ledger,
                    )
                    if outcome.status in {
                        AgentStatus.SUCCESS,
                        AgentStatus.PARTIAL,
                    }:
                        _write_json(
                            self.paths.rca_checkpoint,
                            serialize_outcome(
                                outcome,
                                checkpoint_kind="rca",
                                real_call_count=1,
                            ),
                        )
            else:
                outcome = await agents[name].run(invocation)

            if name == AgentName.STATIC_PLANNER:
                outcome = adjust_plan_for_continuation(
                    outcome,
                    metrics_artifact_ref,
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
            raise P2ContinueError("continuation Triage failed")

        planner = await invoke(AgentName.STATIC_PLANNER)
        if planner.status == AgentStatus.FAILED:
            raise P2ContinueError(
                "continuation Static Planner failed"
            )

        metrics = await invoke(AgentName.METRICS_EVIDENCE)
        if metrics.status == AgentStatus.FAILED:
            raise P2ContinueError(
                "reused Metrics checkpoint is failed"
            )

        device = await invoke(AgentName.DEVICE_EVIDENCE)
        if device.status == AgentStatus.FAILED:
            raise P2ContinueError(
                "continued Device Agent failed"
            )

        logs = await invoke(AgentName.LOGS_EVIDENCE)
        knowledge = await invoke(AgentName.KNOWLEDGE_CONTEXT)
        if (
            logs.status != AgentStatus.NOT_AVAILABLE
            or knowledge.status != AgentStatus.NOT_AVAILABLE
        ):
            raise P2ContinueError(
                "Logs/Knowledge placeholder boundary drifted"
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
            "bundle-p2-continue",
        )
        outputs["evidence_bundle"] = {
            "evidence_bundle": (
                artifacts.evidence_bundle.model_dump(mode="json")
            )
        }
        output_refs.append(bundle_ref)

        judge = await invoke(AgentName.EVIDENCE_JUDGE)
        if judge.status == AgentStatus.FAILED:
            raise P2ContinueError("continuation Judge failed")
        judge_payload = _mapping(judge.output).get(
            "judge_result"
        )
        if not isinstance(judge_payload, Mapping):
            raise P2ContinueError("Judge result is missing")
        if (
            judge_payload.get("rca_allowed") is not True
            or _text(judge_payload.get("status"))
            in {
                JudgeStatus.INSUFFICIENT.value,
                JudgeStatus.BLOCKED.value,
            }
        ):
            raise P2ContinueError(
                "continuation evidence did not allow RCA"
            )

        rca = await invoke(AgentName.RCA)
        if rca.status not in {
            AgentStatus.SUCCESS,
            AgentStatus.PARTIAL,
        }:
            raise P2ContinueError("continued GLM RCA failed")

        report = await invoke(AgentName.NOTIFICATION_REPORT)
        if report.status == AgentStatus.FAILED:
            raise P2ContinueError("continuation Report failed")
        notification = _mapping(report.output).get(
            "notification_plan"
        )
        if not isinstance(notification, Mapping):
            raise P2ContinueError(
                "notification plan is missing"
            )
        if (
            notification.get("send_notification") is not False
            or int(notification.get("notification_count", -1)) != 0
            or notification.get("second_card_sent") is not False
            or notification.get("production_card_replaced") is not False
        ):
            raise P2ContinueError(
                "notification boundary drifted"
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
        stored = AgentTraceStore(self.paths.trace_root).persist(
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
            raise P2ContinueError(
                "supplemental trace contracts are missing"
            )

        if not self.paths.device_checkpoint.is_file():
            raise P2ContinueError(
                "successful Device checkpoint is missing"
            )
        if not self.paths.rca_checkpoint.is_file():
            raise P2ContinueError(
                "successful RCA checkpoint is missing"
            )
        device_checkpoint_payload = _safe_read_json(
            self.paths.device_checkpoint
        )
        rca_checkpoint_payload = _safe_read_json(
            self.paths.rca_checkpoint
        )
        if int(
            device_checkpoint_payload.get(
                "real_call_count"
            )
            or 0
        ) != 1:
            raise P2ContinueError(
                "Device checkpoint call count is not one"
            )
        if int(
            rca_checkpoint_payload.get(
                "real_call_count"
            )
            or 0
        ) != 1:
            raise P2ContinueError(
                "RCA checkpoint call count is not one"
            )

        continuation_counts = {
            "prometheus_mcp": 0,
            "netmiko_mcp": 1,
            "glm_rca": 1,
        }
        cumulative_counts = {
            "prometheus_mcp": 1,
            "netmiko_mcp": 1,
            "glm_rca": 1,
        }
        continue_payload = {
            "schema_version": CONTINUE_SCHEMA_VERSION,
            "request_id": request_id,
            "status": "completed",
            "family": self.sample.family,
            "original_request_id": (
                self.sample.original_request_id
            ),
            "previous_checkpoint": dict(old_checkpoint),
            "metrics_existing_artifact_reused": True,
            "metrics_source_collected_at": (
                _mapping(
                    _mapping(metrics.output).get(
                        "metrics_evidence"
                    )
                ).get("collected_at")
            ),
            "continuation_call_counts": continuation_counts,
            "batch_p2_cumulative_real_call_counts": (
                cumulative_counts
            ),
            "current_run_ledger": ledger.snapshot(),
            "judge_status": judge_payload.get("status"),
            "rca_status": rca_payload.get("status"),
            "logs_status": logs.status.value,
            "knowledge_status": knowledge.status.value,
            "notification_sent": False,
            "notification_count": 0,
            "second_card_sent": False,
            "production_card_replaced": False,
            "prometheus_mcp_repeated": False,
            "netmiko_mcp_called": True,
            "production_glm_called": True,
            "evidence_mcp_called": False,
            "analytics_mcp_called": False,
            "fastmcp_called": False,
            "ops_es_api_called": False,
            "elasticsearch_called": False,
            "write_command_executed": False,
            "command_generation_performed": False,
            "promql_generation_performed": False,
            "automatic_followup_queries": False,
            "trace_written": True,
            "governance_written": True,
            "service_restart": False,
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
                    "schema_version": (
                        CONTINUE_SCHEMA_VERSION
                    ),
                    "request_id": request_id,
                    "status": "completed",
                    "mode": (
                        "manual_device_rca_continuation"
                    ),
                    "legacy_preserved": True,
                    "notification_sent": False,
                    "trace_written": True,
                },
                "p2_continue.json": continue_payload,
            }
        )
        governance = AgentTraceGovernanceAdapter(
            trace_service=AgentTraceReadService(
                self.paths.trace_root
            ),
            governance_root=self.paths.governance_root,
        ).persist_for_request_safe(request_id)
        if governance.get("ok") is not True:
            raise P2ContinueError(
                "isolated Governance persistence failed"
            )

        actual_files = {
            path.name
            for path in stored.directory.glob("*.json")
            if path.is_file()
        }
        missing = sorted(EXPECTED_TRACE_FILES - actual_files)
        if missing:
            raise P2ContinueError(
                "continuation trace is incomplete: "
                + ", ".join(missing)
            )

        return {
            **continue_payload,
            "trace_dir": str(stored.directory),
            "governance_ok": True,
        }


def _mapping_ref_kind(reference: str) -> str:
    try:
        from .schema_validator import parse_contract_ref

        return parse_contract_ref(reference)["kind"]
    except Exception:
        return ""


def preflight_report(
    *,
    state_root: str | Path = STATE_ROOT,
) -> dict[str, Any]:
    paths = continuation_paths(state_root)
    paths.state_root.mkdir(parents=True, exist_ok=True)
    os.chmod(paths.state_root, 0o700)
    old = validate_old_checkpoints()
    sample = pinned_sample()
    production_config = load_production_config(
        PROJECT_ROOT / "config.yaml"
    )
    helper = resolve_helper_path(production_config)
    wrapper = Path(
        build_netmiko_runtime_v2(
            production_config
        )["MCP_WRAPPER_CMD"]
    )
    if _sha256_file(wrapper) != PINNED_WRAPPER_SHA256:
        raise P2ContinueError(
            "Netmiko Wrapper SHA-256 differs from the collected baseline"
        )

    adapter = PrometheusEvidenceAdapter(
        PROJECT_ROOT / "data" / "prometheus_evidence"
    )
    normalized = adapter.load_existing(
        PINNED_ORIGINAL_REQUEST_ID
    )
    if normalized is None:
        raise P2ContinueError(
            "existing Prometheus artifact is missing"
        )
    if normalized.status in {
        EvidenceStatus.FAILED,
        EvidenceStatus.NOT_AVAILABLE,
        EvidenceStatus.SKIPPED,
    }:
        raise P2ContinueError(
            "existing Prometheus artifact is unusable"
        )

    target = sanitize_device_target(sample)
    report = {
        "schema_version": CONTINUE_SCHEMA_VERSION,
        "status": "pass",
        "previous_checkpoints": old,
        "sample": {
            "original_request_id": sample.original_request_id,
            "family": sample.family,
            "device_ip": target["device_ip"],
            "interface": target["interface"],
            "command_sha256": PINNED_COMMAND_SHA256,
            "exporter_hostname_removed": (
                "hostname" not in target
            ),
            "exporter_instance_removed": (
                "instance" not in target
            ),
        },
        "metrics_reuse": {
            "status": normalized.status.value,
            "source_filename_sha256": hashlib.sha256(
                normalized.source_filename.encode("utf-8")
            ).hexdigest(),
            "source_collected_at": (
                normalized.collected_at.isoformat()
            ),
            "real_prometheus_call_repeated": False,
        },
        "netmiko": {
            "wrapper_path": str(wrapper),
            "wrapper_sha256": _sha256_file(wrapper),
            "helper_path": str(helper),
            "helper_sha256": _sha256_file(helper),
            "helper_size": helper.stat().st_size,
            "server_url": build_netmiko_runtime_v2(
                production_config
            )["MCP_SERVER_URL"],
            "device_command_executed": False,
        },
        "real_calls": {
            "prometheus_mcp": False,
            "netmiko_mcp": False,
            "glm_5_2": False,
        },
        "notification_sent": False,
        "created_at": _aware_now().isoformat(),
    }
    _write_json(paths.state_root / "preflight.json", report)
    return report


def run_continuation(
    *,
    state_root: str | Path = STATE_ROOT,
) -> dict[str, Any]:
    paths = continuation_paths(state_root)
    if paths.result_path.is_file():
        result = _safe_read_json(paths.result_path)
        if result.get("status") == "completed":
            return dict(result)

    preflight = preflight_report(state_root=state_root)
    old_checkpoint = _mapping(
        preflight.get("previous_checkpoints")
    )
    sample = pinned_sample()
    production_config = load_production_config(
        PROJECT_ROOT / "config.yaml"
    )

    prior_request_id = ""
    if paths.device_checkpoint.is_file():
        payload = _safe_read_json(paths.device_checkpoint)
        output = _mapping(payload.get("output"))
        envelope = _mapping(output.get("device_evidence"))
        prior_request_id = _text(envelope.get("request_id"))
    if not prior_request_id and paths.metrics_checkpoint.is_file():
        payload = _safe_read_json(paths.metrics_checkpoint)
        output = _mapping(payload.get("output"))
        envelope = _mapping(output.get("metrics_evidence"))
        prior_request_id = _text(envelope.get("request_id"))

    request_id = prior_request_id or (
        "p2-continue-"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + hashlib.sha256(
            PINNED_ORIGINAL_REQUEST_ID.encode("utf-8")
        ).hexdigest()[:10]
    )
    settings = build_active_p2_settings(
        "p2-device-continue-"
        + hashlib.sha256(
            request_id.encode("utf-8")
        ).hexdigest()[:12]
    )
    runner = P2DeviceContinueRunner(
        settings=settings,
        sample=sample,
        paths=paths,
        production_config=production_config,
    )
    try:
        result = asyncio.run(
            runner.run(
                request_id=request_id,
                old_checkpoint=old_checkpoint,
            )
        )
    except Exception as exc:
        failure = {
            "schema_version": CONTINUE_SCHEMA_VERSION,
            "status": "failed",
            "request_id": request_id,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "traceback": traceback.format_exc(),
            "device_attempt": (
                dict(_safe_read_json(paths.device_attempt))
                if paths.device_attempt.is_file()
                else None
            ),
            "metrics_checkpoint_exists": (
                paths.metrics_checkpoint.is_file()
            ),
            "device_checkpoint_exists": (
                paths.device_checkpoint.is_file()
            ),
            "rca_checkpoint_exists": (
                paths.rca_checkpoint.is_file()
            ),
            "prometheus_mcp_repeated": False,
            "notification_sent": False,
            "write_command_executed": False,
            "failed_at": _aware_now().isoformat(),
        }
        _write_json(paths.failure_path, failure)
        raise

    _write_json(paths.result_path, result)
    if paths.failure_path.is_file():
        paths.failure_path.unlink()
    return result


def evaluate_gate(
    *,
    state_root: str | Path = STATE_ROOT,
) -> dict[str, Any]:
    paths = continuation_paths(state_root)
    result = _safe_read_json(paths.result_path)
    violations: list[str] = []

    if result.get("status") != "completed":
        violations.append("continuation_not_completed")
    if result.get("prometheus_mcp_repeated") is not False:
        violations.append("prometheus_mcp_was_repeated")
    if result.get("notification_sent") is not False:
        violations.append("notification_sent")
    if result.get("second_card_sent") is not False:
        violations.append("second_card_sent")
    if result.get("production_card_replaced") is not False:
        violations.append("production_card_replaced")
    if result.get("write_command_executed") is not False:
        violations.append("write_command_executed")
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

    continuation_counts = _mapping(
        result.get("continuation_call_counts")
    )
    expected_continuation = {
        "prometheus_mcp": 0,
        "netmiko_mcp": 1,
        "glm_rca": 1,
    }
    if dict(continuation_counts) != expected_continuation:
        violations.append(
            "continuation_call_counts_mismatch"
        )

    cumulative = _mapping(
        result.get("batch_p2_cumulative_real_call_counts")
    )
    expected_cumulative = {
        "prometheus_mcp": 1,
        "netmiko_mcp": 1,
        "glm_rca": 1,
    }
    if dict(cumulative) != expected_cumulative:
        violations.append("batch_p2_call_counts_mismatch")

    preflight_path = paths.state_root / "preflight.json"
    if not preflight_path.is_file():
        violations.append("preflight_checkpoint_missing")
    else:
        preflight = _safe_read_json(preflight_path)
        expected_hashes = _mapping(
            _mapping(
                preflight.get("previous_checkpoints")
            ).get("checkpoint_sha256")
        )
        old_files = (
            OLD_STATE_ROOT / "results" / "P2_APPLY_RESULT.txt",
            OLD_STATE_ROOT / "canary" / "discovery.json",
            OLD_STATE_ROOT / "canary" / "P2_FAILURE_REPORT.json",
            OLD_STATE_ROOT / "results" / "directed.log",
            OLD_STATE_ROOT / "results" / "all_v12.log",
            OLD_STATE_ROOT / "results" / "full.log",
        )
        for path in old_files:
            expected = _text(expected_hashes.get(path.name))
            if (
                not path.is_file()
                or not expected
                or _sha256_file(path) != expected
            ):
                violations.append(
                    f"previous_checkpoint_changed:{path.name}"
                )

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
        leaked = [
            str(path)
            for path in (PROJECT_ROOT / "data").rglob(
                f"*{request_id}*"
            )
            if path.is_file()
        ]
        if leaked:
            violations.append(
                "continuation_artifact_leaked_to_production_data"
            )

    gate = {
        "schema_version": CONTINUE_SCHEMA_VERSION,
        "status": "passed" if not violations else "failed",
        "request_id": request_id,
        "violation_count": len(violations),
        "violations": violations,
        "continuation_call_counts": dict(
            continuation_counts
        ),
        "batch_p2_cumulative_real_call_counts": dict(
            cumulative
        ),
        "prometheus_mcp_repeated": result.get(
            "prometheus_mcp_repeated"
        ),
        "notification_sent": result.get(
            "notification_sent"
        ),
        "write_command_executed": result.get(
            "write_command_executed"
        ),
        "evaluated_at": _aware_now().isoformat(),
    }
    _write_json(paths.gate_path, gate)
    return gate
