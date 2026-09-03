"""V13 production integration for the frozen interface-family migration.

This module mounts the already validated D1-D3 contracts into the existing
production pipeline without replacing lower clients/runners or the legacy
notification owner.  Runtime activation is controlled only by the ignored
``data/v13/release_control.json`` file.

Frozen boundaries:
- Triage is the sole upper Family Registry owner when mounted.
- Metrics/Device ownership is active only for the three migrated families.
- Existing Prometheus sidecar and Netmiko executor remain lower infrastructure.
- No arbitrary PromQL/CLI generation is introduced.
- Legacy notification/review remains unchanged in v13.
- Failed/attempted owner calls are fenced from legacy duplicate real calls.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import yaml

from agent_runner.executors import execute_commands
from netaiops.plan_builder import command_is_readonly
from netaiops.safety_policy import evaluate_candidate, evaluate_plan_safety, safety_config
from netaiops.v12.atomic_writer import AtomicJsonWriter
from netaiops.v12.contracts import ContractNotice, EvidenceEnvelope
from netaiops.v12.p2_real_canary import _netmiko_runtime
from netaiops.v12.schema_validator import sanitize_sensitive_data, stable_json_dumps, validate_request_id
from netaiops.v12.status import EvidenceSource, EvidenceStatus

from .capability_broker import EvidenceCapabilityBroker
from .capability_contracts import (
    DeviceCapabilityRequest,
    build_plan_fingerprint,
    build_template_fingerprint,
)
from .evidence_owner_builders import (
    EvidenceOwnerBuildError,
    build_metrics_request,
    plan_family,
    validate_device_target,
)
from .evidence_owners import DeviceEvidenceOwner, MetricsEvidenceOwner
from .legacy_call_fence import LegacyCallFence
from .production_control import load_release_control, owner_active_for_family, triage_mounted
from .real_owner_adapters import bind_d3_netmiko_helper
from .triage_owner import TriageOwner


DEFAULT_PROJECT_ROOT = Path("/opt/netaiops-webhook")
CHECKPOINT_REL = Path("data/v13/capability_checkpoints")
EVIDENCE_REQUEST_REL = Path("data/evidence_hub/requests")
DEVICE_RESULT_REL = Path("data/v13/device_owner_results")
TRIAGE_ARTIFACT_NAME = "production_triage_owner.json"
DEVICE_RESULT_NAME = "command_results.json"


class V13ProductionIntegrationError(RuntimeError):
    """Raised when production ownership cannot be mounted safely."""


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _project_root(project_root: str | Path = DEFAULT_PROJECT_ROOT) -> Path:
    root = Path(project_root).resolve()
    if not root.is_dir() or root.is_symlink():
        raise V13ProductionIntegrationError("project root is not a safe directory")
    return root


def _request_v13_dir(root: Path, request_id: str) -> Path:
    validate_request_id(request_id)
    return root / EVIDENCE_REQUEST_REL / request_id / "v13"


def _checkpoint_root(root: Path) -> Path:
    return root / CHECKPOINT_REL


def _fence(root: Path) -> LegacyCallFence:
    return LegacyCallFence(root / EVIDENCE_REQUEST_REL)


def _load_runtime_config(root: Path) -> dict[str, Any]:
    path = root / "config.yaml"
    if path.is_symlink() or not path.is_file():
        raise V13ProductionIntegrationError("production config.yaml is unavailable")
    value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(value, dict):
        raise V13ProductionIntegrationError("production config root is not a mapping")
    return value


def _safe_json_file(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise V13ProductionIntegrationError(f"runtime artifact is unavailable: {path.name}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise V13ProductionIntegrationError(f"runtime artifact root is invalid: {path.name}")
    return value


def mount_triage_for_normalized_events(
    *,
    request_id: str,
    source: str,
    normalized_events: list[dict[str, Any]],
    project_root: str | Path = DEFAULT_PROJECT_ROOT,
) -> dict[str, Any]:
    """Persist one canonical Triage ownership record before legacy analysis.

    Multi-event batches remain explicit legacy fallback in v13; automatic
    aggregation is intentionally not introduced.
    """

    root = _project_root(project_root)
    control = load_release_control(root)
    if not triage_mounted(control):
        return {
            "handled": False,
            "reason": "v13_triage_not_mounted",
            "external_calls_performed": False,
        }
    if not isinstance(normalized_events, list) or len(normalized_events) != 1:
        return {
            "handled": False,
            "reason": "v13_single_event_required_fallback_legacy",
            "event_count": len(normalized_events) if isinstance(normalized_events, list) else 0,
            "external_calls_performed": False,
        }
    event = normalized_events[0]
    if not isinstance(event, Mapping) or not event:
        return {
            "handled": False,
            "reason": "v13_normalized_event_invalid_fallback_legacy",
            "external_calls_performed": False,
        }

    owner = TriageOwner()
    record = owner.classify_normalized(
        request_id=request_id,
        source=source,
        normalized_event=dict(event),
        mode="store_only",
    )
    writer = AtomicJsonWriter(_request_v13_dir(root, request_id))
    persisted = record.model_dump(mode="json")
    persisted.update(
        {
            "production_mounted": True,
            "production_control_mode": control.get("mode"),
            "production_owner_real_calls_enabled": bool(control.get("owner_real_calls_enabled")),
            "production_mounted_at": _now().isoformat(),
        }
    )
    path = writer.write_json(TRIAGE_ARTIFACT_NAME, persisted)
    return {
        "handled": True,
        "reason": "v13_triage_owner_mounted",
        "family": record.family,
        "migrated_family": record.migrated_family,
        "routing_action": record.routing_action,
        "classification_owner": record.classification_owner,
        "classification_owner_count": record.classification_owner_count,
        "classification_call_count": record.classification_call_count,
        "artifact": str(path),
        "external_calls_performed": False,
    }


def load_canonical_family_result(
    request_id: str,
    *,
    project_root: str | Path = DEFAULT_PROJECT_ROOT,
) -> dict[str, Any] | None:
    """Load the canonical Family Registry output produced by V13 Triage."""

    root = _project_root(project_root)
    path = _request_v13_dir(root, request_id) / TRIAGE_ARTIFACT_NAME
    if not path.exists():
        return None
    payload = _safe_json_file(path)
    family_result = payload.get("family_result")
    family = _text(payload.get("family"))
    if not isinstance(family_result, dict) or not family:
        raise V13ProductionIntegrationError("triage owner artifact has no canonical family_result")
    if _text(family_result.get("family")) != family:
        raise V13ProductionIntegrationError("triage owner family_result is inconsistent")
    return dict(family_result)


def legacy_source_action(
    request_id: str,
    source: str,
    *,
    project_root: str | Path = DEFAULT_PROJECT_ROOT,
) -> str:
    root = _project_root(project_root)
    if source not in {"metrics", "device"}:
        raise ValueError("legacy source must be metrics or device")
    return _fence(root).legacy_action(request_id, source)  # type: ignore[arg-type]


def _metrics_envelope_from_sidecar(
    request_id: str,
    family: str,
    result: Mapping[str, Any],
) -> EvidenceEnvelope:
    record = dict(_mapping(result.get("record")))
    evidences = [dict(x) for x in (record.get("evidences") or []) if isinstance(x, Mapping)]
    ok_count = sum(1 for item in evidences if bool(item.get("ok")))
    total_count = len(evidences)
    skipped = bool(result.get("skipped"))
    error_present = bool(result.get("error")) or _text(record.get("status")) == "sidecar_exception"

    if bool(result.get("ok")) and ok_count > 0:
        status = EvidenceStatus.SUCCESS
        summary = "V13 Metrics owner completed the approved Prometheus sidecar evidence collection."
        reason = None
        notices: list[ContractNotice] = []
    elif skipped:
        status = EvidenceStatus.NOT_AVAILABLE
        summary = "V13 Metrics owner found Prometheus sidecar evidence unavailable for this plan."
        reason = "prometheus_sidecar_not_available"
        notices = [
            ContractNotice(
                code="v13_metrics_sidecar_not_available",
                message="Prometheus sidecar was not eligible or enabled for this request.",
                stage="v13_metrics_owner",
                retryable=False,
                details={"record_status": _text(record.get("status"))},
            )
        ]
    elif error_present:
        status = EvidenceStatus.FAILED
        summary = "V13 Metrics owner observed a Prometheus sidecar execution failure."
        reason = "prometheus_sidecar_failed"
        notices = [
            ContractNotice(
                code="v13_metrics_sidecar_failed",
                message="Prometheus sidecar execution failed under the Metrics owner.",
                stage="v13_metrics_owner",
                retryable=False,
                details={"record_status": _text(record.get("status")), "error_present": True},
            )
        ]
    else:
        status = EvidenceStatus.NO_DATA
        summary = "V13 Metrics owner completed the approved Prometheus sidecar but no usable evidence was produced."
        reason = "prometheus_sidecar_no_data"
        notices = [
            ContractNotice(
                code="v13_metrics_sidecar_no_data",
                message="Prometheus sidecar completed without usable evidence.",
                stage="v13_metrics_owner",
                retryable=False,
                details={"record_status": _text(record.get("status"))},
            )
        ]

    kwargs: dict[str, Any] = {}
    if status == EvidenceStatus.FAILED:
        kwargs["errors"] = notices
    elif notices:
        kwargs["warnings"] = notices

    return EvidenceEnvelope(
        schema_version="v12.1",
        request_id=request_id,
        source=EvidenceSource.METRICS,
        evidence_kind="evidence",
        status=status,
        summary=summary,
        facts={
            "family": family,
            "owner": "metrics_agent",
            "legacy_sidecar_reused_as_lower_infrastructure": True,
            "prometheus_mcp_candidate_count": total_count,
            "successful_evidence_count": ok_count,
            "arbitrary_promql_generated": False,
        },
        scope={"family": family},
        collected_at=_now(),
        reason=reason,
        **kwargs,
    )


def run_metrics_owner_for_plan_result(
    *,
    request_id: str,
    plan_result: dict[str, Any],
    project_root: str | Path = DEFAULT_PROJECT_ROOT,
) -> dict[str, Any]:
    """Let Metrics Agent own the existing lower Prometheus sidecar call."""

    root = _project_root(project_root)
    plan_data = dict(_mapping(plan_result.get("plan_data")))
    if not plan_data:
        return {"handled": False, "reason": "plan_data_missing", "plan_result": plan_result}
    try:
        family = plan_family(plan_data)
    except EvidenceOwnerBuildError:
        return {"handled": False, "reason": "family_not_migrated", "plan_result": plan_result}
    control = load_release_control(root)
    if not owner_active_for_family(family, control):
        return {"handled": False, "reason": "metrics_owner_not_active_for_family", "family": family, "plan_result": plan_result}

    try:
        request = build_metrics_request(request_id=request_id, plan=plan_data, max_attempts=1)
    except Exception as exc:
        return {
            "handled": False,
            "reason": "metrics_owner_contract_not_buildable_fail_open_legacy",
            "family": family,
            "exception_type": type(exc).__name__,
            "plan_result": plan_result,
        }

    broker = EvidenceCapabilityBroker(_checkpoint_root(root))
    owner = MetricsEvidenceOwner(broker=broker, fence=_fence(root))
    sidecar_holder: dict[str, Any] = {}

    def executor(_request, attempt: int) -> EvidenceEnvelope:
        if attempt != 1:
            raise V13ProductionIntegrationError("production Metrics owner retry budget exceeded")
        from netaiops.prometheus_runtime_sidecar import run_prometheus_evidence_sidecar_for_plan_result

        sidecar = run_prometheus_evidence_sidecar_for_plan_result(
            request_id=request_id,
            plan_result=plan_result,
            write_record=True,
            update_plan=True,
            force=False,
            v13_owner_call=True,
        )
        sidecar_holder["result"] = sidecar
        return _metrics_envelope_from_sidecar(request_id, family, sidecar)

    try:
        outcome = owner.execute(request, executor)
    except Exception as exc:
        # If the owner already fenced this source, the external-call boundary
        # is ambiguous/attempted and legacy must never issue a duplicate call.
        if _fence(root).legacy_action(request_id, "metrics") == "skip_duplicate":
            return {
                "handled": True,
                "reason": "v13_metrics_owner_exception_after_fence_no_legacy_retry",
                "family": family,
                "owner": "metrics_agent",
                "exception_type": type(exc).__name__,
                "legacy_action": "skip_duplicate",
                "plan_result": plan_result,
                "legacy_compatible_sidecar_result": {
                    "ok": False,
                    "skipped": True,
                    "request_id": request_id,
                    "record": {"status": "v13_owner_exception_after_fence"},
                    "plan_result": plan_result,
                    "error": "v13_metrics_owner_exception_after_fence",
                },
            }
        return {
            "handled": False,
            "reason": "v13_metrics_owner_exception_before_fence_fail_open_legacy",
            "family": family,
            "exception_type": type(exc).__name__,
            "plan_result": plan_result,
        }

    # The sidecar writes its legacy-compatible metadata back to the plan file.
    # On checkpoint reuse, reload that persisted plan instead of invoking MCP.
    current_plan_result = plan_result
    if outcome.owner_record.decision_action == "reused_checkpoint":
        try:
            from netaiops.plan_builder import get_plan_by_request_id
            current_plan_result = get_plan_by_request_id(request_id)
        except Exception:
            current_plan_result = plan_result

    sidecar_result = sidecar_holder.get("result")
    if not isinstance(sidecar_result, dict):
        sidecar_result = {
            "ok": outcome.owner_record.evidence_status in {EvidenceStatus.SUCCESS, EvidenceStatus.PARTIAL},
            "skipped": outcome.owner_record.evidence_status == EvidenceStatus.NOT_AVAILABLE,
            "request_id": request_id,
            "record": {
                "status": "reused_checkpoint",
                "owner": "metrics_agent",
                "evidence_status": outcome.owner_record.evidence_status.value,
            },
            "plan_result": current_plan_result,
            "error": None,
        }

    return {
        "handled": True,
        "reason": "v13_metrics_owner_active",
        "family": family,
        "owner": outcome.owner_record.owner,
        "owner_count": outcome.owner_record.owner_count,
        "decision_action": outcome.owner_record.decision_action,
        "evidence_status": outcome.owner_record.evidence_status.value,
        "external_call_performed": outcome.owner_record.external_call_performed,
        "legacy_action": outcome.fence_record.legacy_action,
        "plan_result": current_plan_result,
        "legacy_compatible_sidecar_result": sidecar_result,
    }


def _validated_device_candidates(plan: Mapping[str, Any]) -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
    if _text(plan.get("execution_source")) != "playbook":
        raise V13ProductionIntegrationError("Device owner requires a matched Playbook execution source")
    playbook = dict(_mapping(plan.get("playbook")))
    if playbook.get("matched") is not True:
        raise V13ProductionIntegrationError("Device owner requires a matched Playbook")
    playbook_id = _text(playbook.get("playbook_id"))
    if not playbook_id:
        raise V13ProductionIntegrationError("Device owner Playbook id is missing")
    target = validate_device_target(_mapping(plan.get("target_scope")))

    candidates = [dict(x) for x in (plan.get("execution_candidates") or []) if isinstance(x, Mapping)]
    if not candidates:
        raise V13ProductionIntegrationError("Device owner plan has no execution candidates")
    if len(candidates) > 5:
        raise V13ProductionIntegrationError("Device owner candidate budget exceeds five commands")

    approved: list[dict[str, Any]] = []
    cfg = safety_config()
    for item in candidates:
        command = _text(item.get("command"))
        if not command or "{" in command or "}" in command:
            raise V13ProductionIntegrationError("Device owner rejected unresolved command material")
        if item.get("readonly") is not True or not command_is_readonly(command):
            raise V13ProductionIntegrationError("Device owner rejected non-readonly command material")
        candidate = dict(item)
        candidate["readonly"] = True
        if not evaluate_candidate(candidate, cfg).get("safe"):
            raise V13ProductionIntegrationError("Device owner Safety Policy rejected a command")
        approved.append(candidate)

    bounded_plan = dict(plan)
    bounded_plan["execution_candidates"] = approved
    if not evaluate_plan_safety(bounded_plan).get("allowed"):
        raise V13ProductionIntegrationError("Device owner plan-level Safety Policy rejected execution")
    return playbook_id, target, approved


def _device_batch_request(
    *,
    request_id: str,
    plan: Mapping[str, Any],
    family: str,
    playbook_id: str,
    target: Mapping[str, Any],
    candidates: list[Mapping[str, Any]],
) -> DeviceCapabilityRequest:
    command_material = [
        {
            "order": int(item.get("order") or index),
            "capability": _text(item.get("capability")) or "playbook_readonly_command",
            "sha256": hashlib.sha256(_text(item.get("command")).encode("utf-8")).hexdigest(),
        }
        for index, item in enumerate(candidates, start=1)
    ]
    template_id = f"playbook:{playbook_id}:readonly-batch"
    return DeviceCapabilityRequest(
        request_id=request_id,
        family=family,
        capability="playbook_readonly_batch",
        target=dict(target),
        plan_fingerprint=build_plan_fingerprint(dict(plan)),
        template_fingerprint=build_template_fingerprint(
            template_id,
            {"playbook_id": playbook_id, "commands": command_material},
        ),
        required=True,
        max_attempts=1,
        command_template_id=template_id,
        playbook_id=playbook_id,
        readonly_only=True,
        command_generation_allowed=False,
        safety_policy_allowed=True,
        safety_policy_reasons=[],
    )


def _device_result_dir(root: Path, request_id: str) -> Path:
    validate_request_id(request_id)
    path = root / DEVICE_RESULT_REL / request_id
    if path.exists() and path.is_symlink():
        raise V13ProductionIntegrationError("device owner result directory is a symlink")
    return path


def _persist_device_results(
    root: Path,
    request_id: str,
    payload: Mapping[str, Any],
) -> Path:
    writer = AtomicJsonWriter(_device_result_dir(root, request_id))
    return writer.write_json(DEVICE_RESULT_NAME, dict(payload))


def load_device_owner_command_results(
    request_id: str,
    *,
    project_root: str | Path = DEFAULT_PROJECT_ROOT,
    wait_seconds: float = 0.0,
) -> dict[str, Any] | None:
    root = _project_root(project_root)
    path = _device_result_dir(root, request_id) / DEVICE_RESULT_NAME
    deadline = time.monotonic() + max(0.0, float(wait_seconds))
    while True:
        if path.exists():
            return _safe_json_file(path)
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.1)


def _device_envelope(
    *,
    request_id: str,
    family: str,
    target: Mapping[str, Any],
    results: list[Mapping[str, Any]],
) -> EvidenceEnvelope:
    completed = sum(1 for item in results if _text(item.get("dispatch_status")).lower() == "completed")
    failed = sum(1 for item in results if _text(item.get("dispatch_status")).lower() == "failed")
    partial = max(0, len(results) - completed - failed)
    hard_errors = sum(
        1
        for item in results
        if bool(dict(_mapping(item.get("judge"))).get("hard_error"))
    )
    if results and failed == 0 and partial == 0:
        status = EvidenceStatus.SUCCESS
        summary = "V13 Device owner completed the approved read-only Playbook command batch."
        reason = None
    elif completed > 0:
        status = EvidenceStatus.PARTIAL
        summary = "V13 Device owner completed part of the approved read-only Playbook command batch."
        reason = "device_readonly_batch_partial"
    else:
        status = EvidenceStatus.FAILED
        summary = "V13 Device owner could not complete the approved read-only Playbook command batch."
        reason = "device_readonly_batch_failed"

    notices: list[ContractNotice] = []
    if status == EvidenceStatus.FAILED:
        notices.append(
            ContractNotice(
                code="v13_device_readonly_batch_failed",
                message="The approved read-only Device command batch returned no completed command.",
                stage="v13_device_owner",
                retryable=False,
                details={
                    "command_count": len(results),
                    "failed_count": failed,
                    "partial_count": partial,
                    "hard_error_count": hard_errors,
                },
            )
        )

    return EvidenceEnvelope(
        schema_version="v12.1",
        request_id=request_id,
        source=EvidenceSource.DEVICE,
        evidence_kind="evidence",
        status=status,
        summary=summary,
        facts={
            "family": family,
            "owner": "device_agent",
            "command_count": len(results),
            "completed_count": completed,
            "failed_count": failed,
            "partial_count": partial,
            "hard_error_count": hard_errors,
            "arbitrary_cli_generated": False,
            "write_command_executed": False,
        },
        scope=dict(target),
        errors=notices,
        collected_at=_now(),
        reason=reason,
    )


def build_legacy_callback_payload_from_owner(
    *,
    request_id: str,
    plan: Mapping[str, Any],
    command_results: list[Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "request_id": request_id,
        "runner_mode": "v13_device_owner",
        "target_scope": dict(_mapping(plan.get("target_scope"))),
        "classification": dict(_mapping(plan.get("classification"))),
        "playbook": dict(_mapping(plan.get("playbook"))),
        "family_result": dict(_mapping(plan.get("family_result"))),
        "capability_plan": dict(_mapping(plan.get("capability_plan"))),
        "execution_source": _text(plan.get("execution_source")),
        "readonly_only": bool(plan.get("readonly_only")),
        "policy_result": dict(_mapping(plan.get("policy_result"))),
        "precheck_result": {
            "enabled": False,
            "stop": False,
            "reason": "v13_migrated_interface_family_not_reachability_precheck",
            "command_results": [],
        },
        "guard_result": dict(_mapping(plan.get("guard_result"))),
        "interface_target_guard": dict(_mapping(plan.get("interface_target_guard"))),
        "command_results": [dict(item) for item in command_results],
        "completed_at": _now().isoformat(),
        "v13_device_owner": {
            "active": True,
            "owner": "device_agent",
            "legacy_duplicate_call": False,
        },
    }


def run_device_owner_for_plan(
    *,
    request_id: str,
    plan: Mapping[str, Any],
    project_root: str | Path = DEFAULT_PROJECT_ROOT,
) -> dict[str, Any]:
    """Run the approved Playbook batch through the unique Device owner."""

    root = _project_root(project_root)
    try:
        family = plan_family(plan)
    except EvidenceOwnerBuildError:
        return {"handled": False, "reason": "family_not_migrated"}
    control = load_release_control(root)
    if not owner_active_for_family(family, control):
        return {"handled": False, "reason": "device_owner_not_active_for_family", "family": family}

    try:
        playbook_id, target, candidates = _validated_device_candidates(plan)
        request = _device_batch_request(
            request_id=request_id,
            plan=plan,
            family=family,
            playbook_id=playbook_id,
            target=target,
            candidates=candidates,
        )
    except Exception as exc:
        return {
            "handled": False,
            "reason": "device_owner_contract_not_buildable_fail_open_legacy",
            "family": family,
            "exception_type": type(exc).__name__,
        }

    broker = EvidenceCapabilityBroker(_checkpoint_root(root))
    owner = DeviceEvidenceOwner(broker=broker, fence=_fence(root))
    result_holder: dict[str, Any] = {}

    def executor(_request, attempt: int) -> EvidenceEnvelope:
        if attempt != 1:
            raise V13ProductionIntegrationError("production Device owner retry budget exceeded")
        runtime = _netmiko_runtime(_load_runtime_config(root), root)
        old_env = {key: os.environ.get(key) for key in runtime}
        try:
            os.environ.update(runtime)
            with bind_d3_netmiko_helper():
                results = execute_commands(
                    request_id=request_id,
                    target_scope=dict(target),
                    execution_candidates=[dict(item) for item in candidates],
                )
        finally:
            for key, value in old_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        if not isinstance(results, list) or len(results) != len(candidates):
            raise V13ProductionIntegrationError("Device lower executor returned an unexpected result count")
        payload = {
            "schema_version": "v13-device-owner-results-1",
            "request_id": request_id,
            "family": family,
            "playbook_id": playbook_id,
            "command_count": len(candidates),
            "command_fingerprints": [
                hashlib.sha256(_text(item.get("command")).encode("utf-8")).hexdigest()
                for item in candidates
            ],
            "command_results": [dict(item) for item in results],
            "write_command_executed": False,
            "persisted_at": _now().isoformat(),
        }
        _persist_device_results(root, request_id, payload)
        result_holder["payload"] = payload
        return _device_envelope(
            request_id=request_id,
            family=family,
            target=target,
            results=[dict(item) for item in results],
        )

    try:
        outcome = owner.execute(request, executor)
    except Exception as exc:
        if _fence(root).legacy_action(request_id, "device") == "skip_duplicate":
            payload = load_device_owner_command_results(request_id, project_root=root)
            command_results = (
                [dict(x) for x in (payload.get("command_results") or []) if isinstance(x, Mapping)]
                if isinstance(payload, dict)
                else []
            )
            result = {
                "handled": True,
                "reason": "v13_device_owner_exception_after_fence_no_legacy_retry",
                "family": family,
                "owner": "device_agent",
                "exception_type": type(exc).__name__,
                "legacy_action": "skip_duplicate",
                "command_results": command_results,
                "fatal_local_artifact_error": not bool(command_results),
            }
            if command_results:
                result["callback_payload"] = build_legacy_callback_payload_from_owner(
                    request_id=request_id,
                    plan=plan,
                    command_results=command_results,
                )
            return result
        return {
            "handled": False,
            "reason": "v13_device_owner_exception_before_fence_fail_open_legacy",
            "family": family,
            "exception_type": type(exc).__name__,
        }

    payload = result_holder.get("payload")
    if not isinstance(payload, dict):
        payload = load_device_owner_command_results(request_id, project_root=root)
    if not isinstance(payload, dict):
        # A checkpoint/fence means the owner already claimed/attempted this
        # source. Never fall back to a second real Device call.
        return {
            "handled": True,
            "reason": "device_owner_checkpoint_exists_but_raw_results_missing_no_legacy_retry",
            "family": family,
            "owner": "device_agent",
            "decision_action": outcome.owner_record.decision_action,
            "evidence_status": outcome.owner_record.evidence_status.value,
            "legacy_action": outcome.fence_record.legacy_action,
            "command_results": [],
            "fatal_local_artifact_error": True,
        }

    command_results = [dict(x) for x in (payload.get("command_results") or []) if isinstance(x, Mapping)]
    return {
        "handled": True,
        "reason": "v13_device_owner_active",
        "family": family,
        "owner": outcome.owner_record.owner,
        "owner_count": outcome.owner_record.owner_count,
        "decision_action": outcome.owner_record.decision_action,
        "evidence_status": outcome.owner_record.evidence_status.value,
        "external_call_performed": outcome.owner_record.external_call_performed,
        "legacy_action": outcome.fence_record.legacy_action,
        "command_results": command_results,
        "callback_payload": build_legacy_callback_payload_from_owner(
            request_id=request_id,
            plan=plan,
            command_results=command_results,
        ),
        "raw_result_ref": str(_device_result_dir(root, request_id) / DEVICE_RESULT_NAME),
    }


def production_contract_summary(
    *,
    project_root: str | Path = DEFAULT_PROJECT_ROOT,
) -> dict[str, Any]:
    root = _project_root(project_root)
    control = load_release_control(root, strict=True)
    return sanitize_sensitive_data(
        {
            "schema_version": "v13-production-integration-1",
            "control": control,
            "triage_owner": "triage",
            "metrics_owner": "metrics_agent",
            "device_owner": "device_agent",
            "notification_owner_changed": False,
            "logs_agent_enabled": False,
            "knowledge_agent_enabled": False,
            "arbitrary_promql_allowed": False,
            "arbitrary_cli_allowed": False,
            "write_commands_allowed": False,
        }
    )
