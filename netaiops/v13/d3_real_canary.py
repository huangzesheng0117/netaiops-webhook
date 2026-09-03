"""Exactly-once manual V13-D3 real owner Canary.

This module is intentionally not mounted into the production Alertmanager
route.  The controller may invoke it only after explicit user approval.  One
Canary performs at most one Prometheus MCP call and one read-only Netmiko MCP
command, then repeats the owner requests to prove checkpoint reuse without a
second external call.  It never calls GLM, Logs/Analytics MCP, or notification.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from netaiops.v12.atomic_writer import AtomicJsonWriter
from netaiops.v12.p2_real_canary import (
    P2RealCanaryError,
    discover_real_canary_sample,
    load_production_config,
)
from netaiops.v12.schema_validator import sanitize_sensitive_data

from .capability_broker import EvidenceCapabilityBroker
from .evidence_owner_builders import (
    build_device_material,
    build_metrics_request_from_fixed_contract,
)
from .evidence_owners import DeviceEvidenceOwner, MetricsEvidenceOwner
from .legacy_call_fence import LegacyCallFence
from .real_owner_adapters import D3RealExecutors


class D3RealCanaryError(RuntimeError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _read_json(path: Path) -> Mapping[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise D3RealCanaryError("state root is not an object")
    return value


def _find_family_sample(project_root: Path, family: str):
    plans = [p for p in (project_root / "data" / "plans").glob("*.plan.json") if p.is_file() and not p.is_symlink()]
    plans.sort(key=lambda p: (p.stat().st_mtime_ns, p.name), reverse=True)
    rejections: dict[str, int] = {}
    for plan_path in plans[:1800]:
        try:
            plan = _read_json(plan_path)
            request_id = str(plan.get("request_id") or "").strip()
            family_result = plan.get("family_result") or {}
            observed = str(family_result.get("family") or (plan.get("classification") or {}).get("family") or "").strip()
            if observed != family:
                continue
            sample = discover_real_canary_sample(
                project_root,
                preferred_request_id=request_id,
            )
            if sample.family != family:
                continue
            # Bind the stricter D3 owner contracts before the exactly-once
            # Canary state is created, so an unsuitable historical sample
            # cannot consume the one approved external-call attempt.
            probe_request_id = (
                "d3probe-"
                + hashlib.sha256(request_id.encode("utf-8")).hexdigest()[:20]
            )
            build_metrics_request_from_fixed_contract(
                request_id=probe_request_id,
                plan=sample.legacy_plan,
                profile=sample.metrics_profile,
                query_name=sample.metrics_query_name,
                target=sample.metrics_target,
                max_attempts=1,
            )
            build_device_material(
                request_id=probe_request_id,
                plan=sample.legacy_plan,
                max_attempts=1,
                selected_candidate=sample.command_candidate,
            )
            return sample
        except Exception as exc:
            key = type(exc).__name__
            rejections[key] = rejections.get(key, 0) + 1
    raise D3RealCanaryError(
        "no safe historical real-Canary sample for family; "
        + ",".join(f"{k}={v}" for k, v in sorted(rejections.items()))
    )


def run_real_canary(
    *,
    family: str,
    project_root: str | Path = "/opt/netaiops-webhook",
) -> dict[str, Any]:
    if family != "interface_status_or_flap":
        raise D3RealCanaryError("first D3 real Canary is frozen to interface_status_or_flap")
    root = Path(project_root)
    state_root = root / "data" / "v13" / "d3_canary_state"
    state_root.mkdir(parents=True, exist_ok=True)
    os.chmod(state_root, 0o700)
    state_path = state_root / f"{family}.json"
    if state_path.exists():
        existing = _read_json(state_path)
        raise D3RealCanaryError(
            "D3 real Canary already has state="
            + str(existing.get("state") or "unknown")
            + "; automatic retry is forbidden"
        )

    sample = _find_family_sample(root, family)
    activation_seed = f"{family}:{sample.original_request_id}:{_now().isoformat()}"
    activation_id = "d3-" + hashlib.sha256(activation_seed.encode("utf-8")).hexdigest()[:20]
    request_id = "v13d3-" + hashlib.sha256((activation_seed + ":request").encode("utf-8")).hexdigest()[:24]
    started = {
        "schema_version": "v13-d3-real-canary-1",
        "family": family,
        "request_id": request_id,
        "activation_id": activation_id,
        "state": "started",
        "started_at": _now().isoformat(),
        "automatic_retry_allowed": False,
        "prometheus_mcp_calls": 0,
        "netmiko_mcp_calls": 0,
        "device_command_attempt_count": 0,
        "notification_attempt_count": 0,
        "glm_attempt_count": 0,
    }
    AtomicJsonWriter(state_root, directory_mode=0o700, file_mode=0o600).write_json(
        state_path.name,
        started,
    )

    try:
        metrics_request = build_metrics_request_from_fixed_contract(
            request_id=request_id,
            plan=sample.legacy_plan,
            profile=sample.metrics_profile,
            query_name=sample.metrics_query_name,
            target=sample.metrics_target,
            max_attempts=1,
        )
        device_material = build_device_material(
            request_id=request_id,
            plan=sample.legacy_plan,
            max_attempts=1,
            selected_candidate=sample.command_candidate,
        )
        production_config = load_production_config(root / "config.yaml")
        work_root = root / "data" / "v13" / "d3_real_canary" / request_id
        work_root.mkdir(parents=True, exist_ok=True)
        broker = EvidenceCapabilityBroker(root / "data" / "v13" / "capability_checkpoints")
        fence = LegacyCallFence(root / "data" / "evidence_hub" / "requests")
        metrics_owner = MetricsEvidenceOwner(broker=broker, fence=fence)
        device_owner = DeviceEvidenceOwner(broker=broker, fence=fence)
        executors = D3RealExecutors(
            request_id=request_id,
            sample=sample,
            device_material=device_material,
            project_root=root,
            work_root=work_root,
            production_config=production_config,
            activation_id=activation_id,
        )

        metrics_first = metrics_owner.execute(metrics_request, executors.metrics)
        metrics_second = metrics_owner.execute(metrics_request, executors.metrics)
        device_first = device_owner.execute(device_material.request, executors.device)
        device_second = device_owner.execute(device_material.request, executors.device)
        metrics_status = metrics_first.owner_record.evidence_status.value
        device_status = device_first.owner_record.evidence_status.value
        if metrics_status not in {"success", "partial", "no_data"}:
            raise D3RealCanaryError(
                "Prometheus owner real call did not produce an acceptable evidence status"
            )
        if device_status not in {"success", "partial"}:
            raise D3RealCanaryError(
                "Device owner real call did not produce an acceptable evidence status"
            )
        counts = executors.call_counts()
        if counts != {"prometheus_mcp": 1, "netmiko_mcp": 1, "glm_rca": 0}:
            raise D3RealCanaryError(f"real call counts violated D3 budget: {counts}")
        if metrics_second.owner_record.external_call_performed:
            raise D3RealCanaryError("second Metrics owner call was not checkpoint reuse")
        if device_second.owner_record.external_call_performed:
            raise D3RealCanaryError("second Device owner call was not checkpoint reuse")
        if fence.legacy_action(request_id, "metrics") != "skip_duplicate":
            raise D3RealCanaryError("Metrics legacy duplicate fence is missing")
        if fence.legacy_action(request_id, "device") != "skip_duplicate":
            raise D3RealCanaryError("Device legacy duplicate fence is missing")

        result = {
            **started,
            "state": "sentinel_completed",
            "finished_at": _now().isoformat(),
            "sample": sample.public_dict(),
            "prometheus_mcp_calls": 1,
            "netmiko_mcp_calls": 1,
            "device_command_attempt_count": 1,
            "notification_attempt_count": 0,
            "glm_attempt_count": 0,
            "metrics_first_action": metrics_first.owner_record.decision_action,
            "metrics_second_action": metrics_second.owner_record.decision_action,
            "device_first_action": device_first.owner_record.decision_action,
            "device_second_action": device_second.owner_record.decision_action,
            "metrics_status": metrics_status,
            "device_status": device_status,
            "metrics_legacy_action": "skip_duplicate",
            "device_legacy_action": "skip_duplicate",
            "command_sha256": device_material.command_sha256,
            "playbook_id": device_material.playbook_id,
            "write_command_executed": False,
            "notification_sent": False,
            "glm_called": False,
            "evidence_mcp_called": False,
            "analytics_mcp_called": False,
            "ops_es_api_called": False,
            "automatic_retry_allowed": False,
        }
        AtomicJsonWriter(state_root, directory_mode=0o700, file_mode=0o600).write_json(
            state_path.name,
            sanitize_sensitive_data(result),
        )
        trace_root = root / "data" / "evidence_hub" / "requests" / request_id / "v13"
        AtomicJsonWriter(trace_root).write_json(
            "d3_real_canary.json",
            sanitize_sensitive_data(result),
        )
        return result
    except BaseException as exc:
        failed = {
            **started,
            "state": "failed_or_ambiguous",
            "finished_at": _now().isoformat(),
            "error_type": type(exc).__name__,
            "error": str(exc)[:500],
            "automatic_retry_allowed": False,
        }
        try:
            AtomicJsonWriter(state_root, directory_mode=0o700, file_mode=0o600).write_json(
                state_path.name,
                sanitize_sensitive_data(failed),
            )
        except Exception:
            pass
        raise
