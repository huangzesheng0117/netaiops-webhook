"""Explicit V13-D3 device-only recovery Canary after a bounded failed attempt.

The original failed/ambiguous D3 Canary state, checkpoints, and owner fences are
immutable evidence and are never deleted or reused for a second external call.
A recovery Canary creates a new request_id and performs exactly one read-only
Device/Netmiko call.  The already-successful original Metrics evidence is
validated and referenced as prior evidence; Prometheus is not called again.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from netaiops.v12.atomic_writer import AtomicJsonWriter
from netaiops.v12.p2_real_canary import load_production_config
from netaiops.v12.schema_validator import sanitize_sensitive_data

from .capability_broker import EvidenceCapabilityBroker
from .d3_real_canary import _find_family_sample
from .evidence_owner_builders import build_device_material
from .evidence_owners import DeviceEvidenceOwner
from .legacy_call_fence import LegacyCallFence
from .real_owner_adapters import D3RealExecutors, d3_netmiko_runtime_contract


RECOVERY_SCHEMA_VERSION = "v13-d3-device-recovery-1"
_RECOVERY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")


class D3RecoveryCanaryError(RuntimeError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _read_json(path: Path) -> Mapping[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise D3RecoveryCanaryError(f"unsafe or missing JSON artifact: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise D3RecoveryCanaryError("JSON root is not an object")
    return value


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_original_failed_attempt(
    project_root: str | Path,
    family: str,
) -> dict[str, Any]:
    root = Path(project_root)
    state_path = root / "data" / "v13" / "d3_canary_state" / f"{family}.json"
    state = _read_json(state_path)
    if state.get("state") != "failed_or_ambiguous":
        raise D3RecoveryCanaryError("original D3 Canary is not failed_or_ambiguous")
    if state.get("automatic_retry_allowed") is not False:
        raise D3RecoveryCanaryError("original D3 Canary retry boundary drifted")
    original_request_id = str(state.get("request_id") or "").strip()
    if not original_request_id:
        raise D3RecoveryCanaryError("original D3 Canary request_id is missing")

    checkpoint_root = root / "data" / "v13" / "capability_checkpoints" / original_request_id
    checkpoints: dict[str, Mapping[str, Any]] = {}
    checkpoint_sha256: dict[str, str] = {}
    for path in sorted(checkpoint_root.glob("*.json")):
        if path.is_symlink() or not path.is_file():
            continue
        item = _read_json(path)
        source = str(item.get("source") or "").strip()
        if source in {"metrics", "device"}:
            if source in checkpoints:
                raise D3RecoveryCanaryError(f"duplicate original {source} checkpoint")
            checkpoints[source] = item
            checkpoint_sha256[source] = _sha256_file(path)
    if set(checkpoints) != {"metrics", "device"}:
        raise D3RecoveryCanaryError("original Metrics/Device checkpoints are incomplete")

    metrics = checkpoints["metrics"]
    device = checkpoints["device"]
    metrics_env = metrics.get("envelope") or {}
    device_env = device.get("envelope") or {}
    if metrics.get("status") != "success" or metrics_env.get("status") != "success":
        raise D3RecoveryCanaryError("original Metrics checkpoint was not successful")
    if metrics.get("attempts") != 1 or metrics.get("terminal") is not True:
        raise D3RecoveryCanaryError("original Metrics checkpoint attempt contract drifted")
    if device.get("status") != "failed" or device_env.get("status") != "failed":
        raise D3RecoveryCanaryError("original Device checkpoint was not failed")
    if device.get("attempts") != 1 or device.get("terminal") is not True:
        raise D3RecoveryCanaryError("original Device checkpoint attempt contract drifted")
    if device_env.get("reason") != "netmiko_mcp_command_failed":
        raise D3RecoveryCanaryError("original Device failure reason drifted")

    fence_root = root / "data" / "evidence_hub" / "requests" / original_request_id / "v13"
    fence_sha256: dict[str, str] = {}
    for source in ("metrics", "device"):
        path = fence_root / f"{source}_owner_fence.json"
        fence = _read_json(path)
        if fence.get("active") is not True:
            raise D3RecoveryCanaryError(f"original {source} owner fence is not active")
        if fence.get("external_call_already_attempted") is not True:
            raise D3RecoveryCanaryError(f"original {source} external-attempt fence is missing")
        if fence.get("legacy_action") != "skip_duplicate":
            raise D3RecoveryCanaryError(f"original {source} legacy fence drifted")
        fence_sha256[source] = _sha256_file(path)

    metrics_facts = metrics_env.get("facts") or {}
    device_facts = device_env.get("facts") or {}
    return {
        "family": family,
        "original_request_id": original_request_id,
        "original_state_sha256": _sha256_file(state_path),
        "checkpoint_sha256": checkpoint_sha256,
        "fence_sha256": fence_sha256,
        "metrics_status": "success",
        "metrics_prometheus_mcp_called": metrics_facts.get("prometheus_mcp_called") is True,
        "device_status": "failed",
        "device_reason": "netmiko_mcp_command_failed",
        "device_netmiko_mcp_called": device_facts.get("netmiko_mcp_called") is True,
    }


def run_device_recovery_canary(
    *,
    family: str,
    recovery_id: str,
    project_root: str | Path = "/opt/netaiops-webhook",
) -> dict[str, Any]:
    if family != "interface_status_or_flap":
        raise D3RecoveryCanaryError("D3 recovery is frozen to interface_status_or_flap")
    recovery_id = str(recovery_id or "").strip().lower()
    if not _RECOVERY_ID_RE.fullmatch(recovery_id):
        raise D3RecoveryCanaryError("recovery_id must match [a-z0-9][a-z0-9-]{2,63}")

    root = Path(project_root)
    original = validate_original_failed_attempt(root, family)
    runtime = d3_netmiko_runtime_contract()
    if runtime.get("helper_exists") is not True or runtime.get("helper_executable") is not True:
        raise D3RecoveryCanaryError("D3 Netmiko helper runtime contract is not ready")

    state_root = root / "data" / "v13" / "d3_recovery_state"
    state_root.mkdir(parents=True, exist_ok=True)
    os.chmod(state_root, 0o700)
    state_path = state_root / f"{family}-{recovery_id}.json"
    if state_path.exists() or state_path.is_symlink():
        existing = _read_json(state_path) if state_path.is_file() and not state_path.is_symlink() else {"state": "unsafe"}
        raise D3RecoveryCanaryError(
            "D3 recovery Canary state already exists; automatic retry forbidden: "
            + str(existing.get("state"))
        )

    sample = _find_family_sample(root, family)
    activation_seed = (
        f"{family}:{recovery_id}:{original['original_request_id']}:"
        f"{sample.original_request_id}:{_now().isoformat()}"
    )
    activation_id = "d3r-" + hashlib.sha256(activation_seed.encode("utf-8")).hexdigest()[:20]
    request_id = "v13d3r-" + hashlib.sha256((activation_seed + ":request").encode("utf-8")).hexdigest()[:24]
    started = {
        "schema_version": RECOVERY_SCHEMA_VERSION,
        "family": family,
        "recovery_id": recovery_id,
        "request_id": request_id,
        "activation_id": activation_id,
        "original_failed_request_id": original["original_request_id"],
        "original_failed_state_sha256": original["original_state_sha256"],
        "state": "started",
        "started_at": _now().isoformat(),
        "automatic_retry_allowed": False,
        "prior_metrics_evidence_reused": True,
        "prometheus_mcp_calls": 0,
        "netmiko_mcp_calls": 0,
        "device_command_attempt_count": 0,
        "notification_attempt_count": 0,
        "glm_attempt_count": 0,
    }
    AtomicJsonWriter(state_root, directory_mode=0o700, file_mode=0o600).write_json(
        state_path.name, started
    )

    executors = None
    try:
        device_material = build_device_material(
            request_id=request_id,
            plan=sample.legacy_plan,
            max_attempts=1,
            selected_candidate=sample.command_candidate,
        )
        production_config = load_production_config(root / "config.yaml")
        work_root = root / "data" / "v13" / "d3_recovery_canary" / request_id
        work_root.mkdir(parents=True, exist_ok=True)
        broker = EvidenceCapabilityBroker(root / "data" / "v13" / "capability_checkpoints")
        fence = LegacyCallFence(root / "data" / "evidence_hub" / "requests")
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

        first = device_owner.execute(device_material.request, executors.device)
        second = device_owner.execute(device_material.request, executors.device)
        device_status = first.owner_record.evidence_status.value
        if device_status not in {"success", "partial"}:
            raise D3RecoveryCanaryError(
                "Device recovery real call did not produce an acceptable evidence status"
            )
        counts = executors.call_counts()
        if counts != {"prometheus_mcp": 0, "netmiko_mcp": 1, "glm_rca": 0}:
            raise D3RecoveryCanaryError(f"recovery real call counts violated budget: {counts}")
        if second.owner_record.external_call_performed:
            raise D3RecoveryCanaryError("second recovery Device owner call was not checkpoint reuse")
        if fence.legacy_action(request_id, "device") != "skip_duplicate":
            raise D3RecoveryCanaryError("recovery Device legacy duplicate fence is missing")

        result = {
            **started,
            "state": "sentinel_completed",
            "finished_at": _now().isoformat(),
            "sample": sample.public_dict(),
            "prior_metrics_evidence_reused": True,
            "prometheus_mcp_calls": 0,
            "netmiko_mcp_calls": 1,
            "device_command_attempt_count": 1,
            "device_first_action": first.owner_record.decision_action,
            "device_second_action": second.owner_record.decision_action,
            "device_status": device_status,
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
            state_path.name, sanitize_sensitive_data(result)
        )
        trace_root = root / "data" / "evidence_hub" / "requests" / request_id / "v13"
        AtomicJsonWriter(trace_root).write_json(
            "d3_recovery_canary.json", sanitize_sensitive_data(result)
        )
        return result
    except BaseException as exc:
        counts = {"prometheus_mcp": 0, "netmiko_mcp": 0, "glm_rca": 0}
        if executors is not None:
            try:
                counts = executors.call_counts()
            except Exception:
                pass
        failed = {
            **started,
            "state": "failed_or_ambiguous",
            "finished_at": _now().isoformat(),
            "error_type": type(exc).__name__,
            "error": str(exc)[:500],
            "prometheus_mcp_calls": int(counts.get("prometheus_mcp") or 0),
            "netmiko_mcp_calls": int(counts.get("netmiko_mcp") or 0),
            "device_command_attempt_count": int(counts.get("netmiko_mcp") or 0),
            "automatic_retry_allowed": False,
        }
        try:
            AtomicJsonWriter(state_root, directory_mode=0o700, file_mode=0o600).write_json(
                state_path.name, sanitize_sensitive_data(failed)
            )
        except Exception:
            pass
        raise
