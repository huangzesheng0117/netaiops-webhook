"""Approved real-call adapters for the V13-D3 manual one-request Canary.

This module reuses the frozen v12 P2 real collectors.  It does not expose raw
PromQL generation, arbitrary CLI generation, GLM, Logs Evidence, Analytics, or
notification capabilities.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from netaiops.v12.contracts import EvidenceEnvelope
from netaiops.v12.p2_controlled_canary import P2CallKind, P2CallLedger, P2Settings
from netaiops.v12.p2_real_canary import (
    P2CanarySample,
    RealNetmikoCollector,
    RealPrometheusCollector,
    _systemd_service_environment,
)

from .capability_broker import CapabilityExecutionError
from .capability_contracts import CapabilityRequest, DeviceCapabilityRequest, MetricsCapabilityRequest
from .evidence_owner_builders import DeviceExecutionMaterial


class D3RealAdapterError(RuntimeError):
    pass


APPROVED_HELPER_ENV = "MCP_HELPER_CMD"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_d3_netmiko_helper() -> Path:
    """Resolve the helper from the running Webhook service environment.

    D3 recovery is often launched from an interactive shell which does not
    inherit EnvironmentFile values from netaiops-webhook.service.  The running
    production service is therefore authoritative for MCP_HELPER_CMD.
    """

    service_env = _systemd_service_environment({APPROVED_HELPER_ENV})
    helper = str(service_env.get(APPROVED_HELPER_ENV) or "").strip()
    if not helper:
        # Fallback is intentionally secondary; it supports offline/unit-test
        # contexts while keeping the running service authoritative in prod.
        helper = str(os.environ.get(APPROVED_HELPER_ENV) or "").strip()
    if not helper:
        raise D3RealAdapterError("MCP_HELPER_CMD is unavailable for D3 Netmiko runtime")

    path = Path(helper)
    if not path.is_absolute():
        raise D3RealAdapterError("MCP_HELPER_CMD must be an absolute path")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise D3RealAdapterError("MCP_HELPER_CMD does not resolve to an existing file") from exc
    if not resolved.is_file():
        raise D3RealAdapterError("MCP_HELPER_CMD is not a file")
    if not os.access(str(resolved), os.X_OK):
        raise D3RealAdapterError("MCP_HELPER_CMD is not executable")
    return resolved


def d3_netmiko_runtime_contract() -> dict[str, Any]:
    helper = resolve_d3_netmiko_helper()
    return {
        "helper_env_present": True,
        "helper_path": str(helper),
        "helper_exists": helper.is_file(),
        "helper_executable": os.access(str(helper), os.X_OK),
        "helper_sha256": _sha256_file(helper),
        "shell_helper_present_before_binding": bool(os.environ.get(APPROVED_HELPER_ENV)),
    }


@contextmanager
def bind_d3_netmiko_helper():
    helper = resolve_d3_netmiko_helper()
    previous = os.environ.get(APPROVED_HELPER_ENV)
    os.environ[APPROVED_HELPER_ENV] = str(helper)
    try:
        yield helper
    finally:
        if previous is None:
            os.environ.pop(APPROVED_HELPER_ENV, None)
        else:
            os.environ[APPROVED_HELPER_ENV] = previous


def build_d3_real_settings(activation_id: str) -> P2Settings:
    now = datetime.now(timezone.utc)
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
        rca_real_calls_enabled=False,
        reuse_existing_evidence_before_real_call=True,
        activated_at=now - timedelta(seconds=5),
        canary_window_minutes=60,
        max_canary_requests=1,
        minimum_completed_for_gate=1,
        allowed_families=(
            "interface_status_or_flap",
            "interface_or_link_utilization_high",
            "interface_traffic_anomaly",
        ),
        total_timeout_seconds=60,
        metrics_timeout_seconds=20,
        device_timeout_seconds=30,
        rca_timeout_seconds=1,
        max_metrics_calls_per_request=1,
        max_device_calls_per_request=1,
        max_rca_calls_per_request=0,
        max_total_external_calls_per_request=2,
        promql_generation_allowed=False,
        command_generation_allowed=False,
        dsl_generation_allowed=False,
        write_commands_allowed=False,
        arbitrary_tool_selection_allowed=False,
        automatic_followup_queries_allowed=False,
    )
    settings.validate_frozen_boundary()
    return settings


class D3RealExecutors:
    def __init__(
        self,
        *,
        request_id: str,
        sample: P2CanarySample,
        device_material: DeviceExecutionMaterial,
        project_root: str | Path,
        work_root: str | Path,
        production_config: Mapping[str, Any],
        activation_id: str,
    ) -> None:
        self.request_id = request_id
        self.sample = sample
        self.device_material = device_material
        self.project_root = Path(project_root)
        self.work_root = Path(work_root)
        self.settings = build_d3_real_settings(activation_id)
        self.ledger = P2CallLedger(
            settings=self.settings,
            request_id=request_id,
            family=sample.family,
        )
        self.metrics_collector = RealPrometheusCollector(
            project_root=self.project_root,
            work_root=self.work_root,
            production_config=production_config,
        )
        self.device_collector = RealNetmikoCollector(
            project_root=self.project_root,
            production_config=production_config,
        )

    def metrics(self, request: CapabilityRequest, attempt: int) -> EvidenceEnvelope:
        if not isinstance(request, MetricsCapabilityRequest):
            raise D3RealAdapterError("metrics executor requires MetricsCapabilityRequest")
        if attempt != 1:
            raise D3RealAdapterError("real Canary does not auto-retry Metrics")
        try:
            outcome = asyncio.run(
                self.metrics_collector.collect(
                    request_id=self.request_id,
                    sample=self.sample,
                    settings=self.settings,
                    ledger=self.ledger,
                )
            )
        except TimeoutError as exc:
            raise CapabilityExecutionError("timeout", "d3_metrics_timeout", "Metrics real call timed out") from exc
        except Exception as exc:
            raise CapabilityExecutionError("failed", "d3_metrics_real_failed", f"Metrics real adapter failed: {type(exc).__name__}") from exc
        raw = outcome.output.get("metrics_evidence")
        if not isinstance(raw, Mapping):
            raise CapabilityExecutionError("failed", "d3_metrics_envelope_missing", "Metrics collector returned no EvidenceEnvelope")
        return EvidenceEnvelope.model_validate(raw)

    def device(self, request: CapabilityRequest, attempt: int) -> EvidenceEnvelope:
        if not isinstance(request, DeviceCapabilityRequest):
            raise D3RealAdapterError("device executor requires DeviceCapabilityRequest")
        if attempt != 1:
            raise D3RealAdapterError("real Canary does not auto-retry Device")
        if request.template_fingerprint != self.device_material.request.template_fingerprint:
            raise D3RealAdapterError("device template fingerprint changed after approval")
        # Replace only the request identity carried into the existing frozen sample.
        sample = replace(
            self.sample,
            command_candidate={
                **dict(self.sample.command_candidate),
                "command": self.device_material.command,
                "readonly": True,
            },
        )
        try:
            # The manual D3 process does not inherit systemd EnvironmentFile
            # values. Bind MCP_HELPER_CMD from the running production service
            # only for the bounded Netmiko call, then restore the shell env.
            with bind_d3_netmiko_helper():
                outcome = asyncio.run(
                    self.device_collector.collect(
                        request_id=self.request_id,
                        sample=sample,
                        settings=self.settings,
                        ledger=self.ledger,
                    )
                )
        except TimeoutError as exc:
            raise CapabilityExecutionError("timeout", "d3_device_timeout", "Device real call timed out") from exc
        except Exception as exc:
            raise CapabilityExecutionError("failed", "d3_device_real_failed", f"Device real adapter failed: {type(exc).__name__}") from exc
        raw = outcome.output.get("device_evidence")
        if not isinstance(raw, Mapping):
            raise CapabilityExecutionError("failed", "d3_device_envelope_missing", "Device collector returned no EvidenceEnvelope")
        return EvidenceEnvelope.model_validate(raw)

    def call_counts(self) -> dict[str, int]:
        snapshot = self.ledger.snapshot()
        raw = snapshot.get("call_counts") or {}
        return {
            "prometheus_mcp": int(raw.get(P2CallKind.METRICS.value) or 0),
            "netmiko_mcp": int(raw.get(P2CallKind.DEVICE.value) or 0),
            "glm_rca": int(raw.get(P2CallKind.RCA.value) or 0),
        }
