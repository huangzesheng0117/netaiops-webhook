"""Build D1 capability requests from persisted, approved legacy plan artifacts.

No raw PromQL is accepted as owner input.  Device CLI is carried only in the
non-persistent ``DeviceExecutionMaterial`` after it has been proven to be an
existing read-only Playbook command; the D1 request stores fingerprints only.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from netaiops.plan_builder import command_is_readonly
from netaiops.interface_target_guard import validate_interface_name
from netaiops.prometheus_plan_hooks import apply_prometheus_evidence_metadata_to_plan
from netaiops.safety_policy import evaluate_candidate, evaluate_plan_safety, safety_config

from .capability_contracts import (
    DeviceCapabilityRequest,
    MetricsCapabilityRequest,
    build_plan_fingerprint,
    build_template_fingerprint,
)
from .evidence_owner_contracts import APPROVED_OWNER_FAMILIES


class EvidenceOwnerBuildError(ValueError):
    pass


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def plan_family(plan: Mapping[str, Any]) -> str:
    family_result = _mapping(plan.get("family_result"))
    classification = _mapping(plan.get("classification"))
    family = _text(
        family_result.get("family")
        or classification.get("family")
        or plan.get("family")
    )
    if family not in APPROVED_OWNER_FAMILIES:
        raise EvidenceOwnerBuildError("plan family is not approved for D3 ownership")
    return family


def _validate_common_target(target: Mapping[str, Any]) -> dict[str, Any]:
    target = dict(target)
    if not target:
        raise EvidenceOwnerBuildError("target scope is missing")
    if not _text(target.get("device_ip") or target.get("ip") or target.get("instance")):
        raise EvidenceOwnerBuildError("target has no device identity")
    vendor = _text(target.get("vendor")).lower()
    if not vendor or vendor in {"unknown", "none", "null", "n/a", "na"}:
        raise EvidenceOwnerBuildError("unknown vendor is blocked-safe")
    return target


def validate_device_target(target: Mapping[str, Any]) -> dict[str, Any]:
    target = _validate_common_target(target)
    interface = _text(
        target.get("interface")
        or target.get("if_name")
        or target.get("ifName")
        or target.get("interface_name")
    )
    if "|" in interface:
        raise EvidenceOwnerBuildError("Device owner requires one concrete interface")
    valid, reasons = validate_interface_name(interface)
    if not valid:
        raise EvidenceOwnerBuildError(
            "invalid interface is blocked-safe: " + ",".join(reasons)
        )
    return target


def validate_metrics_target(target: Mapping[str, Any]) -> dict[str, Any]:
    target = _validate_common_target(target)
    interface_expr = _text(
        target.get("interface_regex")
        or target.get("interfaces")
        or target.get("if_name")
        or target.get("ifName")
        or target.get("interface")
        or target.get("interface_name")
    )
    parts = [part.strip() for part in interface_expr.split("|") if part.strip()]
    if not parts:
        raise EvidenceOwnerBuildError("Metrics owner interface target is missing")
    invalid: list[str] = []
    for part in parts:
        valid, reasons = validate_interface_name(part)
        if not valid:
            invalid.extend(f"{part}:{reason}" for reason in reasons)
    if invalid:
        raise EvidenceOwnerBuildError(
            "invalid Metrics interface target is blocked-safe: " + ",".join(invalid)
        )
    return target


def _target(plan: Mapping[str, Any]) -> dict[str, Any]:
    return validate_device_target(_mapping(plan.get("target_scope")))


def build_metrics_request_from_fixed_contract(
    *,
    request_id: str,
    plan: Mapping[str, Any],
    profile: str,
    query_name: str,
    target: Mapping[str, Any],
    max_attempts: int = 2,
) -> MetricsCapabilityRequest:
    family = plan_family(plan)
    profile = _text(profile)
    query_name = _text(query_name)
    if not profile or not query_name:
        raise EvidenceOwnerBuildError("fixed Prometheus profile/query is missing")
    target = validate_metrics_target(target)
    template_id = f"prometheus:{profile}:{query_name}"
    return MetricsCapabilityRequest(
        request_id=request_id,
        family=family,
        capability="query_prometheus_metric_window",
        target=target,
        plan_fingerprint=build_plan_fingerprint(dict(plan)),
        template_fingerprint=build_template_fingerprint(
            template_id,
            {"profile": profile, "query_name": query_name},
        ),
        required=True,
        max_attempts=max_attempts,
        query_template_id=template_id,
        promql_generation_allowed=False,
    )


def build_metrics_request(
    *,
    request_id: str,
    plan: Mapping[str, Any],
    max_attempts: int = 2,
) -> MetricsCapabilityRequest:
    normalized = apply_prometheus_evidence_metadata_to_plan(dict(plan))
    metadata = _mapping(normalized.get("prometheus_evidence_first"))
    if metadata.get("enabled") is not True:
        raise EvidenceOwnerBuildError("Prometheus evidence is not enabled in persisted plan")
    if _text(metadata.get("status")) != "metadata_ready":
        raise EvidenceOwnerBuildError("Prometheus metadata is not ready")
    profile = _text(metadata.get("evidence_profile"))
    query_names = [_text(x) for x in (metadata.get("query_names") or []) if _text(x)]
    if not profile or not query_names:
        raise EvidenceOwnerBuildError("fixed Prometheus profile/query is missing")
    return build_metrics_request_from_fixed_contract(
        request_id=request_id,
        plan=plan,
        profile=profile,
        query_name=query_names[0],
        target=dict(_mapping(metadata.get("target_context"))) or _mapping(plan.get("target_scope")),
        max_attempts=max_attempts,
    )


@dataclass(frozen=True, slots=True)
class DeviceExecutionMaterial:
    request: DeviceCapabilityRequest
    command: str
    command_sha256: str
    playbook_id: str
    candidate_order: int


def build_device_material(
    *,
    request_id: str,
    plan: Mapping[str, Any],
    max_attempts: int = 2,
    selected_candidate: Mapping[str, Any] | None = None,
) -> DeviceExecutionMaterial:
    family = plan_family(plan)
    if _text(plan.get("execution_source")) != "playbook":
        raise EvidenceOwnerBuildError("D3 Device owner requires execution_source=playbook")
    playbook = _mapping(plan.get("playbook"))
    if playbook.get("matched") is not True:
        raise EvidenceOwnerBuildError("D3 Device owner requires a matched Playbook")
    playbook_id = _text(playbook.get("playbook_id"))
    if not playbook_id:
        raise EvidenceOwnerBuildError("matched Playbook has no playbook_id")

    target = _target(plan)
    candidates = [dict(x) for x in (plan.get("execution_candidates") or []) if isinstance(x, Mapping)]
    if selected_candidate is not None:
        requested_command = _text(selected_candidate.get("command"))
        requested_order = int(selected_candidate.get("order") or 0)
        candidates = [
            item for item in candidates
            if _text(item.get("command")) == requested_command
            and int(item.get("order") or 0) == requested_order
        ]
        if len(candidates) != 1:
            raise EvidenceOwnerBuildError("selected real Canary command is not an exact persisted Playbook candidate")
    selected: dict[str, Any] | None = None
    for item in candidates:
        command = _text(item.get("command"))
        if not command or "{" in command or "}" in command:
            continue
        if item.get("readonly") is not True or not command_is_readonly(command):
            continue
        candidate = dict(item)
        candidate["readonly"] = True
        if not evaluate_candidate(candidate, safety_config()).get("safe"):
            continue
        one = dict(plan)
        one["execution_candidates"] = [candidate]
        if not evaluate_plan_safety(one).get("allowed"):
            continue
        selected = candidate
        break
    if selected is None:
        raise EvidenceOwnerBuildError("no approved read-only Playbook command is available")

    command = _text(selected.get("command"))
    command_sha = hashlib.sha256(command.encode("utf-8")).hexdigest()
    capability = _text(selected.get("capability")) or "playbook_readonly_command"
    order = int(selected.get("order") or 1)
    template_id = f"playbook:{playbook_id}:{capability}:{order}"
    request = DeviceCapabilityRequest(
        request_id=request_id,
        family=family,
        capability=capability,
        target=target,
        plan_fingerprint=build_plan_fingerprint(dict(plan)),
        template_fingerprint=build_template_fingerprint(
            template_id,
            {
                "playbook_id": playbook_id,
                "capability": capability,
                "candidate_order": order,
                "command_sha256": command_sha,
            },
        ),
        required=True,
        max_attempts=max_attempts,
        command_template_id=template_id,
        playbook_id=playbook_id,
        readonly_only=True,
        command_generation_allowed=False,
        safety_policy_allowed=True,
        safety_policy_reasons=[],
    )
    return DeviceExecutionMaterial(
        request=request,
        command=command,
        command_sha256=command_sha,
        playbook_id=playbook_id,
        candidate_order=order,
    )
