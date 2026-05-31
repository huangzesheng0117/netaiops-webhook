#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetAIOps webhook v8 Prometheus plan metadata hooks.

职责：
- 从 plan.playbook_runtime.prometheus_evidence_first 中提取 v8 Prometheus Evidence 元数据。
- 规范化 target_context、profile、query_names、窗口参数、缺失标签。
- 只写 plan metadata，不执行 Prometheus 查询，不影响 CLI 取证。
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Optional


def first_non_empty(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def infer_profile_from_plan(plan: Dict[str, Any]) -> str:
    playbook = plan.get("playbook") or {}
    runtime = plan.get("playbook_runtime") or {}
    target_scope = plan.get("target_scope") or {}
    family_result = plan.get("family_result") or {}
    classification = plan.get("classification") or {}

    text = " ".join(
        str(x).lower()
        for x in [
            playbook.get("playbook_id"),
            playbook.get("playbook_file"),
            runtime.get("playbook_id"),
            runtime.get("name"),
            target_scope.get("alarm_type"),
            family_result.get("family"),
            family_result.get("legacy_playbook_type"),
            classification.get("category"),
            classification.get("alert_type"),
        ]
        if x
    )

    if any(x in text for x in ["packet", "loss", "discard", "error", "crc", "错包", "丢包"]):
        return "interface_errors"

    if any(x in text for x in ["traffic", "utilization", "bandwidth", "octets", "bps", "流量", "利用率", "突增", "突降"]):
        return "interface_traffic"

    if "f5" in text:
        return "f5_connections"

    if any(x in text for x in ["fortigate", "hillstone", "session", "connection", "会话", "连接数"]):
        return "firewall_sessions"

    if any(x in text for x in ["latency", "delay", "sla", "延迟"]):
        return "latency_window"

    return "unknown"


def default_query_names_for_profile(profile: str) -> List[str]:
    if profile == "interface_traffic":
        return ["in_bps", "out_bps", "oper_status"]
    if profile == "interface_errors":
        return ["in_errors_delta", "out_errors_delta", "in_discards_delta", "out_discards_delta"]
    if profile == "f5_connections":
        return ["current_connections"]
    if profile == "device_up":
        return ["current"]
    return []


def default_required_labels_for_profile(profile: str) -> List[str]:
    if profile in ("interface_traffic", "interface_errors"):
        return ["device_ip", "if_name"]
    if profile in ("f5_connections", "firewall_sessions", "device_up"):
        return ["device_ip"]
    return []


def build_target_context(plan: Dict[str, Any]) -> Dict[str, Any]:
    target_scope = plan.get("target_scope") or {}

    device_ip = first_non_empty(
        target_scope.get("device_ip"),
        target_scope.get("ip"),
        target_scope.get("instance"),
        target_scope.get("host_ip"),
    )

    if_name = first_non_empty(
        target_scope.get("if_name"),
        target_scope.get("ifName"),
        target_scope.get("interface"),
        target_scope.get("interface_name"),
        target_scope.get("object_name"),
    )

    return {
        "vendor": first_non_empty(target_scope.get("vendor")),
        "platform": first_non_empty(target_scope.get("platform")),
        "hostname": first_non_empty(target_scope.get("hostname"), target_scope.get("sysName")),
        "device_ip": device_ip,
        "ip": first_non_empty(target_scope.get("ip"), device_ip),
        "instance": first_non_empty(target_scope.get("instance"), device_ip),
        "if_name": if_name,
        "ifName": first_non_empty(target_scope.get("ifName"), if_name),
        "interface": first_non_empty(target_scope.get("interface"), if_name),
        "interface_name": first_non_empty(target_scope.get("interface_name"), if_name),
        "object_name": first_non_empty(target_scope.get("object_name"), if_name),
        "ifAlias": first_non_empty(target_scope.get("ifAlias"), target_scope.get("if_alias")),
        "job": first_non_empty(target_scope.get("job")),
        "alarm_type": first_non_empty(target_scope.get("alarm_type")),
    }


def find_missing_required_labels(required_labels: List[str], target_context: Dict[str, Any]) -> List[str]:
    missing: List[str] = []

    for label in required_labels:
        label = str(label).strip()
        if not label:
            continue

        if label == "device_ip":
            if not first_non_empty(target_context.get("device_ip"), target_context.get("ip"), target_context.get("instance")):
                missing.append(label)
            continue

        if label in ("if_name", "ifName", "interface"):
            if not first_non_empty(target_context.get("if_name"), target_context.get("ifName"), target_context.get("interface"), target_context.get("object_name")):
                missing.append(label)
            continue

        if not first_non_empty(target_context.get(label)):
            missing.append(label)

    return sorted(set(missing))


def normalize_prometheus_evidence_first(plan: Dict[str, Any]) -> Dict[str, Any]:
    runtime = plan.get("playbook_runtime") or {}
    raw = runtime.get("prometheus_evidence_first") or {}

    if not isinstance(raw, dict) or not raw:
        return {
            "enabled": False,
            "status": "not_configured",
            "reason": "playbook_runtime.prometheus_evidence_first not found",
        }

    enabled = bool(raw.get("enabled", False))
    profile = first_non_empty(raw.get("evidence_profile"), raw.get("profile"))
    if not profile:
        profile = infer_profile_from_plan(plan)

    query_names = raw.get("query_names")
    if not isinstance(query_names, list) or not query_names:
        query_names = default_query_names_for_profile(profile)

    required_labels = raw.get("required_labels")
    if not isinstance(required_labels, list) or not required_labels:
        required_labels = default_required_labels_for_profile(profile)

    target_context = build_target_context(plan)
    missing_labels = find_missing_required_labels(required_labels, target_context)

    lookback = int(raw.get("lookback_minutes") or 15)
    compare_offset = int(raw.get("compare_offset_minutes") or 5)
    step_seconds = int(raw.get("step_seconds") or 60)

    status = "disabled"
    if enabled:
        if profile == "unknown":
            status = "metadata_incomplete_profile_unknown"
        elif missing_labels:
            status = "metadata_ready_but_missing_required_labels"
        elif not query_names:
            status = "metadata_incomplete_query_names_empty"
        else:
            status = "metadata_ready"

    return {
        "enabled": enabled,
        "status": status,
        "runtime_stage": "plan_metadata_only",
        "source": "playbook.prometheus_evidence_first",
        "backend_preference": first_non_empty(raw.get("backend_preference"), "prometheus_mcp"),
        "fallback": first_non_empty(raw.get("fallback"), "http_api"),
        "evidence_profile": profile,
        "query_names": query_names,
        "lookback_minutes": lookback,
        "compare_offset_minutes": compare_offset,
        "step_seconds": step_seconds,
        "step": f"{step_seconds}s",
        "required_labels": required_labels,
        "missing_required_labels": missing_labels,
        "target_context": target_context,
        "stop_device_cli_if_not_confirmed": bool(raw.get("stop_device_cli_if_not_confirmed", False)),
        "unavailable_policy": first_non_empty(raw.get("unavailable_policy"), "continue_cli_evidence"),
        "raw": raw,
    }


def apply_prometheus_evidence_metadata_to_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    """
    返回一个带 prometheus_evidence_first 字段的新 plan。
    不执行任何 Prometheus 查询。
    """
    if not isinstance(plan, dict):
        return plan

    result = deepcopy(plan)
    meta = normalize_prometheus_evidence_first(result)
    result["prometheus_evidence_first"] = meta

    features = result.get("v8_features")
    if not isinstance(features, dict):
        features = {}

    features["prometheus_evidence_first"] = {
        "enabled": bool(meta.get("enabled")),
        "status": meta.get("status"),
        "runtime_stage": meta.get("runtime_stage"),
        "profile": meta.get("evidence_profile"),
        "query_names": meta.get("query_names") or [],
        "missing_required_labels": meta.get("missing_required_labels") or [],
    }
    result["v8_features"] = features

    return result
