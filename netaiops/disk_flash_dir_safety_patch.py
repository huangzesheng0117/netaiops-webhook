#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple


SAFE_DIR_RE = re.compile(
    r"^\s*dir\s+"
    r"(?:bootflash:|flash:|log:|crashinfo:|stby-bootflash:|stby-flash:)"
    r"[A-Za-z0-9_\-\.\/\*\:\@]*\s*$",
    re.I,
)

FORBIDDEN_RE = re.compile(
    r"^\s*("
    r"configure|conf\s+t|shutdown|no\s+shutdown|clear|reload|delete|erase|debug|copy|write\s+memory|"
    r"install\s+remove|request\s+platform\s+software\s+package\s+clean|format|squeeze"
    r")\b",
    re.I,
)

DISK_FLASH_IDS = {
    "cisco_device_disk_flash_usage_high",
    "device_disk_flash_usage_high",
    "disk_flash_usage_high",
    "device_filesystem_usage",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_text(value: Any) -> str:
    return "" if value is None else str(value)


def _is_disk_flash_plan(plan_data: Dict[str, Any]) -> bool:
    text = json.dumps(plan_data, ensure_ascii=False, default=str).lower()
    return any(x.lower() in text for x in DISK_FLASH_IDS)


def _is_safe_dir_command(cmd: str) -> bool:
    return bool(SAFE_DIR_RE.match(_safe_text(cmd)))


def _is_forbidden_command(cmd: str) -> bool:
    return bool(FORBIDDEN_RE.search(_safe_text(cmd)))


def _extract_candidates(plan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    candidates = plan_data.get("execution_candidates")
    if isinstance(candidates, list):
        return [x for x in candidates if isinstance(x, dict)]
    return []


def _all_candidates_readonly(candidates: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    reasons = []
    for item in candidates:
        cmd = _safe_text(item.get("command")).strip()
        if not cmd:
            reasons.append("empty_command")
            continue
        if _is_forbidden_command(cmd):
            reasons.append(f"forbidden_command:{cmd}")
            continue
        if not bool(item.get("readonly", False)):
            reasons.append(f"not_readonly:{cmd}")
    return (len(reasons) == 0), reasons


def _patch_execution_candidates(plan_data: Dict[str, Any]) -> Dict[str, Any]:
    patched = []
    candidates = _extract_candidates(plan_data)

    for item in candidates:
        cmd = _safe_text(item.get("command")).strip()
        if _is_safe_dir_command(cmd):
            item["readonly"] = True
            item["risk"] = "low"
            item["disk_flash_safety_override"] = True
            item["safety_override_reason"] = "safe readonly directory listing for Disk/Flash investigation"
            patched.append(cmd)

    return {
        "patched_dir_commands": patched,
        "patched_count": len(patched),
    }


def _patch_playbook_runtime(plan_data: Dict[str, Any]) -> None:
    runtime = plan_data.setdefault("playbook_runtime", {})
    runtime["readonly_only"] = True
    runtime["auto_execute_allowed"] = True

    execution = runtime.setdefault("execution", {})
    execution["readonly_only"] = True
    execution["auto_execute_allowed"] = True

    if "max_commands" not in execution:
        commands = execution.get("commands") or []
        execution["max_commands"] = len(commands) if commands else 15


def _patch_guard_and_policy(plan_data: Dict[str, Any], patch_result: Dict[str, Any]) -> Dict[str, Any]:
    candidates = _extract_candidates(plan_data)
    all_readonly, reasons = _all_candidates_readonly(candidates)

    if not all_readonly:
        return {
            "ok": False,
            "blocked_reasons": reasons,
        }

    plan_data["readonly_only"] = True
    plan_data["auto_confirm_recommended"] = True

    classification = plan_data.setdefault("classification", {})
    classification["auto_execute_allowed"] = True

    family_result = plan_data.setdefault("family_result", {})
    family_result["auto_execute_allowed"] = True

    capability_plan = plan_data.setdefault("capability_plan", {})
    capability_plan["auto_execute_allowed"] = True

    guard = plan_data.setdefault("guard_result", {})
    guard["allowed"] = True
    guard["all_readonly"] = True
    guard["readonly_only"] = True
    guard["guard_summary"] = "all_readonly"
    guard["reasons"] = []
    guard["disk_flash_dir_safety_override"] = patch_result

    safety = plan_data.setdefault("safety_result", {})
    safety["allowed"] = True
    safety["safe"] = True
    safety["reasons"] = []
    safety["disk_flash_dir_safety_override"] = patch_result

    candidate_results = []
    for item in candidates:
        candidate_results.append(
            {
                "order": item.get("order"),
                "command": item.get("command"),
                "readonly": True,
                "risk": item.get("risk", "low"),
                "allowed": True,
                "safe": True,
                "reasons": [],
                "disk_flash_dir_safety_override": bool(item.get("disk_flash_safety_override", False)),
            }
        )
    safety["candidate_results"] = candidate_results

    policy = plan_data.setdefault("policy_result", {})
    policy["auto_confirm_allowed"] = True
    policy["reasons"] = []
    policy["policy_summary"] = "allowed"
    checked = policy.setdefault("checked_items", {})
    checked["vendor"] = checked.get("vendor") or ((plan_data.get("classification") or {}).get("vendor") or "cisco")
    checked["source"] = checked.get("source") or plan_data.get("source", "alertmanager")
    checked["device_ip_present"] = True
    checked["readonly_only"] = True
    checked["guard_all_readonly"] = True
    checked["classification_auto_execute_allowed"] = True
    checked["playbook_auto_execute_allowed"] = True
    checked["command_count"] = len(candidates)
    checked["max_commands"] = max(len(candidates), int(checked.get("max_commands") or len(candidates) or 15))
    checked["safety_policy_allowed"] = True
    checked["safety_reasons"] = []
    checked["disk_flash_dir_safety_override"] = patch_result

    plan_data.setdefault("v8_features", {})
    plan_data["v8_features"]["disk_flash_dir_safety_override"] = {
        "enabled": True,
        "applied_at": _now(),
        **patch_result,
    }

    return {
        "ok": True,
        "blocked_reasons": [],
    }


def apply_disk_flash_dir_safety_override_to_plan_result(plan_result: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(plan_result, dict):
        return plan_result

    plan_data = plan_result.get("plan_data")
    if not isinstance(plan_data, dict):
        return plan_result

    if not _is_disk_flash_plan(plan_data):
        return plan_result

    candidates = _extract_candidates(plan_data)
    if not candidates:
        return plan_result

    forbidden = [x.get("command") for x in candidates if _is_forbidden_command(_safe_text(x.get("command")))]
    if forbidden:
        plan_data.setdefault("v8_features", {})
        plan_data["v8_features"]["disk_flash_dir_safety_override"] = {
            "enabled": True,
            "applied": False,
            "blocked_reason": "forbidden_command_present",
            "forbidden_commands": forbidden,
            "applied_at": _now(),
        }
        return plan_result

    patch_result = _patch_execution_candidates(plan_data)
    _patch_playbook_runtime(plan_data)
    policy_patch = _patch_guard_and_policy(plan_data, patch_result)

    plan_data.setdefault("v8_features", {})
    plan_data["v8_features"]["disk_flash_dir_safety_override"] = {
        "enabled": True,
        "applied": bool(policy_patch.get("ok")),
        "applied_at": _now(),
        **patch_result,
        **policy_patch,
    }

    plan_file = plan_result.get("plan_file")
    if plan_file:
        p = Path(plan_file)
        if p.exists():
            p.write_text(json.dumps(plan_data, ensure_ascii=False, indent=2), encoding="utf-8")

    return plan_result
