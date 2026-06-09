from typing import Any, Dict

SUPPORTED_VENDORS = {
    "huawei",
    "cisco",
    "fortigate",
    "f5",
    "hillstone",
}

SUPPORTED_SOURCES = {
    "alertmanager",
    "elastic",
}


def _safe_lower(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def evaluate_auto_confirm_policy(plan: Dict[str, Any], classification: Dict[str, Any], playbook: Dict[str, Any]) -> Dict[str, Any]:
    target_scope = plan.get("target_scope", {}) or {}
    guard_result = plan.get("guard_result", {}) or {}
    execution_candidates = plan.get("execution_candidates", []) or []
    execution_cfg = playbook.get("execution", {}) or {}

    vendor = _safe_lower(target_scope.get("vendor"))
    source = _safe_lower(plan.get("source"))
    device_ip = str(target_scope.get("device_ip", "")).strip()

    readonly_only = bool(execution_cfg.get("readonly_only", False))
    auto_execute_enabled = bool(execution_cfg.get("auto_execute_allowed", False))
    classification_auto = bool(classification.get("auto_execute_allowed", False))

    reasons = []

    if not plan.get("readonly_only", False):
        reasons.append("plan_not_readonly_only")

    if not guard_result.get("all_readonly", False):
        reasons.append("guard_not_all_readonly")

    # v7.12:
    # 如果显式 playbook 已声明 auto_execute_allowed=true，且全部命令通过只读安全检查，
    # 则不再因为 classifier 没有标记 auto_execute_allowed 而阻断真实告警的自动只读取证。
    if not classification_auto and not auto_execute_enabled:
        reasons.append("classification_not_allow_auto_execute")

    if vendor not in SUPPORTED_VENDORS:
        reasons.append("vendor_not_supported")

    if source not in SUPPORTED_SOURCES:
        reasons.append("source_not_supported")

    if not device_ip:
        reasons.append("device_ip_missing")

    max_commands = int(execution_cfg.get("max_commands", 15) or 15)
    if len(execution_candidates) > max_commands:
        reasons.append("command_count_exceeded")

    if not readonly_only:
        reasons.append("playbook_not_readonly_only")

    if not auto_execute_enabled:
        reasons.append("playbook_auto_execute_disabled")

    allowed = len(reasons) == 0

    return {
        "auto_confirm_allowed": allowed,
        "reasons": reasons,
        "policy_summary": "allowed" if allowed else "blocked",
        "checked_items": {
            "vendor": vendor,
            "source": source,
            "device_ip_present": bool(device_ip),
            "readonly_only": plan.get("readonly_only", False),
            "guard_all_readonly": guard_result.get("all_readonly", False),
            "classification_auto_execute_allowed": classification_auto,
            "playbook_auto_execute_allowed": auto_execute_enabled,
            "command_count": len(execution_candidates),
            "max_commands": max_commands,
        },
    }
