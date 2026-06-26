import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import yaml


BASE_DIR = Path("/opt/netaiops-webhook")
CONFIG_FILE = BASE_DIR / "config.yaml"
AUDIT_DIR = BASE_DIR / "data" / "audit"
AUDIT_FILE = AUDIT_DIR / "safety_policy.ndjson"


DEFAULT_ALLOWED_CAPABILITIES = {
    "show_interface_detail",
    "show_interface_error_counters",
    "show_interface_brief",
    "show_portchannel_summary",
    "show_lacp_neighbor",
    "show_recent_logs",

    "show_bgp_peer_detail",
    "show_route_to_peer",
    "ping_peer",
    "show_bgp_config_snippet",
    "show_ospf_peer_detail",

    "show_device_cpu",
    "show_device_memory",

    "show_f5_pool_list",
    "show_f5_pool_members",
    "show_f5_pool_config",
    "show_f5_connections",
    "show_f5_performance",
}


DEFAULT_ALLOWED_PREFIXES = [
    "show ",
    "display ",
    "get ",
    "diagnose hardware deviceinfo ",
    "diagnose netlink ",
    "get router info ",
    "get system ",
    "get log ",
    "ping ",
    "traceroute ",
    "tmsh show ",
    "tmsh list ",
]


DEFAULT_DENY_PATTERNS = [
    r"^\s*conf(?:ig(?:ure)?)?\b",
    r"^\s*terminal\s+configure\b",
    r"^\s*configure\b",
    r"^\s*set\s+",
    r"^\s*unset\s+",
    r"^\s*delete\s+",
    r"^\s*edit\s+",
    r"^\s*add\s+",
    r"^\s*create\s+",
    r"^\s*modify\s+",
    r"^\s*remove\s+",
    r"^\s*clear\s+",
    r"^\s*reset\s+",
    r"^\s*reload\b",
    r"^\s*reboot\b",
    r"^\s*shutdown\b",
    r"^\s*no\s+shutdown\b",
    r"^\s*write\b",
    r"^\s*copy\s+",
    r"^\s*commit\b",
    r"^\s*save\b",
    r"^\s*erase\b",
    r"^\s*format\b",
    r"^\s*mkdir\b",
    r"^\s*rm\s+",
    r"^\s*mv\s+",
    r"^\s*chmod\b",
    r"^\s*chown\b",
    r"^\s*bash\b",
    r"^\s*python\b",
    r"^\s*sh\s+",
    r"^\s*sudo\b",
    r"^\s*systemctl\b",
    r"\|\s*bash\b",
    r"\|\s*sh\b",
    r";",
    r"&&",
    r"\|\|",
]


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def safe_lower(value: Any) -> str:
    return safe_text(value).lower()


def load_config() -> Dict[str, Any]:
    if not CONFIG_FILE.exists():
        return {}
    try:
        return yaml.safe_load(CONFIG_FILE.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def safety_config() -> Dict[str, Any]:
    cfg = load_config()
    safety = cfg.get("safety_policy", {}) or {}

    allowed_prefixes = safety.get("allowed_command_prefixes", DEFAULT_ALLOWED_PREFIXES)
    deny_patterns = safety.get("deny_command_patterns", DEFAULT_DENY_PATTERNS)
    allowed_capabilities = safety.get("allowed_capabilities", list(DEFAULT_ALLOWED_CAPABILITIES))

    return {
        "enabled": bool(safety.get("enabled", True)),
        "readonly_only": bool(safety.get("readonly_only", True)),
        "max_commands_per_request": int(safety.get("max_commands_per_request", 15)),
        "command_timeout_sec": int(safety.get("command_timeout_sec", 30)),
        "allowed_command_prefixes": [safe_lower(x) for x in allowed_prefixes],
        "deny_command_patterns": [safe_text(x) for x in deny_patterns],
        "allowed_capabilities": set(safe_text(x) for x in allowed_capabilities if safe_text(x)),
        "high_risk_devices": [safe_lower(x) for x in (safety.get("high_risk_devices", []) or [])],
        "audit_enabled": bool(safety.get("audit_enabled", True)),
    }


def append_audit(record: Dict[str, Any]) -> None:
    cfg = safety_config()
    if not cfg.get("audit_enabled", True):
        return

    try:
        AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        with AUDIT_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass


def command_has_denied_pattern(command: str, deny_patterns: List[str]) -> str:
    for pattern in deny_patterns:
        if not pattern:
            continue
        try:
            if re.search(pattern, command, flags=re.IGNORECASE):
                return pattern
        except Exception:
            continue
    return ""


def command_has_allowed_prefix(command: str, allowed_prefixes: List[str]) -> bool:
    cmd = safe_lower(command)
    return any(cmd.startswith(prefix) for prefix in allowed_prefixes)


def is_high_risk_device(plan_data: Dict[str, Any], high_risk_devices: List[str]) -> bool:
    target = plan_data.get("target_scope", {}) or {}

    values = [
        safe_lower(target.get("device_ip")),
        safe_lower(target.get("hostname")),
        safe_lower(target.get("mcp_device_name")),
        safe_lower(((plan_data.get("notify_view") or {}).get("device"))),
    ]

    values = [x for x in values if x]

    for item in high_risk_devices:
        if not item:
            continue
        for value in values:
            if item == value or item in value:
                return True

    return False


def evaluate_candidate(candidate: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    capability = safe_text(candidate.get("capability"))
    command = safe_text(candidate.get("command"))
    readonly = bool(candidate.get("readonly", True))

    reasons: List[str] = []

    if cfg.get("readonly_only", True) and not readonly:
        reasons.append("candidate_not_readonly")

    if capability and capability not in cfg.get("allowed_capabilities", set()):
        reasons.append("capability_not_allowed")

    denied_pattern = command_has_denied_pattern(command, cfg.get("deny_command_patterns", []))
    if denied_pattern:
        reasons.append(f"command_denied_pattern:{denied_pattern}")

    if command and not command_has_allowed_prefix(command, cfg.get("allowed_command_prefixes", [])):
        reasons.append("command_prefix_not_allowed")

    if not command:
        reasons.append("empty_command")

    return {
        "capability": capability,
        "command": command,
        "safe": len(reasons) == 0,
        "reasons": reasons,
    }


def evaluate_plan_safety(plan_data: Dict[str, Any]) -> Dict[str, Any]:
    cfg = safety_config()

    if not cfg.get("enabled", True):
        return {
            "enabled": False,
            "allowed": True,
            "reasons": [],
            "candidate_results": [],
        }

    candidates = plan_data.get("execution_candidates", []) or []
    reasons: List[str] = []
    candidate_results: List[Dict[str, Any]] = []

    max_commands = int(cfg.get("max_commands_per_request", 15))
    if len(candidates) > max_commands:
        reasons.append("too_many_commands")

    if is_high_risk_device(plan_data, cfg.get("high_risk_devices", [])):
        reasons.append("high_risk_device_plan_only")

    for candidate in candidates:
        result = evaluate_candidate(candidate, cfg)
        candidate_results.append(result)
        if not result.get("safe"):
            reasons.append("unsafe_candidate")

    reasons = list(dict.fromkeys(reasons))

    return {
        "enabled": True,
        "allowed": len(reasons) == 0,
        "reasons": reasons,
        "max_commands_per_request": max_commands,
        "command_timeout_sec": int(cfg.get("command_timeout_sec", 30)),
        "candidate_count": len(candidates),
        "candidate_results": candidate_results,
    }


def apply_safety_policy_to_plan(plan_data: Dict[str, Any]) -> Dict[str, Any]:
    plan_data = dict(plan_data or {})
    safety_result = evaluate_plan_safety(plan_data)
    plan_data["safety_result"] = safety_result

    timeout_sec = int(safety_result.get("command_timeout_sec", safety_config().get("command_timeout_sec", 30)))

    updated_candidates = []
    for candidate in plan_data.get("execution_candidates", []) or []:
        item = dict(candidate)
        item["timeout_sec"] = int(item.get("timeout_sec") or timeout_sec)
        updated_candidates.append(item)

    plan_data["execution_candidates"] = updated_candidates

    if not safety_result.get("allowed", True):
        plan_data["auto_confirm_recommended"] = False

        policy_result = dict(plan_data.get("policy_result", {}) or {})
        policy_result["auto_confirm_allowed"] = False

        old_reasons = list(policy_result.get("reasons", []) or [])
        for reason in safety_result.get("reasons", []) or []:
            if reason not in old_reasons:
                old_reasons.append(reason)

        policy_result["reasons"] = old_reasons
        policy_result["policy_summary"] = "blocked_by_safety_policy"

        checked_items = dict(policy_result.get("checked_items", {}) or {})
        checked_items["safety_policy_allowed"] = False
        checked_items["safety_reasons"] = safety_result.get("reasons", [])
        policy_result["checked_items"] = checked_items

        plan_data["policy_result"] = policy_result

    append_audit(
        {
            "time": now_utc(),
            "request_id": safe_text(plan_data.get("request_id")),
            "family": safe_text((plan_data.get("family_result") or {}).get("family")),
            "target_scope": plan_data.get("target_scope", {}),
            "safety_result": safety_result,
        }
    )

    return plan_data

# ===== v5 expanded family safety allowlist begin =====
# 将第六批新增 capability 加入安全白名单。
# 这些 capability 仍然只允许只读命令，最终命令还会继续经过 prefix / deny pattern 检查。

V5_EXPANDED_ALLOWED_CAPABILITIES = {
    "query_prometheus_metric_window",
    "query_elastic_related_logs",
    "show_device_environment",
    "show_fan_status",
    "show_power_status",
    "show_environment_temperature",
    "show_chassis_status",
    "show_module_status",
    "show_inventory",
    "show_interface_transceiver",
    "show_device_disk",
    "show_ha_state",
    "show_cimc_hardware_status",
}

try:
    DEFAULT_ALLOWED_CAPABILITIES.update(V5_EXPANDED_ALLOWED_CAPABILITIES)
except NameError:
    DEFAULT_ALLOWED_CAPABILITIES = set(V5_EXPANDED_ALLOWED_CAPABILITIES)
# ===== v5 expanded family safety allowlist end =====

# ===== v9.6 interface utilization high safety max command exception begin =====
# 背景：
# - 全局 safety_policy.max_commands_per_request 仍保持 15，不能整体放开。
# - interface_or_link_utilization_high 需要支持多接口聚合取证，首轮只读命令最多 30 条。
# - 这里只针对该 family / playbook 放开 too_many_commands。
# - 其它安全检查继续生效：unsafe_candidate、deny pattern、high_risk_device 等不会被绕过。
try:
    _v96_original_evaluate_plan_safety = evaluate_plan_safety
except NameError:
    _v96_original_evaluate_plan_safety = None


_V96_INTERFACE_UTILIZATION_FAMILIES = {
    "interface_or_link_utilization_high",
}

_V96_INTERFACE_UTILIZATION_PLAYBOOKS = {
    "cisco_interface_or_link_utilization_high",
    "cisco_interface_utilization_high",
    "interface_or_link_utilization_high",
}

_V96_INTERFACE_UTILIZATION_MAX_COMMANDS = 30


def _v96_safe_str(value):
    if value is None:
        return ""
    return str(value).strip()


def _v96_nested_get(mapping, *keys):
    current = mapping
    for key in keys:
        if not isinstance(current, dict):
            return ""
        current = current.get(key)
    return current


def _v96_plan_family_or_playbook(plan_data):
    if not isinstance(plan_data, dict):
        return "", ""

    family = _v96_safe_str(_v96_nested_get(plan_data, "family_result", "family"))
    if not family:
        family = _v96_safe_str(_v96_nested_get(plan_data, "classification", "family"))
    if not family:
        family = _v96_safe_str(_v96_nested_get(plan_data, "playbook_runtime", "family"))
    if not family:
        family = _v96_safe_str(plan_data.get("family"))

    playbook_id = _v96_safe_str(_v96_nested_get(plan_data, "playbook_runtime", "playbook_id"))
    if not playbook_id:
        playbook_id = _v96_safe_str(_v96_nested_get(plan_data, "playbook", "playbook_id"))
    if not playbook_id:
        playbook_id = _v96_safe_str(plan_data.get("playbook_id"))

    return family, playbook_id


def _v96_is_interface_utilization_plan(plan_data):
    family, playbook_id = _v96_plan_family_or_playbook(plan_data)
    return family in _V96_INTERFACE_UTILIZATION_FAMILIES or playbook_id in _V96_INTERFACE_UTILIZATION_PLAYBOOKS


def _v96_apply_interface_utilization_safety_exception(plan_data, safety_result):
    if not isinstance(safety_result, dict):
        return safety_result

    if not _v96_is_interface_utilization_plan(plan_data):
        return safety_result

    candidates = plan_data.get("execution_candidates", []) if isinstance(plan_data, dict) else []
    if candidates is None:
        candidates = []

    candidate_count = int(safety_result.get("candidate_count", len(candidates)) or 0)

    # 只允许 30 条以内；超过 30 条仍然阻断。
    if candidate_count > _V96_INTERFACE_UTILIZATION_MAX_COMMANDS:
        result = dict(safety_result)
        result["max_commands_per_request"] = _V96_INTERFACE_UTILIZATION_MAX_COMMANDS
        reasons = list(result.get("reasons") or [])
        if "too_many_commands" not in reasons:
            reasons.append("too_many_commands")
        result["reasons"] = list(dict.fromkeys(reasons))
        result["allowed"] = False
        result["family_max_commands_exception"] = {
            "matched": True,
            "family": _v96_plan_family_or_playbook(plan_data)[0],
            "playbook_id": _v96_plan_family_or_playbook(plan_data)[1],
            "max_commands_per_request": _V96_INTERFACE_UTILIZATION_MAX_COMMANDS,
            "applied": False,
            "reason": "candidate_count_exceeds_family_limit",
        }
        return result

    reasons = list(safety_result.get("reasons") or [])

    # 仅移除 too_many_commands；其它原因必须保留。
    filtered_reasons = [r for r in reasons if r != "too_many_commands"]

    result = dict(safety_result)
    result["reasons"] = filtered_reasons
    result["max_commands_per_request"] = _V96_INTERFACE_UTILIZATION_MAX_COMMANDS
    result["allowed"] = len(filtered_reasons) == 0
    result["family_max_commands_exception"] = {
        "matched": True,
        "family": _v96_plan_family_or_playbook(plan_data)[0],
        "playbook_id": _v96_plan_family_or_playbook(plan_data)[1],
        "max_commands_per_request": _V96_INTERFACE_UTILIZATION_MAX_COMMANDS,
        "applied": "too_many_commands" in reasons,
        "original_reasons": reasons,
        "remaining_reasons": filtered_reasons,
    }
    return result


if _v96_original_evaluate_plan_safety is not None:
    def evaluate_plan_safety(plan_data):
        result = _v96_original_evaluate_plan_safety(plan_data)
        try:
            return _v96_apply_interface_utilization_safety_exception(plan_data, result)
        except Exception:
            return result
# ===== v9.6 interface utilization high safety max command exception end =====
