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
        "max_commands_per_request": int(safety.get("max_commands_per_request", 5)),
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

    max_commands = int(cfg.get("max_commands_per_request", 5))
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
