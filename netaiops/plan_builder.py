import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from netaiops.classifier import classify_event
from netaiops.family_registry import classify_family
from netaiops.capability_registry import build_capability_plan
from netaiops.capability_planner import refine_capability_plan
from netaiops.platform_command_matrix import resolve_execution_candidates
from netaiops.playbook_loader import (
    build_execution_candidates_from_playbook,
    find_best_playbook,
)
from netaiops.policy_engine import evaluate_auto_confirm_policy


BASE_DIR = Path("/opt/netaiops-webhook")
DATA_DIR = BASE_DIR / "data"
ANALYSIS_DIR = DATA_DIR / "analysis"
PLAN_DIR = DATA_DIR / "plans"


READONLY_PREFIXES = [
    "show ",
    "display ",
    "get ",
    "ping ",
    "traceroute ",
    "diagnose ",
    "tmsh show ",
    "tmsh list ",
]

DANGEROUS_PREFIXES = [
    "conf t",
    "configure",
    "shutdown",
    "undo shutdown",
    "reload",
    "reboot",
    "reset",
    "delete",
    "erase",
    "format",
    "write memory",
    "copy run start",
    "save ",
    "commit",
    "interface ",
    "router ",
    "network ",
    "neighbor ",
    "set ",
    "unset ",
    "clear ",
    "execute ",
]


def now_utc_str() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json_file(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def safe_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def analysis_file_by_request_id(request_id: str) -> Path:
    files = list(ANALYSIS_DIR.glob(f"*_{request_id}.analysis.json"))
    if not files:
        raise FileNotFoundError(f"analysis file not found for request_id={request_id}")
    return files[0]


def plan_file_by_request_id(request_id: str) -> Path:
    files = list(PLAN_DIR.glob(f"*_{request_id}.plan.json"))
    if not files:
        raise FileNotFoundError(f"plan file not found for request_id={request_id}")
    return files[0]


def latest_plan_file() -> Path:
    files = sorted(PLAN_DIR.glob("*.plan.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        raise FileNotFoundError("no plan files found")
    return files[0]


def command_is_readonly(command: str) -> bool:
    cmd = (command or "").strip().lower()

    if not cmd:
        return False

    for prefix in DANGEROUS_PREFIXES:
        if cmd.startswith(prefix):
            return False

    for prefix in READONLY_PREFIXES:
        if cmd.startswith(prefix):
            return True

    return False


def build_guard_result(execution_candidates: List[Dict[str, Any]]) -> dict:
    blocked_commands = []
    allowed_commands = []

    for item in execution_candidates:
        cmd = (item or {}).get("command", "")
        readonly = command_is_readonly(cmd)

        if readonly:
            allowed_commands.append(cmd)
        else:
            blocked_commands.append(cmd)

        item["readonly"] = readonly
        item["risk"] = "low" if readonly else "high"

    return {
        "all_readonly": len(blocked_commands) == 0,
        "allowed_count": len(allowed_commands),
        "blocked_count": len(blocked_commands),
        "allowed_commands": allowed_commands,
        "blocked_commands": blocked_commands,
    }


def normalize_execution_candidates(command_plan: list, suggested_commands: list) -> list:
    commands = []

    if isinstance(command_plan, list):
        commands.extend([x for x in command_plan if isinstance(x, str) and x.strip()])

    if not commands and isinstance(suggested_commands, list):
        commands.extend([x for x in suggested_commands if isinstance(x, str) and x.strip()])

    candidates = []
    for idx, cmd in enumerate(commands, start=1):
        candidates.append(
            {
                "order": idx,
                "command": cmd,
                "reason": "generated_from_analysis",
                "risk": "unknown",
                "readonly": False,
            }
        )
    return candidates


def _build_target_scope(event: Dict[str, Any], family_result: Dict[str, Any]) -> Dict[str, Any]:
    vendor = event.get("vendor", "")
    platform = event.get("platform", "")
    hostname = event.get("hostname", "")
    device_ip = event.get("device_ip", "") or event.get("ip", "") or event.get("host_ip", "")
    alarm_type = event.get("alarm_type", "") or event.get("event_type", "")

    scope = {
        "vendor": vendor,
        "platform": platform,
        "hostname": hostname,
        "device_ip": device_ip,
        "alarm_type": alarm_type,
    }

    family_scope = dict((family_result or {}).get("target_scope", {}) or {})
    for key, value in family_scope.items():
        if value not in (None, "", [], {}):
            scope[key] = value

    return scope


def _build_registry_policy_playbook(family_result: Dict[str, Any], capability_plan: Dict[str, Any]) -> Dict[str, Any]:
    selected = capability_plan.get("selected_capabilities", []) or []
    return {
        "playbook_id": family_result.get("legacy_playbook_type") or family_result.get("family") or "capability_registry",
        "execution": {
            "readonly_only": bool(capability_plan.get("readonly_only", True)),
            "auto_execute_allowed": bool(family_result.get("auto_execute_allowed", False)),
            "max_commands": max(len(selected), 5),
        },
    }


def build_plan_from_analysis_data(analysis_data: dict) -> dict:
    result = analysis_data.get("result", {}) or {}
    event = analysis_data.get("event", {}) or {}

    request_id = analysis_data.get("request_id", "")
    source = analysis_data.get("source", "")
    summary = result.get("summary", "")
    recommended_next_step = result.get("recommended_next_step", "")
    command_plan = result.get("command_plan", []) or []
    suggested_commands = result.get("suggested_commands", []) or []
    confidence = result.get("confidence", "low")

    event_for_plan = {
        **event,
        "source": source,
    }

    family_result = classify_family(event_for_plan)
    classification = classify_event(event_for_plan)

    capability_plan = build_capability_plan(event_for_plan, family_result)
    capability_plan = refine_capability_plan(event_for_plan, family_result, capability_plan)
    registry_execution_candidates = resolve_execution_candidates(
        event_for_plan,
        family_result,
        capability_plan,
    )

    playbook = find_best_playbook(event_for_plan, classification)
    policy_playbook = None
    playbook_meta = {
        "matched": False,
        "playbook_id": "",
        "playbook_file": "",
        "mode": "",
    }

    if registry_execution_candidates:
        execution_candidates = registry_execution_candidates
        execution_source = "capability_registry"
        policy_playbook = _build_registry_policy_playbook(family_result, capability_plan)
        playbook_meta = {
            "matched": True,
            "playbook_id": family_result.get("legacy_playbook_type") or family_result.get("family", ""),
            "playbook_file": "",
            "mode": "capability_registry",
        }
    elif playbook:
        execution_candidates = build_execution_candidates_from_playbook(playbook, event_for_plan)
        execution_source = "playbook"
        policy_playbook = playbook
        playbook_meta = {
            "matched": True,
            "playbook_id": (playbook or {}).get("playbook_id", ""),
            "playbook_file": (playbook or {}).get("_file", ""),
            "mode": "legacy_playbook",
        }
    else:
        execution_candidates = normalize_execution_candidates(command_plan, suggested_commands)
        execution_source = "analysis"
        playbook_meta = {
            "matched": False,
            "playbook_id": "",
            "playbook_file": "",
            "mode": "analysis_fallback",
        }

    guard_result = build_guard_result(execution_candidates)
    target_scope = _build_target_scope(event_for_plan, family_result)

    plan = {
        "request_id": request_id,
        "plan_id": f"plan_{uuid.uuid4().hex[:12]}",
        "source": source,
        "plan_type": "network_readonly_diagnosis",
        "plan_status": "generated",
        "readonly_only": guard_result["all_readonly"],
        "requires_confirmation": True,
        "confidence": confidence,
        "summary": summary,
        "recommended_next_step": recommended_next_step,
        "target_scope": target_scope,
        "execution_candidates": execution_candidates,
        "guard_result": guard_result,
        "analysis_file": "",
        "generated_at": now_utc_str(),
        "confirmed_at": None,
        "classification": classification,
        "family_result": family_result,
        "capability_plan": capability_plan,
        "playbook": playbook_meta,
        "execution_source": execution_source,
        "auto_confirm_recommended": False,
        "policy_result": {
            "auto_confirm_allowed": False,
            "reasons": ["policy_not_evaluated"],
            "policy_summary": "not_evaluated",
            "checked_items": {},
        },
    }

    if policy_playbook:
        policy_result = evaluate_auto_confirm_policy(plan, classification, policy_playbook)
        plan["policy_result"] = policy_result
        plan["auto_confirm_recommended"] = policy_result.get("auto_confirm_allowed", False)

    return plan


def generate_plan_for_request_id(request_id: str) -> dict:
    analysis_path = analysis_file_by_request_id(request_id)
    analysis_data = read_json_file(analysis_path)

    if analysis_data.get("analysis_status") != "success":
        raise ValueError(f"analysis is not successful for request_id={request_id}")

    plan = build_plan_from_analysis_data(analysis_data)
    plan["analysis_file"] = str(analysis_path)

    source = analysis_data.get("source", "unknown")
    plan_path = PLAN_DIR / f"{source}_{request_id}.plan.json"
    safe_write_json(plan_path, plan)

    return {
        "plan_file": str(plan_path),
        "plan_data": plan,
    }


def get_plan_by_request_id(request_id: str) -> dict:
    path = plan_file_by_request_id(request_id)
    return {
        "plan_file": str(path),
        "plan_data": read_json_file(path),
    }


def get_latest_plan() -> dict:
    path = latest_plan_file()
    return {
        "plan_file": str(path),
        "plan_data": read_json_file(path),
    }


def confirm_plan_for_request_id(request_id: str) -> dict:
    path = plan_file_by_request_id(request_id)
    plan = read_json_file(path)

    guard_result = plan.get("guard_result", {}) or {}
    all_readonly = guard_result.get("all_readonly", False)

    if not all_readonly:
        raise ValueError(f"plan contains blocked commands, request_id={request_id}")

    plan["plan_status"] = "confirmed"
    plan["confirmed_at"] = now_utc_str()

    safe_write_json(path, plan)

    return {
        "plan_file": str(path),
        "plan_data": plan,
    }


# ===== v5 alert throttle wrapper begin =====
# 说明：
# 原 generate_plan_for_request_id 保持不改，在其外层增加节流/去重策略。
# 这样可以避免强依赖 plan_builder.py 内部 safe_write_json 的具体写法。
try:
    _v5_original_generate_plan_for_request_id = generate_plan_for_request_id

    def generate_plan_for_request_id(request_id: str):
        from pathlib import Path as _Path
        from netaiops.alert_throttle import apply_throttle_to_plan as _apply_throttle_to_plan

        result = _v5_original_generate_plan_for_request_id(request_id)

        if not isinstance(result, dict):
            return result

        plan_data = result.get("plan_data")
        plan_file = result.get("plan_file")

        if not isinstance(plan_data, dict):
            return result

        plan_data = _apply_throttle_to_plan(plan_data)
        result["plan_data"] = plan_data

        if plan_file:
            safe_write_json(_Path(plan_file), plan_data)

        return result

except NameError:
    # 如果未来文件结构变化导致 generate_plan_for_request_id 尚未定义，
    # 则不在 import 阶段阻断服务启动。
    pass
# ===== v5 alert throttle wrapper end =====


# ===== v5 safety policy wrapper begin =====
# 在现有 generate_plan_for_request_id 外层增加最终安全策略。
# 执行顺序位于 family/capability/platform/throttle 之后，确保最终渲染命令也会被检查。
try:
    _v5_safety_original_generate_plan_for_request_id = generate_plan_for_request_id

    def generate_plan_for_request_id(request_id: str):
        from pathlib import Path as _Path
        from netaiops.safety_policy import apply_safety_policy_to_plan as _apply_safety_policy_to_plan

        result = _v5_safety_original_generate_plan_for_request_id(request_id)

        if not isinstance(result, dict):
            return result

        plan_data = result.get("plan_data")
        plan_file = result.get("plan_file")

        if not isinstance(plan_data, dict):
            return result

        plan_data = _apply_safety_policy_to_plan(plan_data)
        result["plan_data"] = plan_data

        if plan_file:
            safe_write_json(_Path(plan_file), plan_data)

        return result

except NameError:
    pass
# ===== v5 safety policy wrapper end =====

