import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from netaiops.classifier import classify_event
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


def _build_target_scope(event: Dict[str, Any]) -> Dict[str, Any]:
    vendor = event.get("vendor", "")
    hostname = event.get("hostname", "")
    device_ip = event.get("device_ip", "") or event.get("ip", "") or event.get("host_ip", "")
    alarm_type = event.get("alarm_type", "") or event.get("event_type", "")

    return {
        "vendor": vendor,
        "hostname": hostname,
        "device_ip": device_ip,
        "alarm_type": alarm_type,
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

    classification = classify_event(
        {
            **event,
            "source": source,
        }
    )

    playbook = find_best_playbook(event, classification)

    if playbook:
        execution_candidates = build_execution_candidates_from_playbook(playbook, event)
        execution_source = "playbook"
    else:
        execution_candidates = normalize_execution_candidates(command_plan, suggested_commands)
        execution_source = "analysis"

    guard_result = build_guard_result(execution_candidates)
    target_scope = _build_target_scope(event)

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
        "playbook": {
            "matched": bool(playbook),
            "playbook_id": (playbook or {}).get("playbook_id", ""),
            "playbook_file": (playbook or {}).get("_file", ""),
        },
        "execution_source": execution_source,
        "auto_confirm_recommended": False,
        "policy_result": {
            "auto_confirm_allowed": False,
            "reasons": ["policy_not_evaluated"],
            "policy_summary": "not_evaluated",
            "checked_items": {},
        },
    }

    if playbook:
        policy_result = evaluate_auto_confirm_policy(plan, classification, playbook)
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
