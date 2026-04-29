import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


BASE_DIR = Path("/opt/netaiops-webhook")
CONFIG_FILE = BASE_DIR / "config.yaml"
DATA_DIR = BASE_DIR / "data"
NORMALIZED_DIR = DATA_DIR / "normalized"
PLAN_DIR = DATA_DIR / "plans"
DISPATCH_DIR = DATA_DIR / "dispatch"
EXECUTION_DIR = DATA_DIR / "execution"
REVIEW_DIR = DATA_DIR / "reviews"


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


def throttle_config() -> Dict[str, Any]:
    cfg = load_config()
    throttle = cfg.get("alert_throttle", {}) or {}

    return {
        "enabled": bool(throttle.get("enabled", True)),
        "cooldown_minutes": int(throttle.get("cooldown_minutes", 10)),
        "active_window_minutes": int(throttle.get("active_window_minutes", 5)),
        "resolved_disable_auto_execute": bool(throttle.get("resolved_disable_auto_execute", True)),
        "same_device_concurrency_limit": int(throttle.get("same_device_concurrency_limit", 1)),
    }


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_datetime(value: Any) -> Optional[datetime]:
    text = safe_text(value)
    if not text:
        return None

    text = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def parse_request_time(request_id: str) -> Optional[datetime]:
    text = safe_text(request_id)
    try:
        base = "_".join(text.split("_")[:2])
        dt = datetime.strptime(base, "%Y%m%d_%H%M%S")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def load_json_file(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def find_file_by_request_id(directory: Path, request_id: str, suffix: str) -> Optional[Path]:
    files = list(directory.glob(f"*_{request_id}.{suffix}"))
    if files:
        return files[0]
    return None


def request_id_from_plan_file(path: Path) -> str:
    name = path.name
    if "_" not in name:
        return ""
    if name.endswith(".plan.json"):
        name = name[:-len(".plan.json")]
    return name.split("_", 1)[1]


def load_event_status(request_id: str) -> str:
    norm_file = find_file_by_request_id(NORMALIZED_DIR, request_id, "json")
    if norm_file and norm_file.exists():
        data = load_json_file(norm_file)
        events = data.get("events", []) or []
        if events:
            return safe_lower(events[0].get("status"))

    return ""


def plan_generated_time(plan_data: Dict[str, Any], plan_path: Optional[Path] = None) -> datetime:
    for key in ("generated_at", "confirmed_at", "created_at"):
        dt = parse_datetime(plan_data.get(key))
        if dt:
            return dt

    rid = safe_text(plan_data.get("request_id"))
    dt = parse_request_time(rid)
    if dt:
        return dt

    if plan_path and plan_path.exists():
        return datetime.fromtimestamp(plan_path.stat().st_mtime, tz=timezone.utc)

    return now_utc()


def build_dedup_key(plan_data: Dict[str, Any]) -> Dict[str, str]:
    target = plan_data.get("target_scope", {}) or {}
    family_result = plan_data.get("family_result", {}) or {}
    classification = plan_data.get("classification", {}) or {}
    playbook = plan_data.get("playbook", {}) or {}

    family = (
        safe_text(family_result.get("family"))
        or safe_text(classification.get("family"))
        or safe_text(classification.get("playbook_type"))
        or safe_text(playbook.get("playbook_id"))
    )

    device_ip = safe_text(target.get("device_ip"))
    interface = safe_text(target.get("interface"))
    peer_ip = safe_text(target.get("peer_ip"))
    pool_member = safe_text(target.get("pool_member"))
    alarm_type = safe_text(target.get("alarm_type"))

    object_id = interface or peer_ip or pool_member or alarm_type or "device"

    return {
        "family": safe_lower(family),
        "device_ip": safe_lower(device_ip),
        "object_id": safe_lower(object_id),
    }


def same_dedup_key(a: Dict[str, str], b: Dict[str, str]) -> bool:
    return (
        a.get("family") == b.get("family")
        and a.get("device_ip") == b.get("device_ip")
        and a.get("object_id") == b.get("object_id")
    )


def execution_exists(request_id: str) -> bool:
    return bool(find_file_by_request_id(EXECUTION_DIR, request_id, "execution.json"))


def review_exists(request_id: str) -> bool:
    return bool(find_file_by_request_id(REVIEW_DIR, request_id, "review.json"))


def dispatch_exists(request_id: str) -> bool:
    return (DISPATCH_DIR / f"{request_id}.dispatch.request.json").exists()


def plan_has_completed_or_started_work(request_id: str, plan_data: Dict[str, Any]) -> bool:
    status = safe_lower(plan_data.get("plan_status"))
    if status in ("confirmed", "executing", "executed", "completed"):
        return True
    if execution_exists(request_id):
        return True
    if review_exists(request_id):
        return True
    if dispatch_exists(request_id):
        return True
    return False


def find_recent_duplicate_plan(current_plan: Dict[str, Any], cooldown_minutes: int) -> Dict[str, Any]:
    current_rid = safe_text(current_plan.get("request_id"))
    current_key = build_dedup_key(current_plan)
    current_time = plan_generated_time(current_plan)

    if not current_key.get("family") or not current_key.get("device_ip"):
        return {}

    for path in sorted(PLAN_DIR.glob("*.plan.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        rid = request_id_from_plan_file(path)
        if not rid or rid == current_rid:
            continue

        old_plan = load_json_file(path)
        old_key = build_dedup_key(old_plan)
        if not same_dedup_key(current_key, old_key):
            continue

        old_time = plan_generated_time(old_plan, path)
        age_minutes = abs((current_time - old_time).total_seconds()) / 60.0

        if age_minutes <= cooldown_minutes and plan_has_completed_or_started_work(rid, old_plan):
            return {
                "request_id": rid,
                "plan_file": str(path),
                "age_minutes": round(age_minutes, 2),
                "dedup_key": old_key,
                "plan_status": old_plan.get("plan_status", ""),
            }

    return {}


def find_active_same_device_dispatch(current_plan: Dict[str, Any], active_window_minutes: int) -> List[Dict[str, Any]]:
    current_rid = safe_text(current_plan.get("request_id"))
    target = current_plan.get("target_scope", {}) or {}
    device_ip = safe_lower(target.get("device_ip"))

    if not device_ip:
        return []

    current_time = plan_generated_time(current_plan)
    active: List[Dict[str, Any]] = []

    for path in sorted(DISPATCH_DIR.glob("*.dispatch.request.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        rid = path.name.replace(".dispatch.request.json", "")
        if not rid or rid == current_rid:
            continue

        if execution_exists(rid):
            continue

        data = load_json_file(path)
        old_target = data.get("target_scope", {}) or {}
        old_device_ip = safe_lower(old_target.get("device_ip"))

        if old_device_ip != device_ip:
            continue

        old_time = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        age_minutes = abs((current_time - old_time).total_seconds()) / 60.0

        if age_minutes <= active_window_minutes:
            active.append(
                {
                    "request_id": rid,
                    "dispatch_file": str(path),
                    "age_minutes": round(age_minutes, 2),
                    "device_ip": old_device_ip,
                }
            )

    return active


def evaluate_plan_throttle(plan_data: Dict[str, Any]) -> Dict[str, Any]:
    cfg = throttle_config()

    if not cfg.get("enabled"):
        return {
            "enabled": False,
            "allowed": True,
            "reasons": [],
            "dedup_key": build_dedup_key(plan_data),
        }

    request_id = safe_text(plan_data.get("request_id"))
    status = load_event_status(request_id)
    reasons: List[str] = []
    details: Dict[str, Any] = {}

    if cfg.get("resolved_disable_auto_execute") and status == "resolved":
        reasons.append("resolved_alert_no_auto_execute")

    duplicate = find_recent_duplicate_plan(plan_data, int(cfg["cooldown_minutes"]))
    if duplicate:
        reasons.append("cooldown_duplicate_alert")
        details["duplicate"] = duplicate

    active_same_device = find_active_same_device_dispatch(plan_data, int(cfg["active_window_minutes"]))
    limit = int(cfg.get("same_device_concurrency_limit", 1))
    if limit > 0 and len(active_same_device) >= limit:
        reasons.append("same_device_active_dispatch_limit")
        details["active_same_device"] = active_same_device

    return {
        "enabled": True,
        "allowed": len(reasons) == 0,
        "reasons": reasons,
        "dedup_key": build_dedup_key(plan_data),
        "event_status": status,
        "cooldown_minutes": int(cfg["cooldown_minutes"]),
        "active_window_minutes": int(cfg["active_window_minutes"]),
        "same_device_concurrency_limit": limit,
        **details,
    }


def apply_throttle_to_plan(plan_data: Dict[str, Any]) -> Dict[str, Any]:
    plan_data = dict(plan_data or {})
    throttle_result = evaluate_plan_throttle(plan_data)
    plan_data["throttle_result"] = throttle_result

    if throttle_result.get("allowed", True):
        return plan_data

    plan_data["auto_confirm_recommended"] = False

    policy_result = dict(plan_data.get("policy_result", {}) or {})
    policy_result["auto_confirm_allowed"] = False

    old_reasons = list(policy_result.get("reasons", []) or [])
    for reason in throttle_result.get("reasons", []) or []:
        if reason not in old_reasons:
            old_reasons.append(reason)

    policy_result["reasons"] = old_reasons
    policy_result["policy_summary"] = "blocked_by_alert_throttle"

    checked_items = dict(policy_result.get("checked_items", {}) or {})
    checked_items["alert_throttle_allowed"] = False
    checked_items["dedup_key"] = throttle_result.get("dedup_key", {})
    checked_items["event_status"] = throttle_result.get("event_status", "")
    policy_result["checked_items"] = checked_items

    plan_data["policy_result"] = policy_result

    return plan_data
