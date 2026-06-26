import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


BASE_DIR = Path("/opt/netaiops-webhook")
DATA_DIR = BASE_DIR / "data"
EXECUTION_DIR = DATA_DIR / "execution"
CALLBACK_DIR = DATA_DIR / "callback"
PLAN_DIR = DATA_DIR / "plans"


def now_utc_str() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json_file(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def safe_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def plan_file_by_request_id(request_id: str) -> Path:
    files = list(PLAN_DIR.glob(f"*_{request_id}.plan.json"))
    if not files:
        raise FileNotFoundError(f"plan file not found for request_id={request_id}")
    return files[0]


def execution_file_by_request_id(request_id: str) -> Path:
    files = list(EXECUTION_DIR.glob(f"*_{request_id}.execution.json"))
    if files:
        return files[0]

    plan_path = plan_file_by_request_id(request_id)
    source = plan_path.name.split("_", 1)[0]
    return EXECUTION_DIR / f"{source}_{request_id}.execution.json"


def summarize_command_results(command_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(command_results)
    completed = 0
    failed = 0
    partial = 0
    hard_error_count = 0

    for item in command_results:
        status = safe_text(item.get("dispatch_status")).lower()
        judge = item.get("judge", {}) if isinstance(item.get("judge"), dict) else {}

        if status == "completed":
            completed += 1
        elif status == "failed":
            failed += 1
        else:
            partial += 1

        if bool(judge.get("hard_error", False)):
            hard_error_count += 1

    if total == 0:
        execution_status = "failed"
    elif failed == 0 and partial == 0:
        execution_status = "completed"
    elif completed > 0:
        execution_status = "partial"
    else:
        execution_status = "failed"

    return {
        "execution_status": execution_status,
        "total_commands": total,
        "completed_commands": completed,
        "failed_commands": failed,
        "partial_commands": partial,
        "hard_error_count": hard_error_count,
    }


def build_execution_record_from_callback(request_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    plan_path = plan_file_by_request_id(request_id)
    plan_data = read_json_file(plan_path)

    command_results = payload.get("command_results", []) or []
    summary = summarize_command_results(command_results)

    record = {
        "request_id": request_id,
        "plan_id": plan_data.get("plan_id", ""),
        "execution_mode": payload.get("runner_mode", "stub"),
        "execution_status": summary["execution_status"],
        "target_scope": plan_data.get("target_scope", {}),
        "playbook": plan_data.get("playbook", {}),
        "classification": plan_data.get("classification", {}),
        "family_result": plan_data.get("family_result", {}),
        "capability_plan": plan_data.get("capability_plan", {}),
        "execution_source": plan_data.get("execution_source", ""),
        "readonly_only": plan_data.get("readonly_only"),
        "policy_result": plan_data.get("policy_result", {}),
        "guard_result": plan_data.get("guard_result", {}),
        "command_results": command_results,
        "stats": summary,
        "received_at": now_utc_str(),
        "source_plan_file": str(plan_path),
    }

    return record


def save_callback_payload(request_id: str, payload: Dict[str, Any]) -> str:
    path = CALLBACK_DIR / f"{request_id}.callback.payload.json"
    safe_write_json(path, payload)
    return str(path)


def save_execution_record(request_id: str, execution_data: Dict[str, Any]) -> str:
    path = execution_file_by_request_id(request_id)
    safe_write_json(path, execution_data)
    return str(path)


def handle_execution_result_callback(request_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    callback_file = save_callback_payload(request_id, payload)
    execution_data = build_execution_record_from_callback(request_id, payload)
    execution_file = save_execution_record(request_id, execution_data)

    return {
        "request_id": request_id,
        "callback_file": callback_file,
        "execution_file": execution_file,
        "execution_data": execution_data,
    }

# ===== log command false hard-error callback guard begin =====
# 兜底保护：无论哪个 API 调用 save_callback_payload，都先修正 show logging/display log
# 日志正文中的历史错误关键字误判，避免 failed 状态进入 execution.json / review.json。
try:
    from netaiops.log_command_hard_error_normalizer import normalize_log_command_false_hard_errors as _normalize_log_cmd_false_hard_errors

    _original_save_callback_payload = save_callback_payload

    def save_callback_payload(request_id: str, payload: dict) -> str:
        try:
            payload = _normalize_log_cmd_false_hard_errors(payload)
        except Exception:
            pass
        return _original_save_callback_payload(request_id, payload)

except Exception:
    pass
# ===== log command false hard-error callback guard end =====

# ===== v9 interface traffic CLI hard-error normalizer guard begin =====
# 将设备返回的硬错误输出归一化为 failed，避免 Invalid interface format / % Invalid command
# 被 MCP completed 状态误统计为成功。
try:
    from netaiops.cli_result_status_normalizer import normalize_execution_callback_payload as _v9_normalize_execution_callback_payload

    _v9_original_build_execution_record_from_callback = build_execution_record_from_callback
    _v9_original_save_callback_payload = save_callback_payload

    def build_execution_record_from_callback(request_id: str, payload: dict) -> dict:
        try:
            payload = _v9_normalize_execution_callback_payload(payload)
        except Exception:
            pass
        return _v9_original_build_execution_record_from_callback(request_id, payload)

    def save_callback_payload(request_id: str, payload: dict) -> str:
        try:
            payload = _v9_normalize_execution_callback_payload(payload)
        except Exception:
            pass
        return _v9_original_save_callback_payload(request_id, payload)

except Exception:
    pass
# ===== v9 interface traffic CLI hard-error normalizer guard end =====
