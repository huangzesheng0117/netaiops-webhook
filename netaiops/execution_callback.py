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

    for item in command_results:
        status = str(item.get("dispatch_status", "")).strip().lower()
        if status == "completed":
            completed += 1
        elif status == "failed":
            failed += 1
        else:
            partial += 1

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
