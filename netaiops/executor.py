import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path("/opt/netaiops-webhook")
DATA_DIR = BASE_DIR / "data"
PLAN_DIR = DATA_DIR / "plans"
EXECUTION_DIR = DATA_DIR / "execution"


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
    if not files:
        raise FileNotFoundError(f"execution file not found for request_id={request_id}")
    return files[0]


def latest_execution_file() -> Path:
    files = sorted(EXECUTION_DIR.glob("*.execution.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        raise FileNotFoundError("no execution files found")
    return files[0]


def create_execution_for_request_id(request_id: str) -> dict:
    plan_path = plan_file_by_request_id(request_id)
    plan = read_json_file(plan_path)

    if plan.get("plan_status") != "confirmed":
        raise ValueError(f"plan is not confirmed, request_id={request_id}")

    if not plan.get("readonly_only", False):
        raise ValueError(f"plan is not readonly_only, request_id={request_id}")

    execution_data = {
        "request_id": request_id,
        "execution_id": f"exec_{uuid.uuid4().hex[:12]}",
        "execution_status": "pending_dispatch",
        "source": plan.get("source", ""),
        "plan_id": plan.get("plan_id", ""),
        "plan_file": str(plan_path),
        "plan_status_at_dispatch": plan.get("plan_status", ""),
        "target_scope": plan.get("target_scope", {}),
        "readonly_only": plan.get("readonly_only", False),
        "commands": [
            {
                "order": item.get("order"),
                "command": item.get("command"),
                "readonly": item.get("readonly", False),
                "risk": item.get("risk", "unknown"),
                "dispatch_status": "pending",
                "output": None,
                "error": None,
            }
            for item in plan.get("execution_candidates", [])
        ],
        "dispatcher": {
            "mode": "stub",
            "backend": "not_connected",
            "message": "execution stub only, mcp-netmiko not connected yet",
        },
        "created_at": now_utc_str(),
        "updated_at": now_utc_str(),
        "dispatched_at": None,
        "completed_at": None,
    }

    source = plan.get("source", "unknown")
    execution_path = EXECUTION_DIR / f"{source}_{request_id}.execution.json"
    safe_write_json(execution_path, execution_data)

    return {
        "execution_file": str(execution_path),
        "execution_data": execution_data,
    }


def get_execution_by_request_id(request_id: str) -> dict:
    path = execution_file_by_request_id(request_id)
    return {
        "execution_file": str(path),
        "execution_data": read_json_file(path),
    }


def get_latest_execution() -> dict:
    path = latest_execution_file()
    return {
        "execution_file": str(path),
        "execution_data": read_json_file(path),
    }


def dispatch_execution_for_request_id(request_id: str) -> dict:
    path = execution_file_by_request_id(request_id)
    execution = read_json_file(path)

    if execution.get("execution_status") != "pending_dispatch":
        raise ValueError(f"execution is not pending_dispatch, request_id={request_id}")

    execution["execution_status"] = "dispatched"
    execution["dispatched_at"] = now_utc_str()
    execution["updated_at"] = now_utc_str()

    for item in execution.get("commands", []):
        item["dispatch_status"] = "dispatched"

    safe_write_json(path, execution)

    return {
        "execution_file": str(path),
        "execution_data": execution,
    }


def complete_execution_for_request_id(request_id: str) -> dict:
    path = execution_file_by_request_id(request_id)
    execution = read_json_file(path)

    if execution.get("execution_status") != "dispatched":
        raise ValueError(f"execution is not dispatched, request_id={request_id}")

    execution["execution_status"] = "completed"
    execution["completed_at"] = now_utc_str()
    execution["updated_at"] = now_utc_str()

    for item in execution.get("commands", []):
        item["dispatch_status"] = "completed"
        if item.get("output") is None:
            item["output"] = "stub execution completed, no real device output yet"

    safe_write_json(path, execution)

    return {
        "execution_file": str(path),
        "execution_data": execution,
    }


def fail_execution_for_request_id(request_id: str, message: str = "execution failed") -> dict:
    path = execution_file_by_request_id(request_id)
    execution = read_json_file(path)

    execution["execution_status"] = "failed"
    execution["updated_at"] = now_utc_str()
    execution["completed_at"] = now_utc_str()

    for item in execution.get("commands", []):
        if item.get("dispatch_status") not in ("completed", "failed"):
            item["dispatch_status"] = "failed"
            if item.get("error") is None:
                item["error"] = message

    safe_write_json(path, execution)

    return {
        "execution_file": str(path),
        "execution_data": execution,
    }


def update_execution_results_for_request_id(request_id: str, command_results: list) -> dict:
    path = execution_file_by_request_id(request_id)
    execution = read_json_file(path)

    commands = execution.get("commands", [])
    command_map = {item.get("order"): item for item in commands}

    any_failed = False

    for result in command_results:
        order = result.get("order")
        if order not in command_map:
            continue

        item = command_map[order]
        item["output"] = result.get("output")
        item["error"] = result.get("error")
        item["dispatch_status"] = result.get("dispatch_status", "completed")

        if item["dispatch_status"] == "failed" or item.get("error"):
            any_failed = True

    execution["updated_at"] = now_utc_str()
    execution["completed_at"] = now_utc_str()
    execution["execution_status"] = "failed" if any_failed else "completed"

    safe_write_json(path, execution)

    return {
        "execution_file": str(path),
        "execution_data": execution,
    }
