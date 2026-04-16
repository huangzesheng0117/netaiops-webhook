import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from netaiops.agent_client import submit_to_agent_runner
from netaiops.plan_builder import get_plan_by_request_id


BASE_DIR = Path("/opt/netaiops-webhook")
DATA_DIR = BASE_DIR / "data"
DISPATCH_DIR = DATA_DIR / "dispatch"


def now_utc_str() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json_file(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def safe_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def dispatch_request_id(request_id: str) -> Dict[str, Any]:
    plan_result = get_plan_by_request_id(request_id)
    plan_file = plan_result["plan_file"]
    plan_data = plan_result["plan_data"]

    plan_status = plan_data.get("plan_status")
    if plan_status != "confirmed":
        raise ValueError(f"plan is not confirmed, request_id={request_id}, plan_status={plan_status}")

    dispatch_result = submit_to_agent_runner(request_id, plan_data)

    record = {
        "request_id": request_id,
        "plan_file": plan_file,
        "plan_id": plan_data.get("plan_id", ""),
        "dispatch_status": dispatch_result.get("dispatch_status", "unknown"),
        "dispatch_mode": dispatch_result.get("dispatch_mode", "stub"),
        "agent_job_id": dispatch_result.get("agent_job_id", ""),
        "dispatch_file": dispatch_result.get("dispatch_file", ""),
        "command_count": dispatch_result.get("command_count", 0),
        "dispatched_at": now_utc_str(),
    }

    record_file = DISPATCH_DIR / f"{request_id}.dispatch.record.json"
    safe_write_json(record_file, record)

    return {
        "dispatch_record_file": str(record_file),
        "dispatch_data": record,
        "agent_response": dispatch_result,
    }


def get_dispatch_record(request_id: str) -> Dict[str, Any]:
    record_file = DISPATCH_DIR / f"{request_id}.dispatch.record.json"
    if not record_file.exists():
        raise FileNotFoundError(f"dispatch record not found for request_id={request_id}")

    return {
        "dispatch_record_file": str(record_file),
        "dispatch_data": read_json_file(record_file),
    }
