import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


BASE_DIR = Path("/opt/netaiops-webhook")
DATA_DIR = BASE_DIR / "data"
DISPATCH_DIR = DATA_DIR / "dispatch"


def now_utc_str() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def submit_to_agent_runner(request_id: str, plan_data: Dict[str, Any]) -> Dict[str, Any]:
    classification = plan_data.get("classification", {}) or {}
    playbook = plan_data.get("playbook", {}) or {}
    execution_candidates = plan_data.get("execution_candidates", []) or []

    dispatch_payload = {
        "request_id": request_id,
        "plan_id": plan_data.get("plan_id", ""),
        "plan_status": plan_data.get("plan_status", ""),
        "prompt_profile": classification.get("prompt_profile", "quick"),
        "playbook_id": playbook.get("playbook_id", ""),
        "execution_source": plan_data.get("execution_source", ""),
        "target_scope": plan_data.get("target_scope", {}),
        "execution_candidates": execution_candidates,
        "submitted_at": now_utc_str(),
        "dispatch_mode": "stub",
    }

    dispatch_file = DISPATCH_DIR / f"{request_id}.dispatch.request.json"
    safe_write_json(dispatch_file, dispatch_payload)

    stub_response = {
        "request_id": request_id,
        "dispatch_status": "accepted",
        "dispatch_mode": "stub",
        "agent_job_id": f"job_{request_id}",
        "dispatch_file": str(dispatch_file),
        "submitted_at": now_utc_str(),
        "message": "stub agent runner accepted dispatch payload",
        "command_count": len(execution_candidates),
    }

    response_file = DISPATCH_DIR / f"{request_id}.dispatch.response.json"
    safe_write_json(response_file, stub_response)

    return stub_response
