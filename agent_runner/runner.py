import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from agent_runner.executors import run_commands


BASE_DIR = Path("/opt/netaiops-webhook")
DATA_DIR = BASE_DIR / "data"
DISPATCH_DIR = DATA_DIR / "dispatch"
CALLBACK_DIR = DATA_DIR / "callback"


def now_utc_str() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json_file(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def safe_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def get_runner_backend() -> str:
    return os.getenv("RUNNER_BACKEND", "stub").strip().lower()


def run_dispatch_request(request_id: str) -> Dict[str, Any]:
    dispatch_file = DISPATCH_DIR / f"{request_id}.dispatch.request.json"
    if not dispatch_file.exists():
        raise FileNotFoundError(f"dispatch request file not found for request_id={request_id}")

    dispatch_payload = read_json_file(dispatch_file)
    execution_candidates = dispatch_payload.get("execution_candidates", []) or []
    target_scope = dispatch_payload.get("target_scope", {}) or {}

    backend = get_runner_backend()

    command_results = run_commands(
        backend=backend,
        request_id=request_id,
        target_scope=target_scope,
        execution_candidates=execution_candidates,
    )

    result = {
        "request_id": request_id,
        "runner_mode": backend,
        "target_scope": target_scope,
        "command_results": command_results,
        "completed_at": now_utc_str(),
    }

    callback_file = CALLBACK_DIR / f"{request_id}.runner.result.json"
    safe_write_json(callback_file, result)
    result["callback_file"] = str(callback_file)

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python agent_runner/runner.py <request_id>")
        raise SystemExit(1)

    request_id = sys.argv[1]
    result = run_dispatch_request(request_id)
    print(json.dumps(result, ensure_ascii=False, indent=2))
