import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from agent_runner.executors import execute_commands
from agent_runner.reachability_precheck import apply_reachability_precheck


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


def normalize_mcp_mode(backend: str) -> str:
    if backend == "stub":
        return "stub"
    return "placeholder"


def run_dispatch_request(request_id: str) -> Dict[str, Any]:
    dispatch_file = DISPATCH_DIR / f"{request_id}.dispatch.request.json"
    if not dispatch_file.exists():
        raise FileNotFoundError(f"dispatch request file not found for request_id={request_id}")

    dispatch_payload = read_json_file(dispatch_file)
    execution_candidates = dispatch_payload.get("execution_candidates", []) or []
    target_scope = dispatch_payload.get("target_scope", {}) or {}

    backend = get_runner_backend()
    os.environ["MCP_MODE"] = normalize_mcp_mode(backend)

    # V13 Device owner fence: once the new owner has claimed this request,
    # the legacy runner must never issue a second Netmiko call.  Reuse the
    # raw lower-executor results persisted by the owner instead.
    v13_reused_owner_results = False
    try:
        from netaiops.v13.production_integration import (
            legacy_source_action,
            load_device_owner_command_results,
        )

        if legacy_source_action(request_id, "device") == "skip_duplicate":
            owner_payload = load_device_owner_command_results(
                request_id,
                wait_seconds=35.0,
            )
            if isinstance(owner_payload, dict):
                owner_results = owner_payload.get("command_results")
                if isinstance(owner_results, list):
                    command_results = [
                        dict(item) for item in owner_results if isinstance(item, dict)
                    ]
                    precheck_result = {
                        "enabled": False,
                        "stop": False,
                        "reason": "v13_device_owner_fence_reused_results",
                        "command_results": [],
                    }
                    v13_reused_owner_results = True
    except Exception:
        v13_reused_owner_results = False

    if not v13_reused_owner_results:
        precheck_result = apply_reachability_precheck(
            request_id=request_id,
            target_scope=target_scope,
            dispatch_payload=dispatch_payload,
        )

        if precheck_result.get("stop"):
            command_results = precheck_result.get("command_results", [])
        else:
            precheck_command_results = precheck_result.get("command_results", [])
            command_results = precheck_command_results + execute_commands(
                request_id=request_id,
                target_scope=target_scope,
                execution_candidates=execution_candidates,
            )


    result = {
        "request_id": request_id,
        "runner_mode": backend,
        "target_scope": target_scope,
        "classification": dispatch_payload.get("classification", {}),
        "playbook": dispatch_payload.get("playbook", {}),
        "family_result": dispatch_payload.get("family_result", {}),
        "capability_plan": dispatch_payload.get("capability_plan", {}),
        "execution_source": dispatch_payload.get("execution_source", ""),
        "readonly_only": dispatch_payload.get("readonly_only"),
        "policy_result": dispatch_payload.get("policy_result", {}),
        "precheck_result": precheck_result,
        "v13_device_owner_results_reused": v13_reused_owner_results,
        "guard_result": dispatch_payload.get("guard_result", {}),
        "command_results": command_results,
        "completed_at": now_utc_str(),
        "source_dispatch_file": str(dispatch_file),
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
