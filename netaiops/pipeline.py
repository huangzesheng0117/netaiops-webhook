import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

from agent_runner.callback_client import post_execution_result
from netaiops.dispatcher import dispatch_request_id
from netaiops.plan_builder import confirm_plan_for_request_id, generate_plan_for_request_id
from netaiops.request_summary import get_request_summary

BASE_DIR = Path("/opt/netaiops-webhook")
CALLBACK_DIR = BASE_DIR / "data" / "callback"
EXECUTION_DIR = BASE_DIR / "data" / "execution"
REVIEW_DIR = BASE_DIR / "data" / "reviews"
INTERNAL_WEBHOOK_BASE_URL = "http://127.0.0.1:18080"


def _has_terminal_artifacts(request_id: str) -> bool:
    patterns = [
        CALLBACK_DIR / f"*{request_id}*",
        EXECUTION_DIR / f"*{request_id}*",
        REVIEW_DIR / f"*{request_id}*",
    ]
    for pattern in patterns:
        if list(pattern.parent.glob(pattern.name)):
            return True
    return False


def _run_local_runner_and_callback(request_id: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "request_id": request_id,
        "runner_invoked": False,
        "callback_invoked": False,
        "runner_returncode": None,
        "runner_stdout": "",
        "runner_stderr": "",
        "runner_result": None,
        "callback_result": None,
        "skipped": False,
        "error": None,
    }

    if _has_terminal_artifacts(request_id):
        result["skipped"] = True
        result["error"] = "terminal_artifacts_already_exist"
        return result

    try:
        proc = subprocess.run(
            [sys.executable, "-m", "agent_runner.runner", request_id],
            text=True,
            capture_output=True,
            timeout=300,
        )
        result["runner_invoked"] = True
        result["runner_returncode"] = proc.returncode
        result["runner_stdout"] = proc.stdout or ""
        result["runner_stderr"] = proc.stderr or ""

        if proc.returncode != 0:
            result["error"] = f"runner_failed_returncode_{proc.returncode}"
            return result

        runner_stdout = (proc.stdout or "").strip()
        runner_json = {}
        if runner_stdout:
            try:
                runner_json = json.loads(runner_stdout)
            except Exception:
                runner_json = {"raw_stdout": runner_stdout}
        result["runner_result"] = runner_json

        callback_file = Path(
            (runner_json or {}).get("callback_file")
            or str(CALLBACK_DIR / f"{request_id}.runner.result.json")
        )

        if not callback_file.exists():
            result["error"] = f"callback_file_not_found:{callback_file}"
            return result

        with open(callback_file, "r", encoding="utf-8") as f:
            payload = json.load(f)

        cb_result = post_execution_result(
            webhook_base_url=INTERNAL_WEBHOOK_BASE_URL,
            request_id=request_id,
            payload=payload,
            timeout=30,
        )
        result["callback_invoked"] = True
        result["callback_result"] = cb_result
        return result

    except Exception as e:
        result["error"] = str(e)
        return result


def run_pipeline_for_request_id(
    request_id: str,
    auto_confirm: bool = True,
    auto_dispatch: bool = True,
) -> Dict[str, Any]:
    plan_result = generate_plan_for_request_id(request_id)
    plan_data = plan_result["plan_data"]

    policy_result = plan_data.get("policy_result", {}) or {}
    auto_confirm_allowed = bool(policy_result.get("auto_confirm_allowed", False))

    confirm_result = None
    dispatch_result = None
    local_execution_result = None

    if auto_confirm and auto_confirm_allowed:
        confirm_result = confirm_plan_for_request_id(request_id)
        plan_data = confirm_result["plan_data"]

    if auto_dispatch and plan_data.get("plan_status") == "confirmed":
        dispatch_result = dispatch_request_id(request_id)

        dispatch_data = (dispatch_result or {}).get("dispatch_data", {}) or {}
        dispatch_status = dispatch_data.get("dispatch_status")

        if dispatch_status == "accepted":
            local_execution_result = _run_local_runner_and_callback(request_id)

    summary = get_request_summary(request_id)

    return {
        "request_id": request_id,
        "plan_result": plan_result,
        "confirm_result": confirm_result,
        "dispatch_result": dispatch_result,
        "local_execution_result": local_execution_result,
        "summary": summary,
    }


def run_pipeline_safe(
    request_id: str,
    auto_confirm: bool = True,
    auto_dispatch: bool = True,
) -> Dict[str, Any]:
    try:
        result = run_pipeline_for_request_id(
            request_id=request_id,
            auto_confirm=auto_confirm,
            auto_dispatch=auto_dispatch,
        )
        return {
            "ok": True,
            "request_id": request_id,
            "result": result,
            "error": None,
        }
    except Exception as e:
        return {
            "ok": False,
            "request_id": request_id,
            "result": None,
            "error": str(e),
        }
