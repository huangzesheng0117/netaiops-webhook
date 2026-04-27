import json
import os
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List

from netaiops.output_judger import judge_command_result


def now_utc_str() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_result_item(
    order: int,
    command: str,
    dispatch_status: str,
    output: str = "",
    error: str | None = None,
    started_at: str | None = None,
    finished_at: str | None = None,
    capability: str = "",
    reason: str = "",
    platform: str = "",
    judge_profile: str = "",
    judge: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    return {
        "order": order,
        "command": command,
        "dispatch_status": dispatch_status,
        "output": output,
        "error": error,
        "started_at": started_at or now_utc_str(),
        "finished_at": finished_at or now_utc_str(),
        "capability": capability,
        "reason": reason,
        "platform": platform,
        "judge_profile": judge_profile,
        "judge": judge or {},
    }


def finalize_result_item(
    item: Dict[str, Any],
    dispatch_status: str,
    output: str = "",
    error: str | None = None,
    started_at: str | None = None,
    finished_at: str | None = None,
) -> Dict[str, Any]:
    command = item.get("command", "")
    judge_profile = item.get("judge_profile", "") or "network_cli_generic"

    judge = judge_command_result(
        command=command,
        output=output,
        error=error or "",
        judge_profile=judge_profile,
        dispatch_status=dispatch_status,
    )

    return build_result_item(
        order=item.get("order", 0),
        command=command,
        dispatch_status=judge.get("final_status", dispatch_status),
        output=output,
        error=error,
        started_at=started_at,
        finished_at=finished_at,
        capability=item.get("capability", ""),
        reason=item.get("reason", ""),
        platform=item.get("platform", ""),
        judge_profile=judge_profile,
        judge=judge,
    )


def run_stub_commands(execution_candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    results = []

    for item in execution_candidates:
        cmd = item.get("command", "")
        started_at = now_utc_str()

        results.append(
            finalize_result_item(
                item=item,
                dispatch_status="completed",
                output=f"[STUB OUTPUT] command executed successfully: {cmd}",
                error=None,
                started_at=started_at,
                finished_at=now_utc_str(),
            )
        )

    return results


def build_mcp_env_summary() -> Dict[str, Any]:
    return {
        "mcp_server_url": os.getenv("MCP_SERVER_URL", ""),
        "mcp_mode": os.getenv("MCP_MODE", "placeholder"),
        "mcp_timeout": os.getenv("MCP_TIMEOUT", "30"),
        "mcp_wrapper_cmd": os.getenv("MCP_WRAPPER_CMD", ""),
    }


def _parse_wrapper_stdout(stdout_text: str) -> Dict[str, Any]:
    text = (stdout_text or "").strip()
    if not text:
        return {}

    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    return {"output": stdout_text}


def run_mcp_commands_placeholder(
    request_id: str,
    target_scope: Dict[str, Any],
    execution_candidates: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    results = []
    mcp_env = build_mcp_env_summary()
    wrapper_cmd = mcp_env.get("mcp_wrapper_cmd", "").strip()

    device_ip = str((target_scope or {}).get("device_ip", "")).strip()
    hostname = str((target_scope or {}).get("hostname", "")).strip()
    vendor = str((target_scope or {}).get("vendor", "")).strip()

    for item in execution_candidates:
        cmd = item.get("command", "")
        order = item.get("order", 0)
        started_at = now_utc_str()

        if not wrapper_cmd:
            results.append(
                finalize_result_item(
                    item=item,
                    dispatch_status="failed",
                    output="",
                    error=(
                        "MCP backend selected but MCP_WRAPPER_CMD is not set. "
                        f"target={hostname or device_ip or 'unknown'} vendor={vendor}"
                    ),
                    started_at=started_at,
                    finished_at=now_utc_str(),
                )
            )
            continue

        payload = {
            "request_id": request_id,
            "target_scope": target_scope,
            "command": cmd,
            "order": order,
            "capability": item.get("capability", ""),
            "platform": item.get("platform", ""),
            "judge_profile": item.get("judge_profile", ""),
        }

        try:
            proc = subprocess.run(
                [wrapper_cmd],
                input=json.dumps(payload, ensure_ascii=False),
                text=True,
                capture_output=True,
                timeout=int(mcp_env.get("mcp_timeout", "30")),
                check=False,
            )

            parsed = _parse_wrapper_stdout(proc.stdout)
            output = str(parsed.get("output", proc.stdout or ""))
            error = str(parsed.get("error", proc.stderr or "")) if (parsed.get("error", proc.stderr or "")) else ""

            wrapper_status = str(parsed.get("dispatch_status", "")).strip().lower()
            if wrapper_status in ("completed", "failed", "partial"):
                dispatch_status = wrapper_status
            else:
                dispatch_status = "completed" if proc.returncode == 0 else "failed"

            results.append(
                finalize_result_item(
                    item=item,
                    dispatch_status=dispatch_status,
                    output=output,
                    error=error,
                    started_at=started_at,
                    finished_at=now_utc_str(),
                )
            )

        except subprocess.TimeoutExpired as e:
            results.append(
                finalize_result_item(
                    item=item,
                    dispatch_status="failed",
                    output="",
                    error=f"wrapper timeout: {e}",
                    started_at=started_at,
                    finished_at=now_utc_str(),
                )
            )
        except Exception as e:
            results.append(
                finalize_result_item(
                    item=item,
                    dispatch_status="failed",
                    output="",
                    error=f"wrapper exception: {e}",
                    started_at=started_at,
                    finished_at=now_utc_str(),
                )
            )

    return results


def execute_commands(
    request_id: str,
    target_scope: Dict[str, Any],
    execution_candidates: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    mcp_mode = os.getenv("MCP_MODE", "placeholder").strip().lower()

    if mcp_mode == "stub":
        return run_stub_commands(execution_candidates)

    return run_mcp_commands_placeholder(
        request_id=request_id,
        target_scope=target_scope,
        execution_candidates=execution_candidates,
    )
