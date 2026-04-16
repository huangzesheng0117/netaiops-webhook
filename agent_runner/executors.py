import json
import os
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List


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
) -> Dict[str, Any]:
    return {
        "order": order,
        "command": command,
        "dispatch_status": dispatch_status,
        "output": output,
        "error": error,
        "started_at": started_at or now_utc_str(),
        "finished_at": finished_at or now_utc_str(),
    }


def run_stub_commands(execution_candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    results = []

    for item in execution_candidates:
        cmd = item.get("command", "")
        order = item.get("order", 0)
        started_at = now_utc_str()

        results.append(
            build_result_item(
                order=order,
                command=cmd,
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


def run_mcp_commands_placeholder(
    request_id: str,
    target_scope: Dict[str, Any],
    execution_candidates: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    第一版真实 MCP 骨架：
    - 先不直接依赖某个 MCP Python SDK
    - 支持后续通过 wrapper 脚本 / CLI / HTTP bridge 对接
    - 当前如果没有 MCP_WRAPPER_CMD，则返回 failed 占位结果
    """
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
                build_result_item(
                    order=order,
                    command=cmd,
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

            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()

            if proc.returncode == 0:
                results.append(
                    build_result_item(
                        order=order,
                        command=cmd,
                        dispatch_status="completed",
                        output=stdout,
                        error=None,
                        started_at=started_at,
                        finished_at=now_utc_str(),
                    )
                )
            else:
                results.append(
                    build_result_item(
                        order=order,
                        command=cmd,
                        dispatch_status="failed",
                        output=stdout,
                        error=stderr or f"MCP wrapper exited with code {proc.returncode}",
                        started_at=started_at,
                        finished_at=now_utc_str(),
                    )
                )

        except Exception as exc:
            results.append(
                build_result_item(
                    order=order,
                    command=cmd,
                    dispatch_status="failed",
                    output="",
                    error=f"MCP execution exception: {exc}",
                    started_at=started_at,
                    finished_at=now_utc_str(),
                )
            )

    return results


def run_commands(
    backend: str,
    request_id: str,
    target_scope: Dict[str, Any],
    execution_candidates: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    backend_l = str(backend or "stub").strip().lower()

    if backend_l == "stub":
        return run_stub_commands(execution_candidates)

    if backend_l == "mcp":
        return run_mcp_commands_placeholder(
            request_id=request_id,
            target_scope=target_scope,
            execution_candidates=execution_candidates,
        )

    raise ValueError(f"unsupported runner backend: {backend}")
