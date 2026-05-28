import socket
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List


REACHABILITY_PLAYBOOK_IDS = {
    "cisco_device_reachability_down",
    "fortigate_device_reachability_down",
    "f5_device_reachability_down",
    "hillstone_device_reachability_down",
}


def now_utc_str() -> str:
    return datetime.now(timezone.utc).isoformat()


def _result_item(order: int, command: str, dispatch_status: str, output: str = "", error: str = "") -> Dict[str, Any]:
    return {
        "order": order,
        "command": command,
        "dispatch_status": dispatch_status,
        "output": output,
        "error": error or None,
        "started_at": now_utc_str(),
        "finished_at": now_utc_str(),
        "capability": "reachability_precheck",
        "reason": "v7.12_reachability_precheck",
        "platform": "local",
        "judge_profile": "reachability_precheck",
        "judge": {
            "final_status": dispatch_status,
            "reason": error or "precheck_completed",
        },
    }


def _ping_management_ip(device_ip: str, timeout_seconds: int = 2) -> Dict[str, Any]:
    cmd = ["ping", "-c", "2", "-W", str(timeout_seconds), device_ip]
    try:
        proc = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=max(6, timeout_seconds * 4),
            check=False,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "output": output.strip(),
            "command": " ".join(cmd),
        }
    except Exception as exc:
        return {
            "ok": False,
            "returncode": -1,
            "output": "",
            "command": " ".join(cmd),
            "error": str(exc),
        }


def _tcp_ssh_check(device_ip: str, port: int = 22, timeout_seconds: int = 3) -> Dict[str, Any]:
    try:
        with socket.create_connection((device_ip, port), timeout=timeout_seconds):
            return {
                "ok": True,
                "output": f"TCP {device_ip}:{port} reachable",
                "command": f"tcp-connect {device_ip}:{port}",
            }
    except Exception as exc:
        return {
            "ok": False,
            "output": "",
            "error": str(exc),
            "command": f"tcp-connect {device_ip}:{port}",
        }


def should_apply_reachability_precheck(dispatch_payload: Dict[str, Any]) -> bool:
    playbook_id = str(dispatch_payload.get("playbook_id", "") or "").strip()
    return playbook_id in REACHABILITY_PLAYBOOK_IDS


def apply_reachability_precheck(
    request_id: str,
    target_scope: Dict[str, Any],
    dispatch_payload: Dict[str, Any],
) -> Dict[str, Any]:
    if not should_apply_reachability_precheck(dispatch_payload):
        return {
            "enabled": False,
            "stop": False,
            "reason": "not_reachability_playbook",
            "command_results": [],
        }

    device_ip = str((target_scope or {}).get("device_ip", "") or "").strip()
    hostname = str((target_scope or {}).get("hostname", "") or "").strip()

    command_results: List[Dict[str, Any]] = []

    if not device_ip:
        command_results.append(
            _result_item(
                1,
                "[precheck] ping management IP",
                "failed",
                "",
                "device_ip_missing; stop before device-side CLI",
            )
        )
        return {
            "enabled": True,
            "stop": True,
            "reason": "device_ip_missing",
            "command_results": command_results,
        }

    ping_result = _ping_management_ip(device_ip)
    command_results.append(
        _result_item(
            1,
            f"[precheck] ping management IP {device_ip}",
            "completed" if ping_result.get("ok") else "failed",
            ping_result.get("output", ""),
            "" if ping_result.get("ok") else "management_ip_ping_failed; stop before SSH/CLI",
        )
    )

    if not ping_result.get("ok"):
        return {
            "enabled": True,
            "stop": True,
            "reason": "management_ip_ping_failed",
            "device_ip": device_ip,
            "hostname": hostname,
            "command_results": command_results,
        }

    ssh_result = _tcp_ssh_check(device_ip)
    command_results.append(
        _result_item(
            2,
            f"[precheck] TCP SSH reachability {device_ip}:22",
            "completed" if ssh_result.get("ok") else "failed",
            ssh_result.get("output", ""),
            "" if ssh_result.get("ok") else f"ssh_tcp_check_failed: {ssh_result.get('error', '')}; stop before CLI",
        )
    )

    if not ssh_result.get("ok"):
        return {
            "enabled": True,
            "stop": True,
            "reason": "ssh_tcp_check_failed",
            "device_ip": device_ip,
            "hostname": hostname,
            "command_results": command_results,
        }

    return {
        "enabled": True,
        "stop": False,
        "reason": "precheck_passed",
        "device_ip": device_ip,
        "hostname": hostname,
        "command_results": command_results,
    }
