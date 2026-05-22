"""v7.9 Interface error counter delta recheck.

用于“接口错包/CRC/FCS/input errors”类告警的延迟二次取证：

1. 第一轮取证后，从 execution_data 中提取 baseline counter。
2. 延迟几分钟后，再次通过 MCP 执行 show interface <iface> counters errors。
3. 对比前后两次计数器，判断错包是否仍在持续增加。

安全边界：
- 只执行只读 show/display 命令。
- 不修改设备配置。
- 不影响原 v4/v5/v6/v7 主链路。
- 结果落盘到 data/interface_error_delta/。
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path("/opt/netaiops-webhook")
DELTA_DIR_REL = Path("data/interface_error_delta")

ERROR_FAMILIES = {
    "interface_packet_loss_or_discards_high",
}

COUNTER_KEYS = [
    "input_errors",
    "input_error",
    "crc",
    "fcs_err",
    "rcv_err",
    "output_errors",
    "out_discards",
    "output_discards",
    "output_total_drops",
    "output_buffer_drops",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def safe_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).replace(",", "").strip())
    except Exception:
        return None


def delta_dir(base_dir: Path = BASE_DIR) -> Path:
    return Path(base_dir) / DELTA_DIR_REL


def job_file(request_id: str, base_dir: Path = BASE_DIR) -> Path:
    return delta_dir(base_dir) / f"{request_id}.job.json"


def result_file(request_id: str, base_dir: Path = BASE_DIR) -> Path:
    return delta_dir(base_dir) / f"{request_id}.delta.json"


def log_file(request_id: str, base_dir: Path = BASE_DIR) -> Path:
    return delta_dir(base_dir) / f"{request_id}.delta.log"


def read_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


def write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)


def execution_file_by_request_id(request_id: str, base_dir: Path = BASE_DIR) -> Path:
    root = Path(base_dir) / "data" / "execution"
    files = list(root.glob(f"*{request_id}*.execution.json"))
    if not files:
        raise FileNotFoundError(f"execution file not found for request_id={request_id}")
    return sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)[0]


def get_family(execution_data: Dict[str, Any]) -> str:
    return safe_text(
        ((execution_data.get("family_result") or {}).get("family"))
        or ((execution_data.get("classification") or {}).get("family"))
        or ((execution_data.get("classification") or {}).get("playbook_type"))
        or ((execution_data.get("playbook") or {}).get("playbook_id"))
    )


def extract_text(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, dict):
        for key in ("output", "result", "text"):
            if value.get(key):
                return extract_text(value.get(key))

        structured = value.get("structuredContent")
        if isinstance(structured, dict) and structured.get("result"):
            return extract_text(structured.get("result"))

        content = value.get("content")
        if isinstance(content, list):
            parts = []
            for item in content:
                if isinstance(item, dict) and item.get("text"):
                    parts.append(safe_text(item.get("text")))
            if parts:
                return "\n".join(parts)

        return json.dumps(value, ensure_ascii=False)

    if isinstance(value, list):
        return "\n".join([extract_text(x) for x in value if x is not None])

    return safe_text(value)


def normalize_interface(value: Any) -> str:
    text = safe_text(value).replace(" ", "")
    if not text:
        return ""

    lower = text.lower()

    if lower.startswith("port-channel"):
        return "port-channel" + text[len("port-channel"):]
    if lower.startswith("po") and re.match(r"(?i)^po\d+", text):
        return "port-channel" + text[2:]
    if lower.startswith("ethernet"):
        return "Ethernet" + text[len("ethernet"):]
    if lower.startswith("eth"):
        return "Ethernet" + text[len("eth"):]
    if lower.startswith("tengigabitethernet"):
        return "TenGigabitEthernet" + text[len("tengigabitethernet"):]
    if lower.startswith("te"):
        return "TenGigabitEthernet" + text[len("te"):]
    if lower.startswith("gigabitethernet"):
        return "GigabitEthernet" + text[len("gigabitethernet"):]
    if lower.startswith("gi"):
        return "GigabitEthernet" + text[len("gi"):]

    return text


def command_interface(command: str) -> str:
    m = re.search(
        r"show\s+interfaces?\s+(\S+)\s+counters\s+errors",
        command or "",
        flags=re.IGNORECASE,
    )
    if m:
        return normalize_interface(m.group(1))

    m = re.search(
        r"show\s+interfaces?\s+(\S+)",
        command or "",
        flags=re.IGNORECASE,
    )
    if m:
        return normalize_interface(m.group(1))

    return ""


def extract_target_scope(execution_data: Dict[str, Any]) -> Dict[str, Any]:
    scope: Dict[str, Any] = {}

    for key in ("target_scope",):
        value = execution_data.get(key)
        if isinstance(value, dict):
            scope.update(value)

    family_scope = (execution_data.get("family_result") or {}).get("target_scope")
    if isinstance(family_scope, dict):
        for k, v in family_scope.items():
            scope.setdefault(k, v)

    return scope


def extract_interface(execution_data: Dict[str, Any]) -> str:
    scope = extract_target_scope(execution_data)

    for key in ("interface", "object_name", "ifName", "if_name", "port"):
        iface = normalize_interface(scope.get(key))
        if iface:
            return iface

    for item in execution_data.get("command_results") or []:
        if not isinstance(item, dict):
            continue
        iface = command_interface(safe_text(item.get("command")))
        if iface:
            return iface

    text = json.dumps(execution_data, ensure_ascii=False)
    for pattern in [
        r"\b(port-channel\s*\d+)\b",
        r"\b(Po\s*\d+)\b",
        r"\b(Ethernet\s*\d+(?:/\d+)+)\b",
        r"\b(Eth\s*\d+(?:/\d+)+)\b",
        r"\b(TenGigabitEthernet\s*\d+(?:/\d+)+)\b",
        r"\b(Te\s*\d+(?:/\d+)+)\b",
        r"\b(GigabitEthernet\s*\d+(?:/\d+)+)\b",
        r"\b(Gi\s*\d+(?:/\d+)+)\b",
    ]:
        m = re.search(pattern, text, flags=re.IGNORECASE)
        if m:
            return normalize_interface(m.group(1))

    return ""


def is_error_counter_alert(execution_data: Dict[str, Any]) -> bool:
    family = get_family(execution_data)
    if family in ERROR_FAMILIES:
        return True

    text = json.dumps(execution_data, ensure_ascii=False).lower()
    keywords = [
        "错包",
        "crc",
        "fcs",
        "input error",
        "input_error",
        "input errors",
        "rcv-err",
        "fcs-err",
        "counters errors",
        "接口错误",
    ]
    return any(k in text for k in keywords)


def parse_counter_snapshot(command: str, output: str, interface: str = "") -> Dict[str, Any]:
    text = output or ""
    target = normalize_interface(interface) or command_interface(command)

    snapshot: Dict[str, Any] = {
        "interface": target,
        "command": command,
        "parsed_at": utc_now(),
        "matched": False,
    }

    # 常规 show interface 输出：
    # 14805 input errors, 14805 CRC, 0 frame, 0 overrun, 0 ignored
    m = re.search(
        r"(?P<input>\d[\d,]*)\s+input errors?,\s*(?P<crc>\d[\d,]*)\s+CRC",
        text,
        flags=re.IGNORECASE,
    )
    if m:
        input_errors = safe_int(m.group("input"))
        crc = safe_int(m.group("crc"))
        snapshot.update({
            "matched": True,
            "input_errors": input_errors,
            "input_error": input_errors,
            "crc": crc,
            "fcs_err": crc,
        })

    for key, pattern in [
        ("output_errors", r"(\d[\d,]*)\s+output errors?"),
        ("output_total_drops", r"(\d[\d,]*)\s+output total drops?"),
        ("output_buffer_drops", r"(\d[\d,]*)\s+output buffer drops?"),
        ("out_discards", r"(\d[\d,]*)\s+out(?:put)?\s+discards?"),
    ]:
        mm = re.search(pattern, text, flags=re.IGNORECASE)
        if mm:
            snapshot["matched"] = True
            snapshot[key] = safe_int(mm.group(1))

    # NXOS/ACI counters errors 表格：
    # Port Align-Err FCS-Err Xmit-Err Rcv-Err UnderSize OutDiscards
    # Po45 0 14805 0 14805 0 0
    lines = [x.strip() for x in text.splitlines() if x.strip()]
    table_mode = False

    for line in lines:
        if "Align-Err" in line and "FCS-Err" in line and "Rcv-Err" in line:
            table_mode = True
            continue

        if not table_mode:
            continue

        parts = line.split()
        if len(parts) < 7:
            continue

        port = normalize_interface(parts[0])
        if target:
            target_l = target.lower()
            port_l = port.lower()
            if port_l != target_l:
                if target_l.startswith("port-channel") and port_l == ("po" + target_l.replace("port-channel", "")):
                    pass
                else:
                    continue

        nums = [safe_int(x) for x in parts[1:7]]
        if any(x is None for x in nums):
            continue

        align_err, fcs_err, xmit_err, rcv_err, undersize, out_discards = nums
        snapshot.update({
            "matched": True,
            "interface": target or port,
            "align_err": align_err,
            "fcs_err": fcs_err,
            "crc": fcs_err,
            "xmit_err": xmit_err,
            "rcv_err": rcv_err,
            "input_errors": rcv_err,
            "input_error": rcv_err,
            "undersize": undersize,
            "out_discards": out_discards,
            "output_discards": out_discards,
        })
        break

    return snapshot


def extract_baseline_snapshot(execution_data: Dict[str, Any]) -> Dict[str, Any]:
    iface = extract_interface(execution_data)

    candidates = []

    for item in execution_data.get("command_results") or []:
        if not isinstance(item, dict):
            continue

        command = safe_text(item.get("command"))
        capability = safe_text(item.get("capability"))
        output = extract_text(item.get("output"))

        priority = 0
        if "counters errors" in command.lower():
            priority += 10
        if capability == "show_interface_error_counters":
            priority += 10
        if "input errors" in output.lower() or "fcs-err" in output.lower() or "crc" in output.lower():
            priority += 5

        snap = parse_counter_snapshot(command, output, interface=iface)
        if snap.get("matched"):
            candidates.append((priority, snap))

    if not candidates:
        return {
            "matched": False,
            "interface": iface,
            "error": "baseline_counter_not_found_in_initial_execution",
        }

    candidates.sort(key=lambda x: x[0], reverse=True)
    result = candidates[0][1]
    result["source"] = "initial_execution"
    return result


def build_recheck_command(interface: str, execution_data: Dict[str, Any]) -> str:
    iface = normalize_interface(interface)
    if not iface:
        return ""

    # ACI/NXOS 当前生产样例使用 show interface port-channel45 counters errors。
    # IOS-XE 的 show interfaces 形式由原主链路处理；本延迟复查优先保持 NXOS/ACI 口径。
    return f"show interface {iface} counters errors"


def run_mcp_counter_command(
    request_id: str,
    execution_data: Dict[str, Any],
    interface: str,
) -> Dict[str, Any]:
    from agent_runner.executors import execute_commands

    target_scope = extract_target_scope(execution_data)
    target_scope["interface"] = interface

    command = build_recheck_command(interface, execution_data)
    if not command:
        return {
            "ok": False,
            "error": "cannot_build_recheck_command_without_interface",
            "command_results": [],
        }

    backend = os.getenv("RUNNER_BACKEND", "mcp").strip().lower()
    if not os.getenv("MCP_MODE"):
        os.environ["MCP_MODE"] = "stub" if backend == "stub" else "placeholder"

    candidate = {
        "order": 1,
        "capability": "show_interface_error_counters_delta_recheck",
        "command": command,
        "arguments": {
            "interface": interface,
        },
        "reason": "v7_9_interface_error_delta_recheck",
        "platform": safe_text(target_scope.get("platform") or target_scope.get("os_family") or "cisco_nxos"),
        "judge_profile": "network_cli_generic",
        "readonly": True,
        "risk": "low",
        "family": "interface_packet_loss_or_discards_high",
    }

    command_results = execute_commands(
        request_id=f"{request_id}_delta_recheck",
        target_scope=target_scope,
        execution_candidates=[candidate],
    )

    return {
        "ok": True,
        "command": command,
        "command_results": command_results,
    }


def compare_snapshots(baseline: Dict[str, Any], latest: Dict[str, Any]) -> Dict[str, Any]:
    deltas: Dict[str, int] = {}
    increasing = []
    decreased = []

    for key in COUNTER_KEYS:
        b = safe_int(baseline.get(key))
        l = safe_int(latest.get(key))

        if b is None or l is None:
            continue

        d = l - b
        deltas[key] = d

        if d > 0:
            increasing.append(key)
        elif d < 0:
            decreased.append(key)

    if increasing:
        status = "still_increasing"
        conclusion = "接口错包计数仍在持续增加，需要继续定位物理层、对端、聚合成员和链路质量。"
    elif deltas:
        status = "not_increasing"
        conclusion = "两次取证之间未观察到错包计数继续增加，可能为历史累计或短时异常。"
    else:
        status = "unknown"
        conclusion = "无法完成前后计数器对比，建议人工复核两次命令输出。"

    return {
        "status": status,
        "deltas": deltas,
        "increasing_counters": increasing,
        "decreased_counters": decreased,
        "conclusion": conclusion,
    }


def build_recommendations(compare: Dict[str, Any], interface: str) -> List[str]:
    status = compare.get("status")
    increasing = compare.get("increasing_counters") or []

    if status == "still_increasing":
        rec = [
            f"接口 {interface or '未知接口'} 错包计数仍在增长，建议优先检查物理链路质量、光模块、跳线、ODF、对端端口和聚合成员状态。",
            "如果 CRC/FCS 与 input_errors 同步增长，优先按物理层误码方向排查；如只在单个成员口增长，重点检查该成员链路。",
            "建议对比对端接口 counters errors，并结合接口日志确认是否存在 flap、LACP 成员切换或模块异常。",
        ]
        if "out_discards" in increasing or "output_discards" in increasing:
            rec.append("如丢弃类计数也增长，需要结合队列、拥塞、微突发和上联带宽利用率继续确认。")
        return rec

    if status == "not_increasing":
        return [
            f"接口 {interface or '未知接口'} 在二次取证窗口内错包计数未继续增加，可优先判断为历史累计或短时异常。",
            "建议结合 Prometheus 5-15 分钟告警窗口确认告警触发时是否为瞬时增长，并关注后续是否再次触发。",
        ]

    return [
        "二次取证未能形成明确 counter delta 结论，建议人工复核 baseline/latest 命令输出。",
    ]


def run_delta_check(
    request_id: str,
    base_dir: Path = BASE_DIR,
    delay_seconds: int = 0,
    execute: bool = True,
    latest_output_override: str = "",
) -> Dict[str, Any]:
    base_dir = Path(base_dir)
    ddir = delta_dir(base_dir)
    ddir.mkdir(parents=True, exist_ok=True)

    started_at = utc_now()
    execution_path = execution_file_by_request_id(request_id, base_dir)
    execution_data = read_json(execution_path)

    if not is_error_counter_alert(execution_data):
        result = {
            "ok": False,
            "stage": "v7.9_interface_error_delta_recheck",
            "request_id": request_id,
            "status": "skipped",
            "skip_reason": "not_interface_error_counter_alert",
            "created_at": utc_now(),
        }
        write_json(result_file(request_id, base_dir), result)
        return result

    interface = extract_interface(execution_data)
    baseline = extract_baseline_snapshot(execution_data)

    if delay_seconds and delay_seconds > 0:
        time.sleep(delay_seconds)

    latest_command_result = {}
    latest_snapshot: Dict[str, Any]

    if latest_output_override:
        command = build_recheck_command(interface, execution_data)
        latest_snapshot = parse_counter_snapshot(
            command=command,
            output=latest_output_override,
            interface=interface,
        )
        latest_snapshot["source"] = "override"
        latest_command_result = {
            "ok": True,
            "command": command,
            "command_results": [
                {
                    "command": command,
                    "dispatch_status": "completed",
                    "output": latest_output_override,
                }
            ],
        }
    elif execute:
        latest_command_result = run_mcp_counter_command(
            request_id=request_id,
            execution_data=execution_data,
            interface=interface,
        )

        outputs = []
        for item in latest_command_result.get("command_results") or []:
            if isinstance(item, dict):
                outputs.append(extract_text(item.get("output")))

        latest_output = "\n".join([x for x in outputs if x])
        latest_snapshot = parse_counter_snapshot(
            command=safe_text(latest_command_result.get("command")),
            output=latest_output,
            interface=interface,
        )
        latest_snapshot["source"] = "mcp_recheck"
    else:
        latest_snapshot = {
            "matched": False,
            "interface": interface,
            "source": "not_executed",
            "error": "execute_false_and_no_latest_output_override",
        }

    compare = compare_snapshots(baseline, latest_snapshot)
    recommendations = build_recommendations(compare, interface)

    result = {
        "ok": True,
        "stage": "v7.9_interface_error_delta_recheck",
        "request_id": request_id,
        "created_at": utc_now(),
        "started_at": started_at,
        "delay_seconds": delay_seconds,
        "interface": interface,
        "family": get_family(execution_data),
        "baseline": baseline,
        "latest": latest_snapshot,
        "compare": compare,
        "recommendations": recommendations,
        "latest_command_result_summary": {
            "ok": latest_command_result.get("ok"),
            "command": latest_command_result.get("command"),
            "command_count": len(latest_command_result.get("command_results") or []),
        },
        "result_file": str(result_file(request_id, base_dir)),
        "safety": {
            "readonly_only": True,
            "writes_device_config": False,
            "sidecar_only": True,
        },
    }

    write_json(result_file(request_id, base_dir), result)
    return result


def read_delta_result(request_id: str, base_dir: Path = BASE_DIR) -> Dict[str, Any]:
    path = result_file(request_id, base_dir)
    if not path.exists():
        raise FileNotFoundError(f"interface error delta result not found for request_id={request_id}")
    return read_json(path)


def list_delta_results(base_dir: Path = BASE_DIR, limit: int = 20) -> List[Dict[str, Any]]:
    root = delta_dir(base_dir)
    if not root.exists():
        return []

    rows = []
    for path in root.glob("*.delta.json"):
        try:
            item = read_json(path)
        except Exception:
            continue
        rows.append(item)

    rows.sort(key=lambda x: safe_text(x.get("created_at")), reverse=True)

    if limit and limit > 0:
        return rows[:limit]

    return rows


def schedule_delta_check(
    request_id: str,
    base_dir: Path = BASE_DIR,
    delay_seconds: Optional[int] = None,
    force: bool = False,
) -> Dict[str, Any]:
    base_dir = Path(base_dir)
    ddir = delta_dir(base_dir)
    ddir.mkdir(parents=True, exist_ok=True)

    if delay_seconds is None:
        delay_seconds = safe_int(os.getenv("NETAIOPS_INTERFACE_ERROR_DELTA_DELAY_SECONDS")) or 300

    existing_job = job_file(request_id, base_dir)
    existing_result = result_file(request_id, base_dir)

    if existing_result.exists() and not force:
        return {
            "ok": True,
            "stage": "v7.9_interface_error_delta_schedule",
            "request_id": request_id,
            "scheduled": False,
            "reason": "delta_result_already_exists",
            "result_file": str(existing_result),
        }

    if existing_job.exists() and not force:
        return {
            "ok": True,
            "stage": "v7.9_interface_error_delta_schedule",
            "request_id": request_id,
            "scheduled": False,
            "reason": "job_already_exists",
            "job_file": str(existing_job),
        }

    execution_path = execution_file_by_request_id(request_id, base_dir)
    execution_data = read_json(execution_path)

    if not is_error_counter_alert(execution_data):
        return {
            "ok": True,
            "stage": "v7.9_interface_error_delta_schedule",
            "request_id": request_id,
            "scheduled": False,
            "reason": "not_interface_error_counter_alert",
        }

    interface = extract_interface(execution_data)
    if not interface:
        return {
            "ok": False,
            "stage": "v7.9_interface_error_delta_schedule",
            "request_id": request_id,
            "scheduled": False,
            "reason": "interface_not_found",
        }

    job = {
        "stage": "v7.9_interface_error_delta_schedule",
        "request_id": request_id,
        "created_at": utc_now(),
        "delay_seconds": delay_seconds,
        "interface": interface,
        "status": "scheduled",
        "job_file": str(existing_job),
        "result_file": str(existing_result),
        "log_file": str(log_file(request_id, base_dir)),
    }
    write_json(existing_job, job)

    cmd = [
        sys.executable,
        str(Path(base_dir) / "tools" / "run_interface_error_delta_check.py"),
        "--rid",
        request_id,
        "--delay",
        str(delay_seconds),
        "--summary",
    ]

    lf = log_file(request_id, base_dir)
    out = lf.open("ab")
    proc = subprocess.Popen(
        cmd,
        cwd=str(base_dir),
        stdout=out,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        close_fds=True,
    )

    job["status"] = "scheduled_process_started"
    job["pid"] = proc.pid
    write_json(existing_job, job)

    return {
        "ok": True,
        "stage": "v7.9_interface_error_delta_schedule",
        "request_id": request_id,
        "scheduled": True,
        "delay_seconds": delay_seconds,
        "interface": interface,
        "pid": proc.pid,
        "job_file": str(existing_job),
        "result_file": str(existing_result),
        "log_file": str(lf),
    }


def maybe_schedule_from_callback(
    request_id: str,
    callback_result: Dict[str, Any],
    base_dir: Path = BASE_DIR,
) -> Dict[str, Any]:
    execution_data = (callback_result or {}).get("execution_data") or {}
    if not isinstance(execution_data, dict):
        return {
            "ok": True,
            "scheduled": False,
            "reason": "callback_result_has_no_execution_data",
        }

    if not is_error_counter_alert(execution_data):
        return {
            "ok": True,
            "scheduled": False,
            "reason": "not_interface_error_counter_alert",
        }

    return schedule_delta_check(
        request_id=request_id,
        base_dir=base_dir,
        delay_seconds=None,
        force=False,
    )


def enrich_summary_with_delta(
    summary: Dict[str, Any],
    execution_data: Dict[str, Any],
    base_dir: Path = BASE_DIR,
) -> Dict[str, Any]:
    request_id = safe_text(execution_data.get("request_id"))
    if not request_id:
        return summary

    try:
        delta = read_delta_result(request_id, base_dir=base_dir)
    except Exception:
        return summary

    compare = delta.get("compare") or {}
    status = compare.get("status")
    deltas = compare.get("deltas") or {}

    line = f"二次错包取证：status={status}，delta={deltas}"
    summary.setdefault("notify_lines", []).append(line)
    summary.setdefault("key_findings", []).append(line)

    for rec in delta.get("recommendations") or []:
        summary.setdefault("recommendations", []).append(rec)

    if compare.get("conclusion"):
        summary["conclusion"] = compare.get("conclusion")

    summary.setdefault("facts", {})["interface_error_delta"] = {
        "status": status,
        "deltas": deltas,
        "result_file": delta.get("result_file"),
    }

    return summary
