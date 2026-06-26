#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Normalize Cisco/NX-OS CLI command results.

目的：
- Netmiko/MCP 有时会把命令执行完成标记为 completed，但设备输出其实是硬错误。
- 例如：
  * % Invalid command
  * Invalid interface format
  * Invalid input detected at '^' marker
- 这些结果必须在 execution.json / review / notification 中按 failed 处理。
"""

from __future__ import annotations

import copy
import re
from typing import Any, Dict, List


_HARD_ERROR_PATTERNS = [
    r"%\s*Invalid command",
    r"%\s*Invalid input detected",
    r"%\s*Ambiguous command",
    r"%\s*Incomplete command",
    r"Invalid interface format",
    r"Invalid range",
    r"Unknown command",
    r"command not found",
    r"syntax error",
    r"not supported on this platform",
]

_HARD_ERROR_RE = re.compile("|".join(f"(?:{p})" for p in _HARD_ERROR_PATTERNS), re.IGNORECASE)


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def is_cli_hard_error_output(output: Any, error: Any = "") -> bool:
    text = "\n".join([_safe_text(output), _safe_text(error)])
    if not text.strip():
        return False
    return bool(_HARD_ERROR_RE.search(text))


def normalize_command_result(item: Dict[str, Any]) -> Dict[str, Any]:
    result = copy.deepcopy(item or {})

    output = result.get("output")
    error = result.get("error")

    if is_cli_hard_error_output(output, error):
        result["dispatch_status"] = "failed"
        if not result.get("error"):
            # 取第一条命中的错误文本，便于排障。
            text = "\n".join([_safe_text(output), _safe_text(error)])
            matched = _HARD_ERROR_RE.search(text)
            result["error"] = matched.group(0) if matched else "cli_hard_error_detected"

        judge = result.get("judge")
        if not isinstance(judge, dict):
            judge = {}
        judge["final_status"] = "failed"
        judge["hard_error"] = True
        judge["matched_rule_id"] = judge.get("matched_rule_id") or "v9_cli_hard_error_output"
        judge["matched_text"] = judge.get("matched_text") or result.get("error") or "cli_hard_error_detected"
        judge["judge_reason"] = "v9 normalized device CLI hard error output"
        result["judge"] = judge

    return result


def normalize_command_results(command_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not isinstance(command_results, list):
        return []
    return [normalize_command_result(item) for item in command_results]


def normalize_execution_callback_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    result = copy.deepcopy(payload or {})
    result["command_results"] = normalize_command_results(result.get("command_results") or [])
    return result
