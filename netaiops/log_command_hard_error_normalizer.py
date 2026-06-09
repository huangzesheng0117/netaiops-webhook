#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
from typing import Any, Dict


LOG_COMMAND_RE = re.compile(
    r"^\s*(show\s+logging|show\s+log|display\s+logbuffer|display\s+log|show\s+event\s+logging)\b",
    re.I,
)

# 只有这些出现在输出开头时，才认为是“本条命令真的失败”。
DIRECT_CLI_ERROR_RE = re.compile(
    r"^\s*(\^+\s*)?(% ?Invalid command|Invalid command|Incomplete command|Ambiguous command|No such file or directory|"
    r"Error:|ERROR:|syntax error|command not found)\b",
    re.I,
)

FALSE_POSITIVE_RULE_IDS = {
    "no_such_file_or_directory",
    "invalid_command",
    "incomplete_command",
    "ambiguous_command",
    "generic_error",
    "error",
}


def _safe_text(value: Any) -> str:
    return "" if value is None else str(value)


def _looks_like_log_output(output: str) -> bool:
    """
    日志查看命令的正常输出通常是大量带日期/时间/设备名/%FACILITY-SEV-MNEMONIC 的日志行。
    这种输出里出现 'No such file or directory' / 'error' 只能说明日志正文里有历史事件，
    不能说明当前 show logging 命令失败。
    """
    text = _safe_text(output)
    if len(text) < 300:
        return False

    lines = [x for x in text.splitlines() if x.strip()]
    if len(lines) < 5:
        return False

    sample = "\n".join(lines[:30])
    log_signals = [
        r"\b20\d{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
        r"%[A-Z0-9_]+-\d+-[A-Z0-9_]+",
        r"\b(message repeated \d+ time",
        r"\bSYSTEM_MSG\b",
        r"\bETHPORT-\d+-",
        r"\bBGP-\d+-",
        r"\bBFD-\d+-",
        r"\bLICMGR-\d+-",
    ]

    return any(re.search(pat, sample, re.I) for pat in log_signals)


def _direct_cli_error(output: str) -> bool:
    text = _safe_text(output).lstrip()
    if not text:
        return False

    # 典型真正失败：
    # ^
    # % Invalid command at '^' marker.
    head = "\n".join(text.splitlines()[:5]).strip()
    return bool(DIRECT_CLI_ERROR_RE.search(head))


def _normalize_one_command_result(item: Dict[str, Any]) -> None:
    cmd = _safe_text(item.get("command")).strip()
    if not LOG_COMMAND_RE.search(cmd):
        return

    judge = item.get("judge")
    if not isinstance(judge, dict):
        return

    if not judge.get("hard_error"):
        return

    matched_rule_id = _safe_text(judge.get("matched_rule_id")).strip()
    matched_text = _safe_text(judge.get("matched_text")).strip()

    output = item.get("output")
    if output is None:
        output = item.get("stdout")
    if output is None:
        output = item.get("result")
    output = _safe_text(output)

    if matched_rule_id and matched_rule_id not in FALSE_POSITIVE_RULE_IDS:
        return

    # 如果输出开头就是设备返回的命令错误，必须保留 failed。
    if _direct_cli_error(output):
        return

    # 如果是大量日志正文，则把 hard-error 调整为 completed。
    if not _looks_like_log_output(output):
        return

    old_status = item.get("dispatch_status") or item.get("status") or item.get("final_status")

    item["dispatch_status"] = "completed"
    if "status" in item and item.get("status") not in (None, "", "skipped"):
        item["status"] = "completed"
    item["final_status"] = "completed"

    judge["final_status"] = "completed"
    judge["hard_error"] = False
    judge["false_hard_error_normalized"] = True
    judge["original_status"] = old_status
    judge["original_matched_rule_id"] = matched_rule_id
    judge["original_matched_text"] = matched_text
    judge["judge_reason"] = (
        "log_command_output_contains_historical_error_text; "
        "the command returned normal log output, so hard-error was normalized"
    )

    item["log_command_false_hard_error_normalized"] = True


def normalize_log_command_false_hard_errors(payload: Any) -> Any:
    """
    递归处理 callback / runner / execution payload。
    只调整日志查看命令的误判，不影响真正的 CLI 语法错误。
    """
    if isinstance(payload, dict):
        if isinstance(payload.get("command"), str):
            _normalize_one_command_result(payload)

        for value in list(payload.values()):
            normalize_log_command_false_hard_errors(value)

    elif isinstance(payload, list):
        for value in payload:
            normalize_log_command_false_hard_errors(value)

    return payload
