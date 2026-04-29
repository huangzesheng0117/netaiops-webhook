import re
from typing import Any, Dict, List


JUDGE_RULESETS: Dict[str, Dict[str, List[Dict[str, str]]]] = {
    "network_cli_generic": {
        "hard_fail": [
            {"id": "invalid_command", "pattern": r"%\s*Invalid (input|command)"},
            {"id": "invalid_command_marker", "pattern": r"Invalid command at ['\"]?\^['\"]? marker"},
            {"id": "incorrect_command", "pattern": r"\bIncorrect command\b"},
            {"id": "unrecognized_command", "pattern": r"\b(Unrecognized|Unrecognised) command\b"},
            {"id": "wrong_parameter", "pattern": r"\bWrong parameter\b"},
            {"id": "command_fail", "pattern": r"\bCommand fail\b"},
            {"id": "ambiguous_command", "pattern": r"%\s*Ambiguous command"},
            {"id": "incomplete_command", "pattern": r"%\s*Incomplete command"},
            {"id": "unknown_command", "pattern": r"\bunknown command\b"},
            {"id": "syntax_error", "pattern": r"\bSyntax Error\b"},
            {"id": "shell_command_not_found", "pattern": r"bash:\s*.+command not found"},
            {"id": "tail_cannot_open", "pattern": r"cannot open ['\"]?\d+['\"]? for reading"},
            {"id": "no_such_file_or_directory", "pattern": r"No such file or directory"},
            {"id": "auth_failed", "pattern": r"authentication failed"},
            {"id": "permission_denied", "pattern": r"permission denied"},
            {"id": "validation_error", "pattern": r"validation error"},
            {"id": "traceback", "pattern": r"Traceback"},
            {"id": "no_device_named", "pattern": r"no device named"},
            {"id": "timeout", "pattern": r"(timed out|timeout)"},
        ],
        "ignore": [
            {"id": "input_errors_counter", "pattern": r"\binput errors\b"},
            {"id": "crc_counter", "pattern": r"\bCRC\b"},
            {"id": "output_errors_counter", "pattern": r"\boutput errors\b"},
            {"id": "error_packets_counter", "pattern": r"\berror packets\b"},
        ],
    },
    "f5_tmsh": {
        "hard_fail": [
            {"id": "tmsh_syntax_error", "pattern": r"Syntax Error:"},
            {"id": "object_not_found", "pattern": r"was not found"},
            {"id": "auth_failed", "pattern": r"Authentication failed"},
            {"id": "validation_error", "pattern": r"validation error"},
            {"id": "traceback", "pattern": r"Traceback"},
        ],
        "ignore": [],
    },
}


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _match_rules(text: str, rules: List[Dict[str, str]]) -> Dict[str, str]:
    for rule in rules:
        pattern = rule.get("pattern", "")
        if not pattern:
            continue
        m = re.search(pattern, text, flags=re.IGNORECASE)
        if m:
            return {
                "matched_rule_id": rule.get("id", ""),
                "matched_text": m.group(0),
            }
    return {
        "matched_rule_id": "",
        "matched_text": "",
    }


def judge_command_result(
    command: str,
    output: Any = "",
    error: Any = "",
    judge_profile: str = "network_cli_generic",
    dispatch_status: str = "",
) -> Dict[str, Any]:
    ruleset = JUDGE_RULESETS.get(judge_profile, JUDGE_RULESETS["network_cli_generic"])
    merged_text = "\n".join(
        [
            _safe_text(command),
            _safe_text(output),
            _safe_text(error),
        ]
    )

    hard_match = _match_rules(merged_text, ruleset.get("hard_fail", []))
    if hard_match["matched_rule_id"]:
        return {
            "final_status": "failed",
            "hard_error": True,
            "matched_rule_id": hard_match["matched_rule_id"],
            "matched_text": hard_match["matched_text"],
            "judge_reason": "hard_fail_pattern_matched",
        }

    ignore_match = _match_rules(merged_text, ruleset.get("ignore", []))
    if ignore_match["matched_rule_id"] and not _safe_text(error).strip():
        if dispatch_status == "failed":
            return {
                "final_status": "failed",
                "hard_error": False,
                "matched_rule_id": "",
                "matched_text": "",
                "judge_reason": "dispatch_failed_without_hard_pattern",
            }
        return {
            "final_status": dispatch_status or "completed",
            "hard_error": False,
            "matched_rule_id": "",
            "matched_text": "",
            "judge_reason": "ignore_pattern_matched_only",
        }

    if dispatch_status == "failed":
        return {
            "final_status": "failed",
            "hard_error": False,
            "matched_rule_id": "",
            "matched_text": "",
            "judge_reason": "dispatch_failed_without_pattern",
        }

    return {
        "final_status": dispatch_status or "completed",
        "hard_error": False,
        "matched_rule_id": "",
        "matched_text": "",
        "judge_reason": "no_hard_fail_pattern_matched",
    }
