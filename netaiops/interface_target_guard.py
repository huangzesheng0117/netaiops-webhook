from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Tuple


INTERFACE_FAMILY_PREFIXES = (
    "interface_",
    "link_",
)
INTERFACE_FAMILIES = {
    "interface_or_link_utilization_high",
    "interface_or_link_traffic_drop",
    "interface_traffic_anomaly",
    "interface_packet_loss_or_discards_high",
    "interface_status_or_flap",
}
INTERFACE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._:/-]{0,127}$")
CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
INVALID_INTERFACE_WORDS = {
    "unknown",
    "none",
    "null",
    "n/a",
    "na",
    "interface",
    "port",
    "link",
    "device",
}
POLICY_REASON_MISSING = "interface_target_missing"
POLICY_REASON_INVALID = "interface_target_invalid"
POLICY_REASON_COMMAND = "interface_command_invalid"


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _family(family_result: Mapping[str, Any], event: Mapping[str, Any]) -> str:
    for value in (
        family_result.get("family"),
        event.get("family"),
        event.get("playbook_type_hint"),
    ):
        text = _text(value).lower()
        if text:
            return text
    return ""


def is_interface_family(
    family_result: Mapping[str, Any],
    event: Mapping[str, Any],
) -> bool:
    family = _family(family_result, event)
    return (
        family in INTERFACE_FAMILIES
        or family.startswith(INTERFACE_FAMILY_PREFIXES)
    )


def validate_interface_name(
    value: Any,
    *,
    event: Mapping[str, Any] | None = None,
) -> Tuple[bool, List[str]]:
    text = _text(value)
    event = _mapping(event)
    reasons: List[str] = []

    if not text:
        return False, ["interface_missing"]
    if len(text) > 128:
        reasons.append("interface_too_long")
    if CONTROL_RE.search(text):
        reasons.append("interface_contains_control_character")
    if CJK_RE.search(text):
        reasons.append("interface_contains_cjk_alert_text")
    if any(char.isspace() for char in text):
        reasons.append("interface_contains_whitespace")
    if not INTERFACE_NAME_RE.fullmatch(text):
        reasons.append("interface_format_invalid")
    if text.lower() in INVALID_INTERFACE_WORDS:
        reasons.append("interface_generic_word")

    labels = _mapping(event.get("labels"))
    # object_name is intentionally not included here. For interface alerts,
    # object_name commonly equals the valid interface identifier.
    alert_values = {
        _text(event.get("alarm_type")).lower(),
        _text(event.get("alert_name")).lower(),
        _text(labels.get("alertname")).lower(),
    }
    alert_values.discard("")
    if text.lower() in alert_values:
        reasons.append("interface_equals_alert_name")

    return len(reasons) == 0, reasons


def _candidate_is_safe(
    item: Mapping[str, Any],
    *,
    interface: str,
) -> Tuple[bool, List[str]]:
    command = _text(item.get("command"))
    reasons: List[str] = []

    if not command:
        reasons.append("command_empty")
    if len(command) > 512:
        reasons.append("command_too_long")
    if CONTROL_RE.search(command):
        reasons.append("command_contains_control_character")
    if CJK_RE.search(command):
        reasons.append("command_contains_cjk_alert_text")
    if "{" in command or "}" in command:
        reasons.append("command_contains_unresolved_placeholder")

    candidate_interface = _text(item.get("interface"))
    if candidate_interface:
        valid, candidate_reasons = validate_interface_name(candidate_interface)
        if not valid:
            reasons.extend(
                f"candidate_{reason}" for reason in candidate_reasons
            )

    if interface and CJK_RE.search(interface):
        reasons.append("validated_interface_contains_cjk")

    return len(reasons) == 0, reasons


def apply_interface_target_guard(
    *,
    event: Mapping[str, Any],
    family_result: Mapping[str, Any],
    target_scope: Mapping[str, Any],
    execution_candidates: Iterable[Mapping[str, Any]],
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]:
    scope = dict(target_scope or {})
    candidates = [
        dict(item)
        for item in (execution_candidates or [])
        if isinstance(item, Mapping)
    ]

    if not is_interface_family(family_result, event):
        return scope, candidates, {
            "applicable": False,
            "status": "not_applicable",
            "reasons": [],
            "original_interface": "",
            "normalized_interface": "",
            "original_candidate_count": len(candidates),
            "kept_candidate_count": len(candidates),
            "dropped_candidate_count": 0,
        }

    interface = _text(
        scope.get("interface")
        or scope.get("if_name")
        or scope.get("ifName")
        or scope.get("interface_name")
    )
    valid, reasons = validate_interface_name(interface, event=event)

    if not valid:
        for key in ("interface", "if_name", "ifName", "interface_name"):
            scope[key] = ""
        return scope, [], {
            "applicable": True,
            "status": "blocked",
            "reasons": reasons,
            "policy_reason": (
                POLICY_REASON_MISSING
                if reasons == ["interface_missing"]
                else POLICY_REASON_INVALID
            ),
            "original_interface": interface,
            "normalized_interface": "",
            "original_candidate_count": len(candidates),
            "kept_candidate_count": 0,
            "dropped_candidate_count": len(candidates),
        }

    kept: List[Dict[str, Any]] = []
    dropped: List[Dict[str, Any]] = []
    for item in candidates:
        safe, candidate_reasons = _candidate_is_safe(
            item,
            interface=interface,
        )
        if safe:
            kept.append(item)
        else:
            dropped.append(
                {
                    "order": item.get("order"),
                    "reasons": candidate_reasons,
                }
            )

    for index, item in enumerate(kept, start=1):
        item["order"] = index

    status = "valid"
    policy_reason = ""
    guard_reasons: List[str] = []
    if candidates and not kept:
        status = "blocked"
        policy_reason = POLICY_REASON_COMMAND
        guard_reasons.append("all_interface_commands_rejected")
    elif dropped:
        status = "partial"
        guard_reasons.append("some_interface_commands_rejected")

    return scope, kept, {
        "applicable": True,
        "status": status,
        "reasons": guard_reasons,
        "policy_reason": policy_reason,
        "original_interface": interface,
        "normalized_interface": interface,
        "original_candidate_count": len(candidates),
        "kept_candidate_count": len(kept),
        "dropped_candidate_count": len(dropped),
        "dropped_candidates": dropped,
    }


def apply_interface_guard_to_policy(
    policy_result: Mapping[str, Any],
    interface_guard: Mapping[str, Any],
) -> Dict[str, Any]:
    result = dict(policy_result or {})
    guard = dict(interface_guard or {})

    if not guard.get("applicable"):
        return result
    if guard.get("status") not in {"blocked"}:
        checked = dict(result.get("checked_items") or {})
        checked["interface_target_guard_status"] = guard.get("status")
        result["checked_items"] = checked
        return result

    reason = _text(guard.get("policy_reason")) or POLICY_REASON_INVALID
    reasons = list(result.get("reasons") or [])
    if reason not in reasons:
        reasons.append(reason)

    checked = dict(result.get("checked_items") or {})
    checked.update(
        {
            "interface_target_guard_status": guard.get("status"),
            "interface_target_present": bool(
                guard.get("normalized_interface")
            ),
            "interface_candidates_kept": guard.get(
                "kept_candidate_count", 0
            ),
            "interface_candidates_dropped": guard.get(
                "dropped_candidate_count", 0
            ),
        }
    )

    result["auto_confirm_allowed"] = False
    result["reasons"] = reasons
    result["policy_summary"] = "blocked_by_interface_target_guard"
    result["checked_items"] = checked
    return result
