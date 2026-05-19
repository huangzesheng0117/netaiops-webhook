from __future__ import annotations

from typing import Any


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _is_not_empty(value: Any) -> bool:
    return value is not None and _safe_text(value) != ""


def _normalize_interface(value: Any) -> str:
    text = _safe_text(value).lower()
    if not text:
        return ""

    replacements = [
        ("tengigabitethernet", "te"),
        ("ten-gigabitethernet", "te"),
        ("ten-gigabit-ethernet", "te"),
        ("gigabitethernet", "gi"),
        ("fastethernet", "fa"),
        ("ethernet", "eth"),
        ("port-channel", "po"),
        ("portchannel", "po"),
    ]

    for old, new in replacements:
        text = text.replace(old, new)

    return text.replace(" ", "")


def _unwrap_execution_data(execution_data: dict[str, Any]) -> dict[str, Any]:
    if isinstance(execution_data, dict) and isinstance(execution_data.get("execution_data"), dict):
        return execution_data.get("execution_data") or {}
    return execution_data or {}


def _iter_parsed_items(execution_data: dict[str, Any]) -> list[dict[str, Any]]:
    data = _unwrap_execution_data(execution_data)
    result = []

    for item in data.get("command_results", []) or []:
        if not isinstance(item, dict):
            continue

        parsed_result = item.get("parsed")
        if not isinstance(parsed_result, dict):
            continue

        if parsed_result.get("status") != "parsed":
            continue

        parsed = parsed_result.get("parsed")
        if not isinstance(parsed, dict):
            continue

        result.append({
            "command": item.get("command", ""),
            "parser": parsed_result.get("parser", ""),
            "parsed": parsed,
        })

    return result


def _target_interfaces(execution_data: dict[str, Any], summary: dict[str, Any]) -> list[str]:
    targets = []

    data = _unwrap_execution_data(execution_data)
    target_scope = data.get("target_scope") if isinstance(data.get("target_scope"), dict) else {}

    facts = summary.get("facts") if isinstance(summary.get("facts"), dict) else {}

    for value in [
        target_scope.get("interface"),
        facts.get("interface"),
        facts.get("command_interface"),
    ]:
        if _is_not_empty(value):
            targets.append(_safe_text(value))

    interfaces = target_scope.get("interfaces")
    if isinstance(interfaces, list):
        for value in interfaces:
            if _is_not_empty(value):
                targets.append(_safe_text(value))

    result = []
    seen = set()
    for item in targets:
        n = _normalize_interface(item)
        if not n or n in seen:
            continue
        seen.add(n)
        result.append(item)

    return result


def _matches_target(parsed: dict[str, Any], target_norms: set[str]) -> bool:
    if not target_norms:
        return True

    candidates = [
        parsed.get("interface"),
        parsed.get("command_interface"),
    ]

    for value in candidates:
        n = _normalize_interface(value)
        if n and n in target_norms:
            return True

    return False


def _select_parsed(parsed_items: list[dict[str, Any]], parser_name: str, target_norms: set[str]) -> dict[str, Any]:
    candidates = [x.get("parsed") or {} for x in parsed_items if x.get("parser") == parser_name]

    for parsed in candidates:
        if _matches_target(parsed, target_norms):
            return parsed

    return candidates[0] if candidates else {}


def _set_if_present(facts: dict[str, Any], key: str, value: Any) -> None:
    if _is_not_empty(value):
        facts[key] = value


def _set_many(facts: dict[str, Any], parsed: dict[str, Any], mapping: dict[str, str]) -> None:
    for src, dst in mapping.items():
        if src in parsed and parsed.get(src) is not None:
            facts[dst] = parsed.get(src)


def _replace_status_lines(lines: list[Any], status_line: str) -> list[Any]:
    result = []
    replaced = False

    for line in lines or []:
        text = _safe_text(line)
        if text.startswith("接口状态："):
            if not replaced:
                result.append(status_line)
                replaced = True
            continue
        result.append(line)

    if not replaced:
        result.insert(0, status_line)

    return result


def apply_parsed_facts_to_summary(summary: dict[str, Any], execution_data: dict[str, Any]) -> dict[str, Any]:
    summary = dict(summary or {})
    facts = dict(summary.get("facts", {}) or {})

    parsed_items = _iter_parsed_items(execution_data)
    if not parsed_items:
        return summary

    targets = _target_interfaces(execution_data, summary)
    target_norms = {_normalize_interface(x) for x in targets if _normalize_interface(x)}

    detail = _select_parsed(parsed_items, "cisco_show_interfaces", target_norms)
    counters = _select_parsed(parsed_items, "cisco_show_interfaces_counters_errors", target_norms)
    etherchannel = _select_parsed(parsed_items, "cisco_etherchannel_summary", set())

    used_parsers = []

    if detail:
        used_parsers.append("cisco_show_interfaces")
        _set_if_present(facts, "interface", detail.get("interface"))
        _set_if_present(facts, "admin_status", detail.get("admin_status"))
        _set_if_present(facts, "oper_status", detail.get("oper_status"))
        _set_if_present(facts, "oper_detail", detail.get("oper_detail"))
        _set_if_present(facts, "description", detail.get("description"))

        _set_many(facts, detail, {
            "bandwidth_bps": "bandwidth_bps",
            "bandwidth_kbit": "bandwidth_kbit",
            "input_rate_bps": "input_rate_bps",
            "output_rate_bps": "output_rate_bps",
            "input_utilization_percent_estimated": "input_utilization_percent_estimated",
            "output_utilization_percent_estimated": "output_utilization_percent_estimated",
            "input_errors": "input_errors",
            "crc": "crc",
            "frame": "frame",
            "overrun": "overrun",
            "ignored": "ignored",
            "output_errors": "output_errors",
            "output_drops": "output_drops",
            "interface_resets": "interface_resets",
        })

        if detail.get("bandwidth_bps") is not None:
            facts["interface_bandwidth_bps"] = detail.get("bandwidth_bps")
            facts["physical_bandwidth_bps"] = detail.get("bandwidth_bps")

    if counters:
        used_parsers.append("cisco_show_interfaces_counters_errors")
        _set_if_present(facts, "counter_interface", counters.get("interface"))
        _set_if_present(facts, "command_interface", counters.get("command_interface"))

        _set_many(facts, counters, {
            "align_err": "align_err",
            "fcs_err": "fcs_err",
            "crc": "crc",
            "xmit_err": "xmit_err",
            "rcv_err": "rcv_err",
            "input_errors": "input_errors",
            "undersize": "undersize",
            "out_discards": "out_discards",
            "output_discards": "output_discards",
            "single_col": "single_col",
            "multi_col": "multi_col",
            "late_col": "late_col",
            "excess_col": "excess_col",
            "carri_sen": "carri_sen",
            "runts": "runts",
        })

    if etherchannel:
        used_parsers.append("cisco_etherchannel_summary")
        _set_many(facts, etherchannel, {
            "channel_group_count": "channel_group_count",
            "aggregator_count": "aggregator_count",
            "port_channel_count": "port_channel_count",
            "member_count": "etherchannel_member_count",
            "bundled_member_count": "etherchannel_bundled_member_count",
            "down_member_count": "etherchannel_down_member_count",
        })

        facts["etherchannel_port_channels"] = etherchannel.get("port_channels", [])
        facts["etherchannel_members"] = etherchannel.get("members", [])

    if used_parsers:
        facts["parsed_facts_enabled"] = True
        facts["facts_source_preference"] = "parsed_first_raw_fallback"
        facts["parsed_fact_sources"] = sorted(set(used_parsers))

    interface = _safe_text(facts.get("interface"))
    oper = _safe_text(facts.get("oper_status"))
    admin = _safe_text(facts.get("admin_status"))

    if interface or oper or admin:
        status_line = f"接口状态：{interface or '未知接口'} oper={oper or '未知'} admin={admin or '未知'}"
        summary["notify_lines"] = _replace_status_lines(summary.get("notify_lines", []) or [], status_line)
        summary["key_findings"] = _replace_status_lines(summary.get("key_findings", []) or [], status_line)

    summary["facts"] = facts
    return summary
