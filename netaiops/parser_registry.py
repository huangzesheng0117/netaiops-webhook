from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Callable

from netaiops.parsers.cisco_interface import can_parse as can_parse_cisco_interface
from netaiops.parsers.cisco_interface import parse_cisco_show_interfaces
from netaiops.parsers.cisco_interface_counters import can_parse as can_parse_cisco_interface_counters
from netaiops.parsers.cisco_interface_counters import parse_cisco_show_interfaces_counters_errors
from netaiops.parsers.cisco_etherchannel import can_parse as can_parse_cisco_etherchannel
from netaiops.parsers.cisco_etherchannel import parse_cisco_etherchannel_summary


ParserFunc = Callable[[str, str, str], dict[str, Any]]
CanParseFunc = Callable[[str, str], bool]


@dataclass(frozen=True)
class ParserSpec:
    parser_name: str
    description: str
    platforms: list[str]
    command_keywords: list[str]
    parser_func: ParserFunc
    can_parse_func: CanParseFunc
    enabled: bool = True


PARSER_SPECS: list[ParserSpec] = [
    ParserSpec(
        parser_name="cisco_show_interfaces",
        description="Parse Cisco IOS/IOS-XE show interfaces output into structured facts.",
        platforms=["cisco_iosxe", "cisco_ios", "iosxe", "ios"],
        command_keywords=["show interfaces"],
        parser_func=parse_cisco_show_interfaces,
        can_parse_func=can_parse_cisco_interface,
    ),
    ParserSpec(
        parser_name="cisco_show_interfaces_counters_errors",
        description="Parse Cisco IOS/IOS-XE show interfaces counters errors output into structured facts.",
        platforms=["cisco_iosxe", "cisco_ios", "iosxe", "ios"],
        command_keywords=["show interfaces", "counters errors"],
        parser_func=parse_cisco_show_interfaces_counters_errors,
        can_parse_func=can_parse_cisco_interface_counters,
    ),
    ParserSpec(
        parser_name="cisco_etherchannel_summary",
        description="Parse Cisco IOS/IOS-XE show etherchannel summary output into structured facts.",
        platforms=["cisco_iosxe", "cisco_ios", "iosxe", "ios"],
        command_keywords=["show etherchannel summary", "show port-channel summary"],
        parser_func=parse_cisco_etherchannel_summary,
        can_parse_func=can_parse_cisco_etherchannel,
    ),
]


def list_parsers(include_disabled: bool = True) -> list[dict[str, Any]]:
    result = []
    for spec in PARSER_SPECS:
        if not include_disabled and not spec.enabled:
            continue
        item = asdict(spec)
        item.pop("parser_func", None)
        item.pop("can_parse_func", None)
        result.append(item)
    return result


def select_parser(command: str, platform: str = "") -> ParserSpec | None:
    for spec in PARSER_SPECS:
        if not spec.enabled:
            continue
        if spec.can_parse_func(command, platform):
            return spec
    return None


def parse_command_output(command: str, output: str, platform: str = "") -> dict[str, Any]:
    spec = select_parser(command=command, platform=platform)

    if spec is None:
        return {
            "status": "skipped",
            "parser": "",
            "reason": "no_parser_matched",
            "command": command,
            "platform": platform or "",
            "parsed": {},
        }

    try:
        parsed = spec.parser_func(command, output, platform)
        return {
            "status": "parsed" if parsed.get("matched") else "unmatched",
            "parser": spec.parser_name,
            "reason": "",
            "command": command,
            "platform": platform or "",
            "parsed": parsed,
        }
    except Exception as exc:
        return {
            "status": "error",
            "parser": spec.parser_name,
            "reason": str(exc),
            "command": command,
            "platform": platform or "",
            "parsed": {},
        }


def enrich_command_results_with_parsed(execution_data: dict[str, Any], force: bool = True) -> dict[str, Any]:
    data = dict(execution_data or {})
    command_results = data.get("command_results")

    if not isinstance(command_results, list):
        return data

    enriched = []
    for item in command_results:
        if not isinstance(item, dict):
            enriched.append(item)
            continue

        new_item = dict(item)
        command = str(new_item.get("command", ""))
        output = str(new_item.get("output", ""))
        platform = str(new_item.get("platform") or data.get("platform") or "")

        if force or "parsed" not in new_item:
            parsed_result = parse_command_output(command=command, output=output, platform=platform)
            new_item["parsed"] = parsed_result

        enriched.append(new_item)

    data["command_results"] = enriched
    return data


def validate_parser_registry() -> dict[str, Any]:
    violations: list[str] = []
    warnings: list[str] = []
    seen: set[str] = set()

    for spec in PARSER_SPECS:
        if not spec.parser_name:
            violations.append("parser_name is empty")

        if spec.parser_name in seen:
            violations.append(f"duplicate parser_name: {spec.parser_name}")
        seen.add(spec.parser_name)

        if not spec.platforms:
            warnings.append(f"{spec.parser_name}: platforms is empty")

        if not spec.command_keywords:
            warnings.append(f"{spec.parser_name}: command_keywords is empty")

        if not callable(spec.parser_func):
            violations.append(f"{spec.parser_name}: parser_func is not callable")

        if not callable(spec.can_parse_func):
            violations.append(f"{spec.parser_name}: can_parse_func is not callable")

    return {
        "verdict": "fail" if violations else "pass",
        "parser_count": len(PARSER_SPECS),
        "enabled_parser_count": len([x for x in PARSER_SPECS if x.enabled]),
        "violations": violations,
        "warnings": warnings,
        "parsers": list_parsers(include_disabled=True),
    }
