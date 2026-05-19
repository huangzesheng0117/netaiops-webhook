from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from netaiops.skill_compliance_validator import load_skill_contract
from netaiops.tool_registry import list_tools


ADAPTIVE_STAGE = "v6.5"
ADAPTIVE_MODE = "skill_constrained_dry_run"

DEFAULT_LIMITS = {
    "max_extra_rounds": 1,
    "max_extra_commands": 3,
    "adaptive_execution_enabled": False,
    "readonly_only": True,
}


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _read_text(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8")


def _collect_yaml_list(text: str, section_name: str) -> list[str]:
    result: list[str] = []
    in_section = False

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        if re.match(r"^[A-Za-z0-9_]+:\s*$", stripped):
            in_section = stripped == f"{section_name}:"
            continue

        if in_section:
            m = re.match(r"^\s*-\s+[\"']?(.*?)[\"']?\s*$", line)
            if m:
                value = m.group(1).strip().strip('"').strip("'")
                if value:
                    result.append(value)
                continue

            if not line.startswith(" "):
                in_section = False

    return result


def _parse_platform_commands(text: str) -> dict[str, dict[str, dict[str, Any]]]:
    result: dict[str, dict[str, dict[str, Any]]] = {}

    in_platform_commands = False
    current_platform = ""
    current_capability = ""

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        if stripped == "platform_commands:":
            in_platform_commands = True
            continue

        if not in_platform_commands:
            continue

        if stripped and not line.startswith(" "):
            break

        m_platform = re.match(r"^\s{2}([A-Za-z0-9_]+):\s*$", line)
        if m_platform:
            current_platform = m_platform.group(1)
            result.setdefault(current_platform, {})
            current_capability = ""
            continue

        m_cap = re.match(r"^\s{4}([A-Za-z0-9_]+):\s*$", line)
        if m_cap and current_platform:
            current_capability = m_cap.group(1)
            result[current_platform].setdefault(current_capability, {})
            continue

        if current_platform and current_capability:
            m_template = re.match(r"^\s{6}template:\s*[\"'](.+?)[\"']\s*$", line)
            if m_template:
                result[current_platform][current_capability]["template"] = m_template.group(1).strip()
                continue

            m_parser = re.match(r"^\s{6}parser:\s*[\"']?([A-Za-z0-9_]+)[\"']?\s*$", line)
            if m_parser:
                result[current_platform][current_capability]["parser"] = m_parser.group(1).strip()
                continue

            m_readonly = re.match(r"^\s{6}readonly:\s*(true|false)\s*$", line, re.IGNORECASE)
            if m_readonly:
                result[current_platform][current_capability]["readonly"] = m_readonly.group(1).lower() == "true"
                continue

    return result


def _template_to_regex(template: str) -> re.Pattern:
    escaped = re.escape(template.strip())
    escaped = escaped.replace(re.escape("{interface}"), r"\S+")
    return re.compile(r"^" + escaped + r"$", re.IGNORECASE)


def command_matches_template(command: str, template: str) -> bool:
    return bool(_template_to_regex(template).match(_safe_text(command)))


def command_matches_any_template(command: str, templates: list[str]) -> bool:
    return any(command_matches_template(command, template) for template in templates)


def normalize_cli_command(command: str) -> str:
    text = _safe_text(command).lower()
    replacements = [
        ("tengigabitethernet", "te"),
        ("gigabitethernet", "gi"),
        ("fastethernet", "fa"),
        ("port-channel", "po"),
        ("portchannel", "po"),
    ]

    for old, new in replacements:
        text = text.replace(old, new)

    return re.sub(r"\s+", " ", text).strip()


def command_has_forbidden_pattern(command: str, forbidden_patterns: list[str]) -> str:
    cmd = _safe_text(command).lower()

    for pattern in forbidden_patterns:
        p = _safe_text(pattern).lower()
        if p and p in cmd:
            return pattern

    return ""


def load_adaptive_skill_constraints(skill_name: str, base_dir: str | Path = ".") -> dict[str, Any]:
    contract = load_skill_contract(skill_name, base_dir)
    skill_path = Path(contract["path"])
    commands_file = skill_path / "commands.yaml"
    commands_text = _read_text(commands_file)

    tool_by_name = {
        item.get("tool_name"): item
        for item in list_tools(include_disabled=True)
        if item.get("tool_name")
    }

    enabled_tool_names = {
        item.get("tool_name")
        for item in list_tools(include_disabled=False)
        if item.get("tool_name")
    }

    constraints = {
        "stage": ADAPTIVE_STAGE,
        "mode": ADAPTIVE_MODE,
        "skill_name": skill_name,
        "family": contract.get("family"),
        "risk_level": contract.get("risk_level"),
        "allowed_tools": contract.get("allowed_tools", []),
        "allowed_capabilities": contract.get("allowed_capabilities", []),
        "command_templates": contract.get("command_templates", []),
        "parsers": contract.get("parsers", []),
        "required_facts": contract.get("required_facts", []),
        "preferred_facts": contract.get("preferred_facts", []),
        "forbidden_patterns": _collect_yaml_list(commands_text, "forbidden_patterns"),
        "platform_commands": _parse_platform_commands(commands_text),
        "limits": dict(DEFAULT_LIMITS),
        "tool_by_name": tool_by_name,
        "enabled_tool_names": sorted(enabled_tool_names),
    }

    return constraints


def validate_adaptive_candidate(candidate: dict[str, Any], constraints: dict[str, Any]) -> dict[str, Any]:
    violations: list[str] = []
    warnings: list[str] = []

    tool_name = _safe_text(candidate.get("tool_name"))
    capability = _safe_text(candidate.get("capability"))
    command = _safe_text(candidate.get("command"))
    parser_name = _safe_text(candidate.get("parser"))
    readonly = candidate.get("readonly", True)

    if not tool_name:
        violations.append("candidate.tool_name is missing")
    elif tool_name not in constraints.get("allowed_tools", []):
        violations.append(f"tool is not allowed by skill: {tool_name}")

    tool_spec = constraints.get("tool_by_name", {}).get(tool_name)
    if tool_name and not tool_spec:
        violations.append(f"tool is not registered: {tool_name}")
    elif tool_spec:
        if tool_spec.get("risk_level") != "readonly":
            violations.append(f"tool risk_level is not readonly: {tool_name}")
        if tool_name not in set(constraints.get("enabled_tool_names", [])):
            violations.append(f"tool is not enabled: {tool_name}")

    if capability not in constraints.get("allowed_capabilities", []):
        violations.append(f"capability is not allowed by skill: {capability}")

    if readonly is not True:
        violations.append("candidate.readonly must be true")

    if not command:
        violations.append("candidate.command is missing")
    elif not command_matches_any_template(command, constraints.get("command_templates", [])):
        violations.append(f"command does not match skill command templates: {command}")

    forbidden = command_has_forbidden_pattern(command, constraints.get("forbidden_patterns", []))
    if forbidden:
        violations.append(f"command contains forbidden pattern: {forbidden}")

    if parser_name and parser_name not in constraints.get("parsers", []):
        violations.append(f"parser is not declared by skill: {parser_name}")

    return {
        "verdict": "fail" if violations else "pass",
        "violations": violations,
        "warnings": warnings,
    }


def validate_adaptive_plan(plan: dict[str, Any], constraints: dict[str, Any]) -> dict[str, Any]:
    violations: list[str] = []
    warnings: list[str] = []

    limits = constraints.get("limits", {})
    candidates = plan.get("candidates") if isinstance(plan.get("candidates"), list) else []

    if plan.get("stage") != ADAPTIVE_STAGE:
        violations.append("plan.stage must be v6.5")

    if plan.get("mode") != ADAPTIVE_MODE:
        violations.append("plan.mode must be skill_constrained_dry_run")

    if plan.get("dispatch_enabled") is not False:
        violations.append("dispatch_enabled must be false in v6.5 batch1")

    if plan.get("extra_round") not in {0, 1}:
        violations.append("extra_round must be 0 or 1")

    if plan.get("extra_round", 0) > limits.get("max_extra_rounds", 1):
        violations.append("extra_round exceeds max_extra_rounds")

    if len(candidates) > limits.get("max_extra_commands", 3):
        violations.append("candidate count exceeds max_extra_commands")

    for index, candidate in enumerate(candidates):
        result = validate_adaptive_candidate(candidate, constraints)
        for item in result.get("violations", []):
            violations.append(f"candidate[{index}]: {item}")
        for item in result.get("warnings", []):
            warnings.append(f"candidate[{index}]: {item}")

    return {
        "verdict": "fail" if violations else "pass",
        "violations": violations,
        "warnings": warnings,
        "candidate_count": len(candidates),
        "limits": limits,
    }
