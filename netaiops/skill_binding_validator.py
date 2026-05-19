from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from netaiops.skill_registry import load_skill, validate_skill_package
from netaiops.tool_registry import list_tools
from netaiops.parser_registry import list_parsers


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
                value = m.group(1).strip()
                if value:
                    result.append(value)
                continue

            if not line.startswith(" "):
                in_section = False

    return result


def _collect_parser_names(text: str) -> list[str]:
    result = []
    for m in re.finditer(r"^\s*parser:\s*[\"']?([A-Za-z0-9_]+)[\"']?\s*$", text, re.MULTILINE):
        result.append(m.group(1))
    return sorted(set(result))


def _collect_platforms(text: str) -> list[str]:
    platforms = []
    in_section = False

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        if stripped == "platform_commands:":
            in_section = True
            continue

        if in_section:
            m = re.match(r"^\s{2}([A-Za-z0-9_]+):\s*$", line)
            if m:
                platforms.append(m.group(1))
                continue

            if stripped and not line.startswith(" "):
                break

    return sorted(set(platforms))


def _known_family_names(base_dir: str | Path = ".") -> set[str]:
    candidates = [
        Path(base_dir) / "netaiops" / "family_registry.py",
        Path(base_dir) / "netaiops" / "classifier.py",
    ]

    names: set[str] = set()

    for p in candidates:
        if not p.exists():
            continue

        text = p.read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(r"interface_or_link_utilization_high|interface_down_or_flap|bgp_neighbor_down|f5_pool_member_down|optical_power_alarm|aci_endpoint_missing", text):
            names.add(m.group(0))

    return names


def _known_capability_names(base_dir: str | Path = ".") -> set[str]:
    candidates = [
        Path(base_dir) / "netaiops" / "capability_registry.py",
        Path(base_dir) / "netaiops" / "capability_planner.py",
        Path(base_dir) / "netaiops" / "platform_command_matrix.py",
    ]

    names: set[str] = set()

    known_patterns = [
        "show_interface_detail",
        "show_interface_error_counters",
        "show_interface_aggregation",
        "prometheus_interface_window",
        "parse_cli_output",
        "show_bgp_summary",
        "show_bgp_neighbor_detail",
        "show_interface_transceiver",
    ]

    for p in candidates:
        if not p.exists():
            continue

        text = p.read_text(encoding="utf-8", errors="ignore")
        for name in known_patterns:
            if name in text:
                names.add(name)

    return names


def load_skill_binding_graph(skill_name: str, base_dir: str | Path = ".") -> dict[str, Any]:
    skill = load_skill(skill_name, base_dir)
    skill_path = Path(skill["path"])
    commands_file = skill_path / "commands.yaml"

    commands_text = _read_text(commands_file) if commands_file.exists() else ""

    allowed_tools = _collect_yaml_list(commands_text, "allowed_tools")
    allowed_capabilities = _collect_yaml_list(commands_text, "allowed_capabilities")
    parser_names = _collect_parser_names(commands_text)
    platforms = _collect_platforms(commands_text)

    tool_names = {item.get("tool_name") for item in list_tools(include_disabled=True)}
    enabled_tool_names = {item.get("tool_name") for item in list_tools(include_disabled=False)}
    parser_registry_names = {item.get("parser_name") for item in list_parsers(include_disabled=True)}
    known_families = _known_family_names(base_dir)
    known_capabilities = _known_capability_names(base_dir)

    graph = {
        "skill_name": skill.get("name"),
        "skill_version": skill.get("version"),
        "family": skill.get("family"),
        "risk_level": skill.get("risk_level"),
        "stage": skill.get("stage"),
        "path": skill.get("path"),
        "allowed_tools": allowed_tools,
        "allowed_capabilities": allowed_capabilities,
        "parsers": parser_names,
        "platforms": platforms,
        "known_families": sorted(known_families),
        "known_capabilities": sorted(known_capabilities),
        "registered_tools": sorted([x for x in tool_names if x]),
        "enabled_tools": sorted([x for x in enabled_tool_names if x]),
        "registered_parsers": sorted([x for x in parser_registry_names if x]),
        "missing_tools": sorted(set(allowed_tools) - tool_names),
        "disabled_tools": sorted(set(allowed_tools) - enabled_tool_names),
        "missing_parsers": sorted(set(parser_names) - parser_registry_names),
        "unknown_capabilities": sorted(set(allowed_capabilities) - known_capabilities),
        "family_known": skill.get("family") in known_families if known_families else None,
    }

    return graph


def validate_skill_binding(skill_name: str, base_dir: str | Path = ".") -> dict[str, Any]:
    violations: list[str] = []
    warnings: list[str] = []

    package_result = validate_skill_package(skill_name, base_dir)
    if package_result.get("verdict") != "pass":
        for item in package_result.get("violations", []):
            violations.append(f"skill_package: {item}")

    graph = load_skill_binding_graph(skill_name, base_dir)

    if graph.get("risk_level") != "readonly":
        violations.append("skill risk_level must be readonly")

    if graph.get("stage") != "v6.3":
        violations.append("skill stage must be v6.3")

    if not graph.get("family"):
        violations.append("skill family is missing")

    if graph.get("family_known") is False:
        warnings.append(f"family not found in family registry text scan: {graph.get('family')}")

    if not graph.get("allowed_tools"):
        violations.append("allowed_tools is empty")

    if not graph.get("allowed_capabilities"):
        violations.append("allowed_capabilities is empty")

    if not graph.get("parsers"):
        warnings.append("no parser is declared in commands.yaml")

    for item in graph.get("missing_tools", []):
        violations.append(f"allowed tool not registered: {item}")

    for item in graph.get("disabled_tools", []):
        warnings.append(f"allowed tool exists but disabled: {item}")

    for item in graph.get("missing_parsers", []):
        violations.append(f"declared parser not registered: {item}")

    for item in graph.get("unknown_capabilities", []):
        warnings.append(f"capability not found in current registry text scan: {item}")

    return {
        "skill_name": skill_name,
        "verdict": "fail" if violations else "pass",
        "violations": violations,
        "warnings": warnings,
        "graph": graph,
    }


def validate_all_skill_bindings(base_dir: str | Path = ".") -> dict[str, Any]:
    from netaiops.skill_registry import list_skills

    skills = list_skills(base_dir)
    results = []

    for skill in skills:
        results.append(validate_skill_binding(skill.get("name"), base_dir))

    violations = []
    warnings = []

    for item in results:
        for v in item.get("violations", []):
            violations.append(f"{item.get('skill_name')}: {v}")
        for w in item.get("warnings", []):
            warnings.append(f"{item.get('skill_name')}: {w}")

    return {
        "verdict": "fail" if violations else "pass",
        "skill_count": len(results),
        "violations": violations,
        "warnings": warnings,
        "bindings": results,
    }
