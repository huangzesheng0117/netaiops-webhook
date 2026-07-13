from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from netaiops.parser_registry import list_parsers
from netaiops.skill_registry import load_skill, validate_skill_package
from netaiops.skill_schema_adapter import (
    load_yaml_mapping,
    normalize_commands_document,
)
from netaiops.tool_registry import list_tools


@lru_cache(maxsize=32)
def _known_family_names(base_dir: str | Path = ".") -> set[str]:
    names: set[str] = set()

    try:
        from netaiops.skill_registry import list_skills

        names.update(
            str(item.get("family", "")).strip()
            for item in list_skills(base_dir)
            if str(item.get("family", "")).strip()
        )
    except Exception:
        pass

    candidates = [
        Path(base_dir) / "netaiops" / "family_registry.py",
        Path(base_dir) / "netaiops" / "classifier.py",
    ]
    for path in candidates:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for match in re.finditer(
            r"interface_or_link_utilization_high|interface_down_or_flap|"
            r"bgp_neighbor_down|f5_pool_member_down|optical_power_alarm|"
            r"aci_endpoint_missing",
            text,
        ):
            names.add(match.group(0))

    return names


@lru_cache(maxsize=32)
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
        "show_interface_counters",
        "prometheus_interface_window",
        "parse_cli_output",
        "show_bgp_summary",
        "show_bgp_neighbor_detail",
        "show_interface_transceiver",
    ]

    for path in candidates:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for name in known_patterns:
            if name in text:
                names.add(name)

    names.update(known_patterns)

    # The current v8/v9 Skill schema may derive semantic capabilities from
    # command buckets instead of declaring the legacy allowed_capabilities
    # list.  Include all normalized capability names from installed Skills so
    # a valid current contract is not reported as unknown merely because it
    # is absent from the historical capability registry modules.
    try:
        from netaiops.skill_registry import list_skills

        for skill in list_skills(base_dir):
            commands_path = Path(skill["path"]) / "commands.yaml"
            if not commands_path.is_file():
                continue
            normalized = normalize_commands_document(
                load_yaml_mapping(commands_path)
            )
            names.update(
                str(item).strip()
                for item in normalized.get("allowed_capabilities", [])
                if str(item).strip()
            )
    except Exception:
        pass

    return names


def load_skill_binding_graph(
    skill_name: str,
    base_dir: str | Path = ".",
) -> dict[str, Any]:
    skill = load_skill(skill_name, base_dir)
    skill_path = Path(skill["path"])
    commands_file = skill_path / "commands.yaml"
    commands = load_yaml_mapping(commands_file) if commands_file.exists() else {}
    normalized = normalize_commands_document(commands)

    tool_names = {
        item.get("tool_name")
        for item in list_tools(include_disabled=True)
        if item.get("tool_name")
    }
    enabled_tool_names = {
        item.get("tool_name")
        for item in list_tools(include_disabled=False)
        if item.get("tool_name")
    }
    parser_registry_names = {
        item.get("parser_name")
        for item in list_parsers(include_disabled=True)
        if item.get("parser_name")
    }
    known_families = _known_family_names(base_dir)
    known_capabilities = _known_capability_names(base_dir)

    allowed_tools = normalized.get("allowed_tools", [])
    allowed_capabilities = normalized.get("allowed_capabilities", [])
    parser_names = normalized.get("parsers", [])

    return {
        "skill_name": skill.get("name"),
        "skill_version": skill.get("version"),
        "family": skill.get("family"),
        "risk_level": skill.get("risk_level"),
        "stage": skill.get("stage"),
        "schema_generation": skill.get("schema_generation"),
        "path": skill.get("path"),
        "allowed_tools": allowed_tools,
        "allowed_capabilities": allowed_capabilities,
        "explicit_allowed_capabilities": normalized.get(
            "explicit_allowed_capabilities",
            [],
        ),
        "derived_capabilities": normalized.get("derived_capabilities", []),
        "parsers": parser_names,
        "platforms": normalized.get("platforms", []),
        "command_templates": normalized.get("command_templates", []),
        "command_entries": normalized.get("entries", []),
        "command_schema_shapes": normalized.get("schema_shapes", []),
        "known_families": sorted(known_families),
        "known_capabilities": sorted(known_capabilities),
        "registered_tools": sorted(tool_names),
        "enabled_tools": sorted(enabled_tool_names),
        "registered_parsers": sorted(parser_registry_names),
        "missing_tools": sorted(set(allowed_tools) - tool_names),
        "disabled_tools": sorted(set(allowed_tools) - enabled_tool_names),
        "missing_parsers": sorted(set(parser_names) - parser_registry_names),
        "unknown_capabilities": sorted(
            set(allowed_capabilities) - known_capabilities
        ),
        "family_known": (
            skill.get("family") in known_families
            if known_families
            else None
        ),
    }


def validate_skill_binding(
    skill_name: str,
    base_dir: str | Path = ".",
) -> dict[str, Any]:
    violations: list[str] = []
    warnings: list[str] = []

    package_result = validate_skill_package(skill_name, base_dir)
    if package_result.get("verdict") != "pass":
        for item in package_result.get("violations", []):
            violations.append(f"skill_package: {item}")

    graph = load_skill_binding_graph(skill_name, base_dir)

    if graph.get("risk_level") != "readonly":
        violations.append("skill risk_level must be readonly")
    if not graph.get("stage"):
        violations.append("skill stage is missing")
    if not graph.get("family"):
        violations.append("skill family is missing")
    if graph.get("family_known") is False:
        warnings.append(
            f"family not found in current registry scan: {graph.get('family')}"
        )
    if not graph.get("allowed_tools"):
        violations.append("allowed_tools is empty")
    if not graph.get("allowed_capabilities"):
        violations.append(
            "allowed_capabilities is empty after schema normalization"
        )
    if not graph.get("platforms"):
        violations.append("platform_commands is empty")
    if not graph.get("command_templates"):
        violations.append("command_templates is empty after schema normalization")
    if not graph.get("parsers"):
        warnings.append("no parser is declared or inferred in commands.yaml")

    for item in graph.get("missing_tools", []):
        violations.append(f"allowed tool not registered: {item}")
    for item in graph.get("disabled_tools", []):
        warnings.append(f"allowed tool exists but disabled: {item}")
    for item in graph.get("missing_parsers", []):
        violations.append(f"declared or inferred parser not registered: {item}")
    for item in graph.get("unknown_capabilities", []):
        warnings.append(
            f"capability not found in current registry scan: {item}"
        )

    return {
        "skill_name": skill_name,
        "verdict": "fail" if violations else "pass",
        "violations": violations,
        "warnings": warnings,
        "graph": graph,
    }


def validate_all_skill_bindings(
    base_dir: str | Path = ".",
) -> dict[str, Any]:
    from netaiops.skill_registry import list_skills

    results = [
        validate_skill_binding(skill.get("name"), base_dir)
        for skill in list_skills(base_dir)
    ]

    violations: list[str] = []
    warnings: list[str] = []
    for item in results:
        for violation in item.get("violations", []):
            violations.append(f"{item.get('skill_name')}: {violation}")
        for warning in item.get("warnings", []):
            warnings.append(f"{item.get('skill_name')}: {warning}")

    return {
        "verdict": "fail" if violations else "pass",
        "skill_count": len(results),
        "violations": violations,
        "warnings": warnings,
        "skills": results,
    }
