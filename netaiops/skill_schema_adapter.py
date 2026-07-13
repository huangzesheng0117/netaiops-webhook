from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping

import yaml

SUPPORTED_SKILL_STAGES = frozenset({"v6.3", "v8", "v9"})
LEGACY_STAGE = "v6.3"


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _as_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        text = _safe_text(item)
        if text and text not in result:
            result.append(text)
    return result


def load_yaml_mapping(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    payload = yaml.safe_load(source.read_text(encoding="utf-8"))
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise ValueError(f"YAML root must be an object: {source}")
    return dict(payload)


def schema_generation(stage: str) -> str:
    return "legacy" if _safe_text(stage) == LEGACY_STAGE else "current"


def normalize_template(template: str) -> str:
    return _safe_text(template).replace("{interface_each}", "{interface}")


def _infer_parser(template: str, platform: str) -> str:
    normalized = normalize_template(template).lower()
    platform_name = _safe_text(platform).lower()
    ios_platforms = {"cisco_iosxe", "cisco_ios", "iosxe", "ios"}
    if platform_name not in ios_platforms:
        return ""
    if normalized in {"show etherchannel summary", "show port-channel summary"}:
        return "cisco_etherchannel_summary"
    if "counters errors" in normalized and normalized.startswith("show interfaces"):
        return "cisco_show_interfaces_counters_errors"
    if re.fullmatch(r"show interfaces \{interface\}", normalized):
        return "cisco_show_interfaces"
    return ""


def _semantic_capability(template: str, bucket: str = "") -> str:
    normalized = normalize_template(template).lower()
    if normalized in {"show etherchannel summary", "show port-channel summary"}:
        return "show_interface_aggregation"
    if "counters errors" in normalized and normalized.startswith(("show interface", "show interfaces")):
        return "show_interface_error_counters"
    if re.fullmatch(r"show interfaces? \{interface\}", normalized):
        return "show_interface_detail"
    if bucket == "per_interface" and re.fullmatch(r"show interfaces? \{interface\} counters", normalized):
        return "show_interface_counters"
    return ""


def _entry_priority(entry: Mapping[str, Any]) -> tuple[int, str]:
    template = _safe_text(entry.get("template")).lower()
    capability = _safe_text(entry.get("capability"))
    if capability == "show_interface_error_counters":
        return (0 if "counters errors" in template else 10, template)
    if capability == "show_interface_detail":
        return (0, template)
    if capability == "show_interface_aggregation":
        return (0, template)
    return (50, template)


def normalize_commands_document(document: Mapping[str, Any]) -> dict[str, Any]:
    allowed_tools = _as_string_list(document.get("allowed_tools"))
    explicit_capabilities = _as_string_list(document.get("allowed_capabilities"))
    forbidden_patterns = _as_string_list(document.get("forbidden_patterns"))
    readonly_only = document.get("readonly_only") is True
    raw_platforms = document.get("platform_commands")
    if not isinstance(raw_platforms, dict):
        raw_platforms = {}

    entries: list[dict[str, Any]] = []
    shapes: set[str] = set()

    for platform, platform_spec in raw_platforms.items():
        platform_name = _safe_text(platform)
        if not platform_name or not isinstance(platform_spec, dict):
            continue

        is_bucket_schema = any(
            isinstance(platform_spec.get(name), list)
            for name in ("global", "per_interface")
        )
        if is_bucket_schema:
            shapes.add("current_command_buckets")
            for bucket in ("global", "per_interface"):
                commands = platform_spec.get(bucket)
                if not isinstance(commands, list):
                    continue
                for index, item in enumerate(commands):
                    template = _safe_text(item)
                    if not template:
                        continue
                    capability = _semantic_capability(template, bucket)
                    entry = {
                        "platform": platform_name,
                        "capability": capability,
                        "semantic_capability": capability,
                        "bucket": bucket,
                        "template": normalize_template(template),
                        "source_template": template,
                        "parser": _infer_parser(template, platform_name),
                        "readonly": True,
                        "source_schema": "current_command_buckets",
                    }
                    entries.append(entry)
            continue

        shapes.add("capability_map")
        for capability, raw_spec in platform_spec.items():
            capability_name = _safe_text(capability)
            if not capability_name or not isinstance(raw_spec, dict):
                continue
            template = _safe_text(raw_spec.get("template"))
            if not template:
                continue
            parser = _safe_text(raw_spec.get("parser")) or _infer_parser(
                template,
                platform_name,
            )
            entries.append(
                {
                    "platform": platform_name,
                    "capability": capability_name,
                    "semantic_capability": _semantic_capability(template),
                    "bucket": "capability",
                    "template": normalize_template(template),
                    "source_template": template,
                    "parser": parser,
                    "readonly": raw_spec.get("readonly", True) is True,
                    "source_schema": "capability_map",
                }
            )

    derived_capabilities: list[str] = []
    for entry in entries:
        for value in (entry.get("capability"), entry.get("semantic_capability")):
            text = _safe_text(value)
            if text and text not in derived_capabilities:
                derived_capabilities.append(text)

    allowed_capabilities = list(explicit_capabilities)
    for capability in derived_capabilities:
        if capability not in allowed_capabilities:
            allowed_capabilities.append(capability)

    templates: list[str] = []
    parsers: list[str] = []
    platforms: list[str] = []
    for entry in entries:
        template = _safe_text(entry.get("template"))
        parser = _safe_text(entry.get("parser"))
        platform = _safe_text(entry.get("platform"))
        if template and template not in templates:
            templates.append(template)
        if parser and parser not in parsers:
            parsers.append(parser)
        if platform and platform not in platforms:
            platforms.append(platform)

    adaptive_platform_commands: dict[str, dict[str, dict[str, Any]]] = {}
    semantic_names = {
        "show_interface_detail",
        "show_interface_error_counters",
        "show_interface_aggregation",
    }
    for platform in platforms:
        candidates = [entry for entry in entries if entry["platform"] == platform]
        for capability in semantic_names:
            matches = [
                entry
                for entry in candidates
                if entry.get("capability") == capability
                or entry.get("semantic_capability") == capability
            ]
            if not matches:
                continue
            chosen = sorted(matches, key=_entry_priority)[0]
            adaptive_platform_commands.setdefault(platform, {})[capability] = {
                "template": chosen["template"],
                "source_template": chosen["source_template"],
                "parser": chosen["parser"],
                "readonly": chosen["readonly"],
                "bucket": chosen["bucket"],
                "source_schema": chosen["source_schema"],
            }

    return {
        "schema_shapes": sorted(shapes),
        "allowed_tools": allowed_tools,
        "allowed_capabilities": allowed_capabilities,
        "explicit_allowed_capabilities": explicit_capabilities,
        "derived_capabilities": derived_capabilities,
        "forbidden_patterns": forbidden_patterns,
        "readonly_only": readonly_only,
        "platforms": platforms,
        "entries": entries,
        "command_templates": templates,
        "parsers": parsers,
        "adaptive_platform_commands": adaptive_platform_commands,
    }


def normalize_evidence_document(document: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "required_facts": _as_string_list(document.get("required_facts")),
        "preferred_facts": _as_string_list(document.get("preferred_facts")),
        "manual_review_conditions": _as_string_list(
            document.get("manual_review_conditions")
        ),
        "has_status_rules": isinstance(document.get("status_rules"), dict),
    }


def output_schema_facts(schema: Mapping[str, Any]) -> dict[str, Any]:
    facts = schema.get("facts")
    if isinstance(facts, dict):
        return dict(facts)
    if schema.get("type") == "object" and isinstance(schema.get("properties"), dict):
        return dict(schema["properties"])
    return {}
