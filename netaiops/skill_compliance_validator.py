from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from netaiops.investigation_state import (
    build_and_persist_investigation_session,
    find_request_files,
    safe_read_json,
    unwrap_execution,
    unwrap_review,
)
from netaiops.skill_registry import load_skill
from netaiops.skill_schema_adapter import (
    load_yaml_mapping,
    normalize_commands_document,
    normalize_evidence_document,
)


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _read_text(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8")


def _template_to_regex(template: str):
    import re

    escaped = re.escape(template.strip())
    escaped = escaped.replace(re.escape("{interface}"), r"\S+")
    escaped = escaped.replace(re.escape("{interface_each}"), r"\S+")
    escaped = re.sub(r"\\\{[A-Za-z0-9_]+\\\}", r"\\S+", escaped)
    return re.compile(r"^" + escaped + r"$", re.IGNORECASE)


def _command_matches_templates(command: str, templates: list[str]) -> bool:
    command = _safe_text(command)
    if not command:
        return False

    for template in templates:
        if _template_to_regex(template).match(command):
            return True

    return False


def _fact_present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str) and not value.strip():
        return False
    return True


def load_skill_contract(skill_name: str, base_dir: str | Path = ".") -> dict[str, Any]:
    skill = load_skill(skill_name, base_dir)
    skill_path = Path(skill["path"])

    commands = load_yaml_mapping(skill_path / "commands.yaml")
    evidence = load_yaml_mapping(skill_path / "evidence_rules.yaml")
    commands_normalized = normalize_commands_document(commands)
    evidence_normalized = normalize_evidence_document(evidence)
    output_schema = json.loads(
        (skill_path / "output_schema.json").read_text(encoding="utf-8")
    )

    notification = (
        output_schema.get("notification")
        if isinstance(output_schema.get("notification"), dict)
        else {}
    )
    required_lines = notification.get("required_lines")
    if not isinstance(required_lines, list):
        required_lines = notification.get("required_sections")
    if not isinstance(required_lines, list):
        required_lines = []

    return {
        "skill_name": skill.get("name"),
        "skill_version": skill.get("version"),
        "family": skill.get("family"),
        "risk_level": skill.get("risk_level"),
        "stage": skill.get("stage"),
        "schema_generation": skill.get("schema_generation"),
        "path": skill.get("path"),
        "allowed_tools": commands_normalized.get("allowed_tools", []),
        "allowed_capabilities": commands_normalized.get(
            "allowed_capabilities",
            [],
        ),
        "explicit_allowed_capabilities": commands_normalized.get(
            "explicit_allowed_capabilities",
            [],
        ),
        "derived_capabilities": commands_normalized.get(
            "derived_capabilities",
            [],
        ),
        "command_templates": commands_normalized.get(
            "command_templates",
            [],
        ),
        "command_entries": commands_normalized.get("entries", []),
        "platform_commands": commands_normalized.get(
            "adaptive_platform_commands",
            {},
        ),
        "parsers": commands_normalized.get("parsers", []),
        "forbidden_patterns": commands_normalized.get(
            "forbidden_patterns",
            [],
        ),
        "required_facts": evidence_normalized.get("required_facts", []),
        "preferred_facts": evidence_normalized.get("preferred_facts", []),
        "manual_review_conditions": evidence_normalized.get(
            "manual_review_conditions",
            [],
        ),
        "notification_required_lines": [
            str(item) for item in required_lines if str(item).strip()
        ],
        "output_schema": output_schema,
    }


def validate_execution_against_skill(execution_data: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any]:
    violations: list[str] = []
    warnings: list[str] = []

    command_results = execution_data.get("command_results")
    if not isinstance(command_results, list):
        command_results = []

    templates = contract.get("command_templates") or []
    allowed_parsers = set(contract.get("parsers") or [])

    parsed_count = 0
    skipped_count = 0
    error_count = 0
    unmatched_count = 0
    checked_commands = []

    if not command_results:
        violations.append("execution.command_results is empty")

    for item in command_results:
        if not isinstance(item, dict):
            continue

        command = _safe_text(item.get("command"))
        checked_commands.append(command)

        if not _command_matches_templates(command, templates):
            violations.append(f"command not allowed by skill templates: {command}")

        parsed_result = item.get("parsed") if isinstance(item.get("parsed"), dict) else {}
        status = _safe_text(parsed_result.get("status"))
        parser_name = _safe_text(parsed_result.get("parser"))

        if status == "parsed":
            parsed_count += 1
        elif status == "skipped":
            skipped_count += 1
            violations.append(f"command parser skipped: {command}")
        elif status == "error":
            error_count += 1
            violations.append(f"command parser error: {command}")
        elif status == "unmatched":
            unmatched_count += 1
            violations.append(f"command parser unmatched: {command}")
        else:
            violations.append(f"command parsed status missing: {command}")

        if parser_name and parser_name not in allowed_parsers:
            violations.append(f"parser not declared by skill: {parser_name} for command {command}")

    return {
        "verdict": "fail" if violations else "pass",
        "violations": violations,
        "warnings": warnings,
        "summary": {
            "command_count": len(command_results),
            "parsed_count": parsed_count,
            "skipped_count": skipped_count,
            "error_count": error_count,
            "unmatched_count": unmatched_count,
            "checked_commands": checked_commands,
        },
    }


def _review_notification_text(review_data: dict[str, Any]) -> str:
    chunks = []

    es = review_data.get("evidence_summary") if isinstance(review_data.get("evidence_summary"), dict) else {}

    for key in ["notify_lines", "key_findings"]:
        value = es.get(key)
        if isinstance(value, list):
            chunks.extend([str(x) for x in value])
        elif value:
            chunks.append(str(value))

    for key in ["conclusion", "summary", "analysis"]:
        value = review_data.get(key)
        if value:
            chunks.append(str(value))

    notify_result = review_data.get("notify_result") if isinstance(review_data.get("notify_result"), dict) else {}
    request_data = notify_result.get("request_data") if isinstance(notify_result.get("request_data"), dict) else {}
    for key in ["text", "detail", "content"]:
        value = request_data.get(key)
        if value:
            chunks.append(str(value))

    return "\n".join(chunks)


def validate_review_against_skill(
    review_data: dict[str, Any],
    contract: dict[str, Any],
    strict_notification: bool = False,
) -> dict[str, Any]:
    violations: list[str] = []
    warnings: list[str] = []

    es = review_data.get("evidence_summary") if isinstance(review_data.get("evidence_summary"), dict) else {}
    facts = es.get("facts") if isinstance(es.get("facts"), dict) else {}

    required_facts = contract.get("required_facts") or []
    for fact_name in required_facts:
        if not _fact_present(facts.get(fact_name)):
            violations.append(f"required fact missing: {fact_name}")

    if facts.get("parsed_facts_enabled") is not True:
        violations.append("parsed_facts_enabled is not true")

    if facts.get("facts_source_preference") != "parsed_first_raw_fallback":
        violations.append("facts_source_preference is not parsed_first_raw_fallback")

    expected_parsers = set(contract.get("parsers") or [])
    actual_sources = set(facts.get("parsed_fact_sources") or [])

    missing_sources = sorted(expected_parsers - actual_sources)
    for parser_name in missing_sources:
        violations.append(f"parsed fact source missing: {parser_name}")

    notification_text = _review_notification_text(review_data)
    missing_lines = []

    for line_key in contract.get("notification_required_lines") or []:
        if line_key not in notification_text:
            missing_lines.append(line_key)

    if missing_lines:
        msg = "notification required lines missing: " + ",".join(missing_lines)
        if strict_notification:
            violations.append(msg)
        else:
            warnings.append(msg)

    return {
        "verdict": "fail" if violations else "pass",
        "violations": violations,
        "warnings": warnings,
        "summary": {
            "required_facts": required_facts,
            "missing_notification_lines": missing_lines,
            "parsed_fact_sources": sorted(actual_sources),
        },
    }


def validate_session_skill_context(session: dict[str, Any]) -> dict[str, Any]:
    violations: list[str] = []
    warnings: list[str] = []

    context = session.get("skill_context") if isinstance(session.get("skill_context"), dict) else {}

    if not context:
        violations.append("skill_context is missing")
        return {
            "verdict": "fail",
            "violations": violations,
            "warnings": warnings,
            "summary": {},
        }

    if context.get("matched") is not True:
        violations.append("skill_context.matched is not true")

    if context.get("binding_verdict") != "pass":
        violations.append("skill_context.binding_verdict is not pass")

    for item in context.get("violations") or []:
        violations.append(f"skill_context violation: {item}")

    for item in context.get("warnings") or []:
        warnings.append(f"skill_context warning: {item}")

    return {
        "verdict": "fail" if violations else "pass",
        "violations": violations,
        "warnings": warnings,
        "summary": {
            "family": context.get("family"),
            "skill_name": context.get("skill_name"),
            "binding_verdict": context.get("binding_verdict"),
            "allowed_tools": context.get("allowed_tools"),
            "allowed_capabilities": context.get("allowed_capabilities"),
            "parsers": context.get("parsers"),
        },
    }


def validate_request_skill_compliance(
    request_id: str,
    base_dir: str | Path = ".",
    strict_notification: bool = False,
) -> dict[str, Any]:
    base_dir = Path(base_dir)

    session, session_file = build_and_persist_investigation_session(request_id, base_dir)
    session_result = validate_session_skill_context(session)

    context = session.get("skill_context") if isinstance(session.get("skill_context"), dict) else {}
    skill_name = context.get("skill_name")

    violations: list[str] = []
    warnings: list[str] = []

    violations.extend(session_result.get("violations") or [])
    warnings.extend(session_result.get("warnings") or [])

    if not skill_name:
        violations.append("skill_name is missing from skill_context")
        return {
            "verdict": "fail",
            "request_id": request_id,
            "session_file": str(session_file),
            "violations": violations,
            "warnings": warnings,
            "checks": {
                "session_skill_context": session_result,
            },
        }

    contract = load_skill_contract(skill_name, base_dir)
    files = find_request_files(base_dir, request_id)

    execution_file = files.get("execution")
    review_file = files.get("review")

    if not execution_file:
        violations.append("execution file not found")
        execution_result = {
            "verdict": "fail",
            "violations": ["execution file not found"],
            "warnings": [],
            "summary": {},
        }
    else:
        execution_data = unwrap_execution(safe_read_json(Path(execution_file)))
        execution_result = validate_execution_against_skill(execution_data, contract)
        violations.extend(execution_result.get("violations") or [])
        warnings.extend(execution_result.get("warnings") or [])

    if not review_file:
        violations.append("review file not found")
        review_result = {
            "verdict": "fail",
            "violations": ["review file not found"],
            "warnings": [],
            "summary": {},
        }
    else:
        review_data = unwrap_review(safe_read_json(Path(review_file)))
        review_result = validate_review_against_skill(
            review_data,
            contract,
            strict_notification=strict_notification,
        )
        violations.extend(review_result.get("violations") or [])
        warnings.extend(review_result.get("warnings") or [])

    return {
        "verdict": "fail" if violations else "pass",
        "stage": "v6.3",
        "request_id": request_id,
        "skill_name": skill_name,
        "family": contract.get("family"),
        "session_file": str(session_file),
        "execution_file": execution_file,
        "review_file": review_file,
        "violations": violations,
        "warnings": warnings,
        "checks": {
            "session_skill_context": session_result,
            "execution": execution_result,
            "review": review_result,
        },
    }
