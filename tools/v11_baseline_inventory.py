#!/usr/bin/env python3
"""Build a read-only v11 baseline inventory for one historical request.

This tool reads only local request artifacts and Git metadata. It does not
call GLM, Prometheus MCP, Netmiko MCP, DingTalk, or any other network service.
It never embeds raw payloads, device output, Prometheus samples, or secrets in
its JSON output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


PROJECT_IMPORT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_IMPORT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_IMPORT_ROOT))

from netaiops.governance.contracts import (  # noqa: E402
    ArtifactRef,
    DEFAULT_EXTERNAL_CALL_POLICY,
    GOVERNANCE_SCHEMA_VERSION,
    LOGS_NOT_AVAILABLE_REASON,
    REAL_FIXTURE_MATRIX,
    SYNTHETIC_FIXTURE_MATRIX,
    get_fixture_spec,
)


_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
MAX_JSON_READ_BYTES = 16 * 1024 * 1024

ARTIFACT_PATTERNS: tuple[tuple[str, str], ...] = (
    ("raw_payload", "data/raw/*{request_id}*.json"),
    ("normalized_event", "data/normalized/*{request_id}*.json"),
    ("analysis", "data/analysis/*{request_id}*.analysis.json"),
    ("pipeline", "data/analysis/*{request_id}*.pipeline.json"),
    ("plan", "data/plans/*{request_id}*.plan.json"),
    (
        "prometheus_evidence",
        "data/prometheus_evidence/*{request_id}*.prometheus_evidence.json",
    ),
    ("execution", "data/execution/*{request_id}*.execution.json"),
    ("review", "data/reviews/*{request_id}*.review.json"),
    (
        "notification_summary",
        "data/evidence_hub/requests/{request_id}/notification_summary.json",
    ),
    (
        "notification_summary_slim",
        "data/evidence_hub/requests/{request_id}/notification_summary_slim.json",
    ),
    (
        "ai_analysis_card",
        "data/evidence_hub/requests/{request_id}/ai_analysis_card.json",
    ),
    (
        "ai_analysis_card_send_result",
        "data/evidence_hub/requests/{request_id}/ai_analysis_card_send_result.json",
    ),
    (
        "evidence_hub_meta",
        "data/evidence_hub/requests/{request_id}/meta.json",
    ),
    (
        "evidence_hub_summary",
        "data/evidence_hub/requests/{request_id}/summary.json",
    ),
)

REQUIRED_BASELINE_KINDS = (
    "raw_payload",
    "normalized_event",
    "analysis",
    "plan",
    "execution",
    "review",
    "evidence_hub_meta",
    "evidence_hub_summary",
)


class InventoryError(RuntimeError):
    """Raised when a baseline request cannot be safely inventoried."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def validate_request_id(value: str) -> str:
    request_id = str(value or "").strip()
    if not _REQUEST_ID_RE.fullmatch(request_id):
        raise InventoryError(f"invalid request_id: {value!r}")
    if request_id in {".", ".."} or "/" in request_id or "\\" in request_id:
        raise InventoryError(f"unsafe request_id: {value!r}")
    return request_id


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_relative_path(path: Path, project_root: Path) -> str:
    try:
        return path.resolve().relative_to(project_root.resolve()).as_posix()
    except ValueError as exc:
        raise InventoryError(f"artifact escapes project root: {path}") from exc


def read_json_object(path: Path) -> tuple[dict[str, Any] | None, str]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, f"stat_failed:{type(exc).__name__}:{exc}"
    if size > MAX_JSON_READ_BYTES:
        return None, f"file_too_large:{size}"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, f"json_read_failed:{type(exc).__name__}:{exc}"
    if not isinstance(value, dict):
        return None, f"json_root_not_object:{type(value).__name__}"
    return value, ""


def first_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def pick(mapping: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        value = mapping.get(name)
        if value not in (None, "", [], {}):
            return value
    return None


def string_value(value: Any, *, limit: int = 240) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        text = str(value).strip()
    else:
        return ""
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def integer_value(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def git_output(project_root: Path, *args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=project_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout.strip()


def git_metadata(project_root: Path) -> dict[str, Any]:
    branch = git_output(project_root, "rev-parse", "--abbrev-ref", "HEAD")
    commit = git_output(project_root, "rev-parse", "HEAD")
    status = git_output(
        project_root,
        "status",
        "--short",
        "--untracked-files=all",
    )
    return {
        "available": bool(branch and commit),
        "branch": branch,
        "commit": commit,
        "dirty": bool(status),
    }


def find_artifacts(
    project_root: Path,
    request_id: str,
) -> tuple[dict[str, list[Path]], list[ArtifactRef]]:
    groups: dict[str, list[Path]] = {}
    references: list[ArtifactRef] = []
    seen: set[Path] = set()

    for kind, pattern in ARTIFACT_PATTERNS:
        formatted = pattern.format(request_id=request_id)
        paths = sorted(
            path
            for path in project_root.glob(formatted)
            if path.is_file()
        )
        groups[kind] = paths
        for path in paths:
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            references.append(
                ArtifactRef(
                    kind=kind,
                    path=safe_relative_path(path, project_root),
                    sha256=sha256_file(path),
                    exists=True,
                    size_bytes=path.stat().st_size,
                )
            )

    return groups, references


def load_first(
    groups: Mapping[str, Sequence[Path]],
    kind: str,
    read_errors: list[dict[str, str]],
) -> dict[str, Any]:
    paths = groups.get(kind) or ()
    if not paths:
        return {}
    value, error = read_json_object(paths[0])
    if error:
        read_errors.append(
            {
                "kind": kind,
                "path": paths[0].as_posix(),
                "error": error,
            }
        )
        return {}
    return value or {}


def extract_analysis_summary(data: Mapping[str, Any]) -> dict[str, Any]:
    result = first_mapping(data.get("result"))
    return {
        "status": string_value(pick(data, "analysis_status", "status")),
        "model": string_value(pick(data, "model", "llm_model_requested")),
        "requested_model": string_value(data.get("llm_model_requested")),
        "error_type": string_value(data.get("error_type")),
        "result_status": string_value(pick(result, "status", "analysis_status")),
    }


def extract_plan_summary(data: Mapping[str, Any]) -> dict[str, Any]:
    target = first_mapping(data.get("target_scope"))
    return {
        "status": string_value(pick(data, "plan_status", "status")),
        "plan_type": string_value(data.get("plan_type")),
        "readonly_only": bool(data.get("readonly_only", False)),
        "requires_confirmation": bool(data.get("requires_confirmation", False)),
        "hostname": string_value(pick(target, "hostname", "device_name")),
        "device_ip": string_value(pick(target, "device_ip", "ip")),
        "object": string_value(pick(target, "interface", "object", "object_name")),
    }


def extract_prometheus_summary(data: Mapping[str, Any]) -> dict[str, Any]:
    evidences = data.get("evidences")
    evidence_count = len(evidences) if isinstance(evidences, list) else 0
    return {
        "status": string_value(pick(data, "status", "evidence_status")),
        "ok": bool(data.get("ok", False)),
        "profile": string_value(data.get("profile")),
        "query_count": len(data.get("query_names") or [])
        if isinstance(data.get("query_names"), list)
        else 0,
        "evidence_count": evidence_count,
    }


def extract_execution_summary(data: Mapping[str, Any]) -> dict[str, Any]:
    stats = first_mapping(data.get("stats"))
    results = data.get("command_results")
    command_count = len(results) if isinstance(results, list) else 0
    return {
        "status": string_value(pick(data, "execution_status", "status")),
        "readonly_only": bool(data.get("readonly_only", False)),
        "command_count": command_count,
        "success_count": integer_value(
            pick(stats, "success", "success_count", "succeeded", "completed_commands")
        ),
        "failed_count": integer_value(
            pick(stats, "failed", "failed_count", "failure_count", "failed_commands")
        ),
        "hard_error_count": integer_value(
            pick(stats, "hard_error_count", "cli_hard_error_count")
        ),
    }


def extract_review_summary(data: Mapping[str, Any]) -> dict[str, Any]:
    stats = first_mapping(data.get("stats"))
    evidence = first_mapping(data.get("evidence_summary"))
    return {
        "status": string_value(pick(data, "review_status", "status")),
        "execution_status": string_value(data.get("execution_status")),
        "family": string_value(data.get("family")),
        "missing_evidence_count": integer_value(
            pick(stats, "missing_evidence_count", "missing_count")
        ),
        "metrics_status": string_value(
            pick(evidence, "metrics_status", "prometheus_status")
        ),
    }


def extract_evidence_hub_summary(data: Mapping[str, Any]) -> dict[str, Any]:
    summary = first_mapping(data.get("summary"))
    meta = first_mapping(data.get("meta"))
    evidence_status = first_mapping(
        pick(summary, "evidence_status") or data.get("evidence_status")
    )
    missing = pick(data, "missing_sections")
    read_errors = pick(data, "read_error_sections")
    return {
        "status": string_value(pick(data, "status", "overall_status")),
        "family": string_value(pick(meta, "family") or data.get("family")),
        "metrics_status": string_value(evidence_status.get("metrics")),
        "device_status": string_value(evidence_status.get("device")),
        "review_status": string_value(evidence_status.get("review")),
        "missing_sections": list(missing) if isinstance(missing, list) else [],
        "read_error_sections": list(read_errors)
        if isinstance(read_errors, list)
        else [],
    }


def build_inventory(project_root: Path, request_id: str) -> dict[str, Any]:
    root = project_root.expanduser().resolve()
    if not root.is_dir():
        raise InventoryError(f"project root does not exist: {root}")
    request_id = validate_request_id(request_id)

    groups, references = find_artifacts(root, request_id)
    read_errors: list[dict[str, str]] = []

    analysis = load_first(groups, "analysis", read_errors)
    plan = load_first(groups, "plan", read_errors)
    prometheus = load_first(groups, "prometheus_evidence", read_errors)
    execution = load_first(groups, "execution", read_errors)
    review = load_first(groups, "review", read_errors)
    evidence_hub = load_first(groups, "evidence_hub_summary", read_errors)
    if not evidence_hub:
        evidence_hub = load_first(groups, "evidence_hub_meta", read_errors)

    present_kinds = sorted(kind for kind, paths in groups.items() if paths)
    missing_required = [
        kind for kind in REQUIRED_BASELINE_KINDS if not groups.get(kind)
    ]
    fixture = get_fixture_spec(request_id)

    inventory_status = "ready"
    if missing_required or read_errors:
        inventory_status = "partial"

    artifact_groups = {
        kind: {
            "count": len(paths),
            "paths": [safe_relative_path(path, root) for path in paths],
        }
        for kind, paths in groups.items()
    }

    return {
        "schema_version": GOVERNANCE_SCHEMA_VERSION,
        "inventory_type": "v11_baseline_request_inventory",
        "status": inventory_status,
        "generated_at": utc_now(),
        "request_id": request_id,
        "fixture": fixture.to_dict() if fixture else None,
        "git_metadata": git_metadata(root),
        "artifact_summary": {
            "present_kinds": present_kinds,
            "missing_required_kinds": missing_required,
            "artifact_count": len(references),
            "read_errors": read_errors,
        },
        "artifact_groups": artifact_groups,
        "artifact_refs": [item.to_dict() for item in references],
        "request_summary": {
            "analysis": extract_analysis_summary(analysis),
            "plan": extract_plan_summary(plan),
            "prometheus": extract_prometheus_summary(prometheus),
            "execution": extract_execution_summary(execution),
            "review": extract_review_summary(review),
            "evidence_hub": extract_evidence_hub_summary(evidence_hub),
            "logs": {
                "status": "not_available",
                "reason": LOGS_NOT_AVAILABLE_REASON,
                "proposal_eligible": False,
            },
        },
        "fixture_matrix": {
            "real": [item.to_dict() for item in REAL_FIXTURE_MATRIX],
            "synthetic": [item.to_dict() for item in SYNTHETIC_FIXTURE_MATRIX],
        },
        "external_call_policy": DEFAULT_EXTERNAL_CALL_POLICY.to_dict(),
        "external_calls_performed": {
            "glm": False,
            "prometheus_mcp": False,
            "netmiko_mcp": False,
            "notification": False,
            "webhook_post": False,
        },
        "sensitive_content_embedded": False,
    }


def write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    output = path.expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(output)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a read-only v11 baseline inventory for one request."
    )
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--json-out", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        inventory = build_inventory(
            Path(args.project_root),
            args.request_id,
        )
        write_json_atomic(Path(args.json_out), inventory)
    except (InventoryError, OSError, ValueError) as exc:
        print(f"[FAIL] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "status": inventory["status"],
                "request_id": inventory["request_id"],
                "artifact_count": inventory["artifact_summary"]["artifact_count"],
                "missing_required_kinds": inventory["artifact_summary"][
                    "missing_required_kinds"
                ],
                "json_out": str(Path(args.json_out)),
                "external_calls_performed": inventory[
                    "external_calls_performed"
                ],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
