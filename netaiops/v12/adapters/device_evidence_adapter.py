"""Read-only adapter for existing device execution artifacts.

Batch G reuses the current request's execution/callback artifact. It never calls
Netmiko MCP, never renders CLI, and never exposes full raw device output to RCA.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from netaiops.output_judger import judge_command_result

from ..contracts import ContractNotice
from ..schema_validator import (
    build_contract_ref,
    build_evidence_ref,
    sanitize_sensitive_data,
    validate_request_id,
)
from ..status import EvidenceStatus


_DEFAULT_ROOTS = (
    Path("/opt/netaiops-webhook/data/callback"),
    Path("/opt/netaiops-webhook/data/execution"),
)
_MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
_ALLOWED_SCOPE_KEYS = (
    "vendor", "platform", "hostname", "device_name", "device_ip", "ip",
    "instance", "site", "interface", "if_name", "ifName", "object_name",
    "peer_ip", "pool", "pool_member",
)
_NOT_AVAILABLE_STATUSES = frozenset(
    {"runtime_disabled", "not_available", "unavailable", "backend_unavailable", "mcp_unavailable"}
)
_SKIPPED_STATUSES = frozenset({"skipped", "not_executed", "policy_blocked"})
_PARTIAL_STATUSES = frozenset({"partial", "partially_completed"})
_FAILURE_STATUSES = frozenset({"failed", "error", "timeout", "timed_out"})
_FORBIDDEN_FACT_KEYS = frozenset(
    {
        "command", "commands", "output", "raw_output", "full_device_output",
        "error", "stderr", "stdout", "prompt", "password", "secret",
        "token", "authorization", "mcp_session",
    }
)


class DeviceEvidenceAdapterError(ValueError):
    """Raised when an existing execution artifact cannot be safely normalized."""


@dataclass(frozen=True, slots=True)
class NormalizedDeviceEvidence:
    status: EvidenceStatus
    summary: str
    facts: Mapping[str, Any]
    scope: Mapping[str, Any]
    evidence_refs: tuple[str, ...]
    warnings: tuple[ContractNotice, ...]
    errors: tuple[ContractNotice, ...]
    collected_at: datetime
    reason: str | None
    source_artifact_ref: str
    source_filename: str


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _safe_identifier(value: Any, fallback: str) -> str:
    output: list[str] = []
    for char in _text(value):
        if (char.isascii() and char.isalnum()) or char in "._:@-":
            output.append(char)
        else:
            output.append("-")
    normalized = "".join(output).strip("-._:@") or fallback
    if not normalized[0].isalnum():
        normalized = "x-" + normalized
    return normalized[:191]


def _aware_datetime(value: Any, fallback: datetime) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = _text(value)
        if not text:
            return fallback
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return fallback
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return fallback
    return parsed


def _notice(code: str, message: str, *, details: Mapping[str, Any] | None = None) -> ContractNotice:
    return ContractNotice(
        code=code,
        message=message,
        stage="device_evidence",
        retryable=False,
        details=dict(details or {}),
    )


def _safe_scope(value: Any) -> dict[str, Any]:
    source = _mapping(value)
    return {
        key: sanitize_sensitive_data(source.get(key))
        for key in _ALLOWED_SCOPE_KEYS
        if source.get(key) not in (None, "", [], {})
    }


def _safe_parser_facts(item: Mapping[str, Any]) -> tuple[str, list[str], dict[str, Any], str]:
    parser = _mapping(item.get("parser"))
    parser_status = _text(
        item.get("parser_status")
        or parser.get("status")
        or ("success" if item.get("parsed_facts") or item.get("parsed") else "")
    ).lower()
    candidate = item.get("parsed_facts")
    if not isinstance(candidate, Mapping):
        candidate = item.get("parsed")
    if not isinstance(candidate, Mapping):
        candidate = parser.get("facts")
    safe: dict[str, Any] = {}
    if isinstance(candidate, Mapping):
        for key in sorted(candidate, key=lambda value: str(value))[:32]:
            name = str(key)
            if name.lower() in _FORBIDDEN_FACT_KEYS:
                continue
            raw = candidate[key]
            if isinstance(raw, (str, int, float, bool)) or raw is None:
                safe[name[:128]] = sanitize_sensitive_data(raw)
            elif isinstance(raw, list):
                safe[name[:128]] = [
                    sanitize_sensitive_data(value)
                    for value in raw[:20]
                    if isinstance(value, (str, int, float, bool)) or value is None
                ]
    parser_error = _text(item.get("parser_error") or parser.get("error"))
    return parser_status, sorted(safe), safe, parser_error


def _error_category(
    *,
    dispatch_status: str,
    output: str,
    error: str,
    judge: Mapping[str, Any],
    parser_status: str,
    parser_error: str,
    parsed_facts: Mapping[str, Any],
) -> str:
    merged = f"{dispatch_status}\n{output}\n{error}\n{parser_error}".lower()
    rule = _text(judge.get("matched_rule_id")).lower()
    if bool(judge.get("hard_error")):
        return rule or "hard_error"
    if "timeout" in merged or "timed out" in merged:
        return "timeout"
    if any(
        token in merged
        for token in (
            "mcp backend selected", "mcp unavailable", "mcp not available",
            "wrapper exception", "connection refused",
        )
    ):
        return "mcp_not_available"
    if parser_error or parser_status in {"failed", "error", "invalid"}:
        return "parser_failed"
    if dispatch_status in _FAILURE_STATUSES:
        return "dispatch_failed"
    if not output.strip() and not parsed_facts:
        return "empty_output"
    return ""


def _result_class(dispatch_status: str, error_category: str) -> str:
    if dispatch_status in _SKIPPED_STATUSES:
        return "skipped"
    if error_category:
        return "failed"
    if dispatch_status in _PARTIAL_STATUSES:
        return "partial"
    return "success"


class DeviceEvidenceAdapter:
    """Locate and normalize one existing device execution artifact."""

    def __init__(
        self,
        artifact_roots: Iterable[str | Path] = _DEFAULT_ROOTS,
        *,
        utcnow: Any | None = None,
    ) -> None:
        self.artifact_roots = tuple(Path(root) for root in artifact_roots)
        self._utcnow = utcnow or (lambda: datetime.now(timezone.utc))

    def find_existing(self, request_id: str) -> Path | None:
        request_id = validate_request_id(request_id)
        candidates: list[Path] = []
        patterns = (
            f"{request_id}.runner.result.json",
            f"*{request_id}*.execution.json",
            f"*{request_id}*.runner.result.json",
        )
        for root in self.artifact_roots:
            if not root.exists():
                continue
            if not root.is_dir():
                raise DeviceEvidenceAdapterError(f"Device evidence root is not a directory: {root}")
            resolved_root = root.resolve()
            for pattern in patterns:
                for path in root.glob(pattern):
                    if path.is_symlink() or not path.is_file():
                        continue
                    resolved = path.resolve()
                    if resolved_root not in resolved.parents:
                        continue
                    candidates.append(path)
        if not candidates:
            return None
        unique = {path.resolve(): path for path in candidates}
        ordered = list(unique.values())
        ordered.sort(key=lambda path: (path.stat().st_mtime_ns, path.name), reverse=True)
        return ordered[0]

    def load_existing(self, request_id: str) -> NormalizedDeviceEvidence | None:
        path = self.find_existing(request_id)
        if path is None:
            return None
        if path.stat().st_size > _MAX_ARTIFACT_BYTES:
            raise DeviceEvidenceAdapterError("Device execution artifact exceeds the read-only size limit")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise DeviceEvidenceAdapterError(
                f"Device execution artifact is unreadable: {type(exc).__name__}"
            ) from exc
        if not isinstance(payload, dict):
            raise DeviceEvidenceAdapterError("Device execution artifact root must be an object")
        return self.normalize(request_id, payload, source_filename=path.name)

    def normalize(
        self,
        request_id: str,
        payload: Mapping[str, Any],
        *,
        source_filename: str = "existing.runner.result.json",
    ) -> NormalizedDeviceEvidence:
        request_id = validate_request_id(request_id)
        record = sanitize_sensitive_data(dict(payload))
        record_request_id = _text(record.get("request_id"))
        if record_request_id and record_request_id != request_id:
            raise DeviceEvidenceAdapterError("Device execution request_id does not match invocation")

        now = self._utcnow()
        if now.tzinfo is None or now.utcoffset() is None:
            raise DeviceEvidenceAdapterError("utcnow provider must return a timezone-aware datetime")
        collected_at = _aware_datetime(record.get("completed_at") or record.get("finished_at"), now)
        record_status = _text(record.get("status") or record.get("execution_status")).lower()
        raw_results = record.get("command_results")
        if raw_results is None:
            raw_results = []
        if not isinstance(raw_results, list):
            raise DeviceEvidenceAdapterError("Device execution command_results must be a list")

        facts: list[dict[str, Any]] = []
        evidence_refs: list[str] = []
        warnings: list[ContractNotice] = []
        errors: list[ContractNotice] = []
        counts = {"success": 0, "partial": 0, "failed": 0, "skipped": 0}
        hard_error_count = 0
        parser_failure_count = 0

        for index, raw_item in enumerate(raw_results):
            if not isinstance(raw_item, Mapping):
                warnings.append(
                    _notice(
                        "device_result_invalid",
                        "A device command result was not an object",
                        details={"index": index},
                    )
                )
                continue
            item = sanitize_sensitive_data(dict(raw_item))
            command = _text(item.get("command"))
            output = _text(item.get("output"))
            error = _text(item.get("error"))
            dispatch_status = _text(item.get("dispatch_status") or item.get("status")).lower()
            judge_profile = _text(item.get("judge_profile") or "network_cli_generic")
            judged = judge_command_result(
                command=command,
                output=output,
                error=error,
                judge_profile=judge_profile,
                dispatch_status=dispatch_status,
            )
            parser_status, parsed_keys, parsed_facts, parser_error = _safe_parser_facts(item)
            category = _error_category(
                dispatch_status=dispatch_status,
                output=output,
                error=error,
                judge=judged,
                parser_status=parser_status,
                parser_error=parser_error,
                parsed_facts=parsed_facts,
            )
            classification = _result_class(dispatch_status, category)
            counts[classification] += 1
            if bool(judged.get("hard_error")):
                hard_error_count += 1
            if category == "parser_failed":
                parser_failure_count += 1

            output_digest = hashlib.sha256(output.encode("utf-8")).hexdigest() if output else ""
            capability = _text(item.get("capability"))[:128]
            order = item.get("order", index + 1)
            fact = {
                "order": order,
                "capability": capability,
                "dispatch_status": dispatch_status,
                "result_class": classification,
                "final_status": _text(judged.get("final_status")),
                "hard_error": bool(judged.get("hard_error")),
                "hard_error_rule": _text(judged.get("matched_rule_id")),
                "judge_reason": _text(judged.get("judge_reason")),
                "error_category": category,
                "parser_status": parser_status,
                "parsed_fact_keys": parsed_keys,
                "parsed_facts": parsed_facts,
                "output_present": bool(output),
                "output_length": len(output),
                "output_sha256": output_digest,
                "platform": _text(item.get("platform"))[:128],
                "interface": _text(item.get("interface"))[:256],
                "started_at": _text(item.get("started_at"))[:64],
                "finished_at": _text(item.get("finished_at"))[:64],
            }
            facts.append(fact)

            if classification in {"success", "partial"}:
                identifier = _safe_identifier(
                    f"{order}-{capability or 'command'}-{output_digest[:12]}",
                    f"result-{index + 1}",
                )
                evidence_refs.append(build_evidence_ref(request_id, "device", identifier))
            elif classification == "failed":
                errors.append(
                    _notice(
                        f"device_{category or 'command_failed'}",
                        "A device evidence item failed deterministic validation",
                        details={
                            "order": order,
                            "capability": capability,
                            "error_category": category or "command_failed",
                            "hard_error_rule": _text(judged.get("matched_rule_id")),
                        },
                    )
                )
            else:
                warnings.append(
                    _notice(
                        "device_result_skipped",
                        "A planned device evidence item was skipped",
                        details={"order": order, "capability": capability},
                    )
                )

        precheck = _mapping(record.get("precheck_result"))
        reason: str | None = None
        total = sum(counts.values())
        if not raw_results:
            if bool(precheck.get("stop")) or record_status in _SKIPPED_STATUSES:
                status = EvidenceStatus.SKIPPED
                reason = _text(precheck.get("reason")) or "device_execution_skipped"
            elif record_status in _NOT_AVAILABLE_STATUSES:
                status = EvidenceStatus.NOT_AVAILABLE
                reason = record_status or "device_execution_not_available"
            else:
                status = EvidenceStatus.NOT_AVAILABLE
                reason = "device_execution_results_empty"
        elif counts["success"] == total:
            status = EvidenceStatus.SUCCESS
        elif counts["failed"] == total:
            status = EvidenceStatus.FAILED
        elif counts["skipped"] == total:
            status = EvidenceStatus.SKIPPED
            reason = "device_execution_results_skipped"
        else:
            status = EvidenceStatus.PARTIAL

        summary = (
            "Device evidence: "
            f"success={counts['success']}, partial={counts['partial']}, "
            f"failed={counts['failed']}, skipped={counts['skipped']}; "
            f"hard_errors={hard_error_count}; parser_failures={parser_failure_count}."
        )
        source_identifier = _safe_identifier(
            hashlib.sha256(source_filename.encode("utf-8")).hexdigest()[:20],
            "artifact",
        )
        source_artifact_ref = build_contract_ref(
            "artifact", request_id, "device_execution", source_identifier
        )
        safe_facts = {
            "command_result_count": len(facts),
            "counts": counts,
            "hard_error_count": hard_error_count,
            "parser_failure_count": parser_failure_count,
            "results": facts,
            "reuse_existing_execution": True,
            "netmiko_mcp_called": False,
            "command_generation_performed": False,
            "write_command_executed": False,
            "raw_output_forwarded": False,
        }
        return NormalizedDeviceEvidence(
            status=status,
            summary=summary,
            facts=MappingProxyType(safe_facts),
            scope=MappingProxyType(
                {
                    **_safe_scope(record.get("target_scope")),
                    "runner_mode": _text(record.get("runner_mode"))[:64],
                    "required": True,
                }
            ),
            evidence_refs=tuple(dict.fromkeys(evidence_refs)),
            warnings=tuple(warnings),
            errors=tuple(errors),
            collected_at=collected_at,
            reason=reason,
            source_artifact_ref=source_artifact_ref,
            source_filename=source_filename,
        )
