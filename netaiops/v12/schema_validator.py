"""Deterministic validation, reference, and serialization helpers."""

from __future__ import annotations

import json
import re
from typing import Any, Mapping, TypeVar

from pydantic import BaseModel, ValidationError

from .errors import ContractValidationError, EvidenceReferenceError


SCHEMA_VERSION = "v12.1"
REDACTED_VALUE = "[REDACTED]"

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_REFERENCE_RE = re.compile(
    r"^(?P<scheme>evidence|artifact|context|event|plan|agent|report)://"
    r"(?P<request_id>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})/"
    r"(?P<kind>[a-z][a-z0-9_-]{0,63})/"
    r"(?P<identifier>[A-Za-z0-9][A-Za-z0-9._:@-]{0,191})$"
)
_SENSITIVE_PARTS = frozenset(
    {
        "authorization",
        "cookie",
        "password",
        "passwd",
        "secret",
        "session",
        "token",
    }
)
_SENSITIVE_NAMES = frozenset(
    {
        "api_key",
        "apikey",
        "full_device_output",
        "full_log",
        "mcp_session",
        "private_key",
        "raw_payload",
        "set_cookie",
    }
)

ModelT = TypeVar("ModelT", bound=BaseModel)


def validate_request_id(value: str) -> str:
    if not isinstance(value, str) or not _REQUEST_ID_RE.fullmatch(value):
        raise ValueError("request_id must use the frozen v12 safe identifier format")
    return value


def _normalized_key(value: Any) -> tuple[str, set[str]]:
    text = str(value).strip().lower()
    normalized = re.sub(r"[^a-z0-9]+", "_", text).strip("_")
    parts = {part for part in normalized.split("_") if part}
    return normalized, parts


def is_sensitive_key(value: Any) -> bool:
    normalized, parts = _normalized_key(value)
    return normalized in _SENSITIVE_NAMES or bool(parts & _SENSITIVE_PARTS)


def sanitize_sensitive_data(value: Any) -> Any:
    """Return a deep deterministic copy with sensitive mapping values redacted."""

    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for key in sorted(value, key=lambda item: str(item)):
            text_key = str(key)
            sanitized[text_key] = (
                REDACTED_VALUE
                if is_sensitive_key(text_key)
                else sanitize_sensitive_data(value[key])
            )
        return sanitized
    if isinstance(value, tuple):
        return [sanitize_sensitive_data(item) for item in value]
    if isinstance(value, list):
        return [sanitize_sensitive_data(item) for item in value]
    if isinstance(value, set):
        items = [sanitize_sensitive_data(item) for item in value]
        return sorted(items, key=lambda item: stable_json_dumps(item))
    return value


def parse_contract_ref(value: str) -> dict[str, str]:
    if not isinstance(value, str):
        raise EvidenceReferenceError("contract reference must be a string")
    match = _REFERENCE_RE.fullmatch(value)
    if match is None:
        raise EvidenceReferenceError(
            "reference must use scheme://request_id/kind/identifier"
        )
    return match.groupdict()


def validate_contract_ref(value: str) -> str:
    parse_contract_ref(value)
    return value


def validate_evidence_ref(value: str) -> str:
    parsed = parse_contract_ref(value)
    if parsed["scheme"] != "evidence":
        raise EvidenceReferenceError("evidence_ref must use the evidence scheme")
    return value


def build_contract_ref(
    scheme: str,
    request_id: str,
    kind: str,
    identifier: str,
) -> str:
    value = f"{scheme}://{request_id}/{kind}/{identifier}"
    validate_contract_ref(value)
    return value


def build_evidence_ref(
    request_id: str,
    source: str,
    identifier: str,
) -> str:
    value = build_contract_ref("evidence", request_id, source, identifier)
    validate_evidence_ref(value)
    return value


def validate_refs_for_request(
    request_id: str,
    refs: list[str] | tuple[str, ...],
    *,
    evidence_only: bool = False,
) -> None:
    validate_request_id(request_id)
    for value in refs:
        parsed = (
            parse_contract_ref(validate_evidence_ref(value))
            if evidence_only
            else parse_contract_ref(value)
        )
        if parsed["request_id"] != request_id:
            raise EvidenceReferenceError(
                f"reference request_id mismatch: {value!r}"
            )


def stable_json_dumps(value: Any) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", exclude_none=False)
    sanitized = sanitize_sensitive_data(value)
    return json.dumps(
        sanitized,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def validate_contract(
    model_type: type[ModelT],
    payload: Mapping[str, Any],
) -> ModelT:
    try:
        return model_type.model_validate(sanitize_sensitive_data(payload))
    except ValidationError as exc:
        raise ContractValidationError(
            f"{model_type.__name__} validation failed",
            issues=exc.errors(include_url=False),
        ) from exc


def validate_contract_json(
    model_type: type[ModelT],
    payload_json: str,
) -> ModelT:
    try:
        payload = json.loads(payload_json)
    except json.JSONDecodeError as exc:
        raise ContractValidationError(
            "contract JSON is invalid",
            issues=(
                {
                    "type": "json_invalid",
                    "loc": (),
                    "msg": str(exc),
                    "input": "<invalid-json>",
                },
            ),
        ) from exc
    if not isinstance(payload, dict):
        raise ContractValidationError("contract JSON root must be an object")
    return validate_contract(model_type, payload)
