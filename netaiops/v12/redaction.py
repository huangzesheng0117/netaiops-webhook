"""Persistence redaction helpers for v12 trace artifacts."""

from __future__ import annotations

import re
from typing import Any, Mapping

from pydantic import BaseModel

from .schema_validator import (
    REDACTED_VALUE,
    is_sensitive_key,
    sanitize_sensitive_data,
)


OMITTED_VALUE = "[OMITTED]"
_OMITTED_KEYS = frozenset(
    {
        "raw_payload",
        "raw_payloads",
        "raw_output",
        "full_device_output",
        "full_log",
        "full_logs",
        "stdout",
        "stderr",
        "command_output",
        "command_outputs",
        "device_output",
        "device_outputs",
        "log_events",
        "prometheus_samples",
    }
)


def _normalized_key(value: Any) -> str:
    text = str(value).strip().lower()
    return re.sub(r"[^a-z0-9]+", "_", text).strip("_")


def redact_for_persistence(value: Any) -> Any:
    """Return a deterministic deep copy safe for trace persistence."""

    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", exclude_none=False)

    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for key in sorted(value, key=lambda item: str(item)):
            text_key = str(key)
            normalized = _normalized_key(text_key)
            if normalized in _OMITTED_KEYS:
                output[text_key] = OMITTED_VALUE
            elif is_sensitive_key(text_key):
                output[text_key] = REDACTED_VALUE
            else:
                output[text_key] = redact_for_persistence(value[key])
        return output

    if isinstance(value, tuple):
        return [redact_for_persistence(item) for item in value]

    if isinstance(value, list):
        return [redact_for_persistence(item) for item in value]

    if isinstance(value, set):
        items = [redact_for_persistence(item) for item in value]
        return sorted(items, key=lambda item: repr(item))

    return sanitize_sensitive_data(value)
