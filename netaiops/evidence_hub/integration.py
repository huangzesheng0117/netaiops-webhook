"""Evidence Hub pipeline integration helpers for v10 Batch 3.

This module is intentionally side-effect-light and tolerant:
- it only reads existing request artifacts
- it writes only under data/evidence_hub/requests/<request_id>/
- it never blocks the original review / notification pipeline
- it never sends notifications and never touches network devices
"""

from __future__ import annotations

from pathlib import Path
import os
from typing import Any, Dict, Mapping, Optional

from .schema import DEFAULT_BASE_DIR, safe_request_id
from .writer import build_evidence_detail

JsonDict = Dict[str, Any]


def _as_bool(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on", "enabled", "enable"}:
        return True
    if text in {"0", "false", "no", "n", "off", "disabled", "disable"}:
        return False
    return default


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _nested_mapping(config: Optional[Mapping[str, Any]], key: str) -> Mapping[str, Any]:
    if not isinstance(config, Mapping):
        return {}
    value = config.get(key)
    return value if isinstance(value, Mapping) else {}


def evidence_hub_enabled(config: Optional[Mapping[str, Any]] = None) -> bool:
    """Return whether automatic Evidence Hub detail building is enabled."""
    env_value = os.environ.get("EVIDENCE_HUB_ENABLED")
    if env_value is not None:
        return _as_bool(env_value, default=True)

    section = _nested_mapping(config, "evidence_hub")
    for value in (
        section.get("enabled"),
        section.get("auto_build_enabled"),
        (config or {}).get("evidence_hub_enabled") if isinstance(config, Mapping) else None,
    ):
        if value is not None:
            return _as_bool(value, default=True)
    return True


def get_evidence_hub_base_url(config: Optional[Mapping[str, Any]] = None) -> str:
    """Return configured public Evidence Hub base URL, if any."""
    env_value = _as_text(os.environ.get("EVIDENCE_HUB_BASE_URL"))
    if env_value:
        return env_value.rstrip("/")

    section = _nested_mapping(config, "evidence_hub")
    candidates = [
        section.get("base_url"),
        section.get("detail_base_url"),
        section.get("public_base_url"),
    ]
    if isinstance(config, Mapping):
        candidates.extend([
            config.get("evidence_hub_base_url"),
            config.get("detail_base_url"),
        ])
    for value in candidates:
        text = _as_text(value)
        if text:
            return text.rstrip("/")
    return ""


def build_detail_url(
    request_id: str,
    *,
    config: Optional[Mapping[str, Any]] = None,
) -> str:
    """Build /evidence-ui/<request_id> URL if a base URL exists."""
    rid = safe_request_id(request_id)
    base_url = get_evidence_hub_base_url(config)
    if not base_url:
        return ""
    return f"{base_url}/evidence-ui/{rid}"


def build_evidence_detail_safe(
    request_id: str,
    *,
    base_dir: Path = DEFAULT_BASE_DIR,
    config: Optional[Mapping[str, Any]] = None,
    stage: str = "pipeline",
    logger: Any = None,
    overwrite: bool = True,
) -> JsonDict:
    """Build Evidence Hub detail without ever raising to the main pipeline."""
    try:
        rid = safe_request_id(request_id)
    except Exception as exc:
        return {
            "ok": False,
            "status": "error",
            "stage": stage,
            "request_id": str(request_id),
            "enabled": True,
            "error": f"invalid_request_id: {exc}",
        }

    enabled = evidence_hub_enabled(config)
    if not enabled:
        return {
            "ok": True,
            "status": "skipped",
            "reason": "evidence_hub_disabled",
            "stage": stage,
            "request_id": rid,
            "enabled": False,
        }

    detail_url = build_detail_url(rid, config=config)
    try:
        result = build_evidence_detail(
            rid,
            base_dir=Path(base_dir),
            detail_url=detail_url,
            overwrite=overwrite,
        )
        result = dict(result or {})
        result.update({
            "ok": True,
            "enabled": True,
            "stage": stage,
            "detail_url": detail_url,
        })
        if logger is not None:
            try:
                logger.info(
                    "evidence hub detail built request_id=%s stage=%s detail_dir=%s missing=%s read_errors=%s",
                    rid,
                    stage,
                    result.get("detail_dir_rel") or result.get("detail_dir"),
                    result.get("missing_sections"),
                    result.get("read_error_sections"),
                )
            except Exception:
                pass
        return result
    except Exception as exc:
        if logger is not None:
            try:
                logger.exception(
                    "evidence hub detail build failed request_id=%s stage=%s: %r",
                    rid,
                    stage,
                    exc,
                )
            except Exception:
                pass
        return {
            "ok": False,
            "status": "error",
            "stage": stage,
            "request_id": rid,
            "enabled": True,
            "detail_url": detail_url,
            "error": f"{type(exc).__name__}: {exc}",
        }


__all__ = [
    "build_detail_url",
    "build_evidence_detail_safe",
    "evidence_hub_enabled",
    "get_evidence_hub_base_url",
]
