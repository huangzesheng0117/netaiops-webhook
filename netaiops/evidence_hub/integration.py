"""Evidence Hub pipeline integration helpers for v10.

This module is intentionally tolerant:
- it only reads existing request artifacts
- it writes only under data/evidence_hub/requests/<request_id>/
- it never blocks the original review / notification pipeline
- it never sends notifications and never touches network devices
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .detail_url import (
    build_detail_url,
    evidence_hub_enabled,
    evidence_hub_url_config_summary,
    get_evidence_hub_base_url,
)
from .schema import DEFAULT_BASE_DIR, safe_request_id
from .writer import build_evidence_detail

JsonDict = Dict[str, Any]


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
    url_config = evidence_hub_url_config_summary(config)
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
            "url_config": url_config,
        })
        if logger is not None:
            try:
                logger.info(
                    "evidence hub detail built request_id=%s stage=%s detail_url=%s detail_dir=%s missing=%s read_errors=%s",
                    rid,
                    stage,
                    detail_url,
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
            "url_config": url_config,
            "error": f"{type(exc).__name__}: {exc}",
        }


__all__ = [
    "build_detail_url",
    "build_evidence_detail_safe",
    "evidence_hub_enabled",
    "evidence_hub_url_config_summary",
    "get_evidence_hub_base_url",
]
