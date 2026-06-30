"""Evidence Hub read-only Detail API helpers for v10 Batch 5.

This module provides safe JSON readers for the FastAPI routes added in Batch 5.
Design boundaries:
- read only data/evidence_hub/requests/<request_id>/
- never builds details automatically
- never reads token / env / secret files
- never touches devices and never sends DingDong notifications
- API responses prefer relative paths when a path is under the project base dir
"""

from __future__ import annotations

from pathlib import Path
import json
from typing import Any, Dict, Iterable, Mapping

from .schema import DEFAULT_BASE_DIR, REQUIRED_SECTION_FILES, request_detail_dir, safe_request_id

JsonDict = Dict[str, Any]

SUMMARY_FILENAME = "summary.json"
SECTION_ALIASES: Dict[str, str] = {
    "meta": "meta",
    "alert": "alert_context",
    "alert_context": "alert_context",
    "normalized": "normalized_event",
    "normalized_event": "normalized_event",
    "classification": "classification",
    "plan": "plan",
    "metrics": "metrics_evidence",
    "metrics_evidence": "metrics_evidence",
    "device": "device_evidence",
    "device_evidence": "device_evidence",
    "review": "review",
    "analysis": "analysis_result",
    "analysis_result": "analysis_result",
    "notification": "notification_summary",
    "notification_summary": "notification_summary",
    "raw": "raw_payload",
    "raw_payload": "raw_payload",
}


def _as_path(value: Any) -> Path:
    return value if isinstance(value, Path) else Path(str(value))


def _rel_path(path: Path, base_dir: Path) -> str:
    try:
        return str(path.relative_to(base_dir))
    except Exception:
        return str(path)


def _read_json_file(path: Path) -> JsonDict:
    if not path.exists():
        raise FileNotFoundError(str(path))
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        return data
    return {"_value": data}


def _normalize_section_name(section: str) -> str:
    key = str(section or "").strip().lower()
    if key not in SECTION_ALIASES:
        raise KeyError(f"unknown evidence section: {section!r}")
    return SECTION_ALIASES[key]


def _safe_detail_dir(request_id: str, base_dir: Path) -> Path:
    rid = safe_request_id(request_id)
    detail_dir = request_detail_dir(rid, base_dir=base_dir)
    if not detail_dir.exists() or not detail_dir.is_dir():
        raise FileNotFoundError(f"evidence detail not found for request_id={rid}")
    return detail_dir


def _section_filename(section_name: str) -> str:
    normalized = _normalize_section_name(section_name)
    return REQUIRED_SECTION_FILES[normalized]


def _sanitize_paths(value: Any, base_dir: Path) -> Any:
    """Replace absolute project paths with relative paths for API output."""
    path_like_keys = {
        "source_file",
        "detail_dir",
        "detail_root",
        "review_file",
        "execution_file",
        "plan_file",
        "analysis_file",
        "normalized_file",
        "raw_file",
    }
    if isinstance(value, dict):
        sanitized: JsonDict = {}
        for key, item in value.items():
            if key in path_like_keys and isinstance(item, str) and item.startswith(str(base_dir)):
                sanitized[key] = _rel_path(Path(item), base_dir)
            else:
                sanitized[key] = _sanitize_paths(item, base_dir)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_paths(item, base_dir) for item in value]
    return value


def detail_exists(request_id: str, *, base_dir: Path = DEFAULT_BASE_DIR) -> bool:
    try:
        rid = safe_request_id(request_id)
    except ValueError:
        return False
    return request_detail_dir(rid, base_dir=Path(base_dir)).is_dir()


def get_evidence_summary(request_id: str, *, base_dir: Path = DEFAULT_BASE_DIR) -> JsonDict:
    """Return summary.json for one request_id."""
    base = Path(base_dir)
    rid = safe_request_id(request_id)
    detail_dir = _safe_detail_dir(rid, base)
    summary_path = detail_dir / SUMMARY_FILENAME
    data = _sanitize_paths(_read_json_file(summary_path), base)
    return {
        "status": "ok",
        "request_id": rid,
        "section": "summary",
        "file": _rel_path(summary_path, base),
        "data": data,
    }


def get_evidence_section(
    request_id: str,
    section: str,
    *,
    base_dir: Path = DEFAULT_BASE_DIR,
) -> JsonDict:
    """Return a single evidence section document."""
    base = Path(base_dir)
    rid = safe_request_id(request_id)
    section_name = _normalize_section_name(section)
    detail_dir = _safe_detail_dir(rid, base)
    section_path = detail_dir / _section_filename(section_name)
    data = _sanitize_paths(_read_json_file(section_path), base)
    return {
        "status": "ok",
        "request_id": rid,
        "section": section_name,
        "file": _rel_path(section_path, base),
        "data": data,
    }


def get_evidence_detail(request_id: str, *, base_dir: Path = DEFAULT_BASE_DIR) -> JsonDict:
    """Return all available Evidence Hub section documents for one request_id."""
    base = Path(base_dir)
    rid = safe_request_id(request_id)
    detail_dir = _safe_detail_dir(rid, base)

    sections: Dict[str, JsonDict] = {}
    available_sections = []
    missing_sections = []
    for section_name, filename in REQUIRED_SECTION_FILES.items():
        section_path = detail_dir / filename
        if not section_path.exists():
            missing_sections.append(section_name)
            continue
        sections[section_name] = _sanitize_paths(_read_json_file(section_path), base)
        available_sections.append(section_name)

    summary_index: JsonDict = {}
    summary_path = detail_dir / SUMMARY_FILENAME
    if summary_path.exists():
        summary_index = _sanitize_paths(_read_json_file(summary_path), base)
    else:
        missing_sections.append("summary")

    return {
        "status": "ok",
        "request_id": rid,
        "detail_dir": _rel_path(detail_dir, base),
        "summary_file": _rel_path(summary_path, base),
        "summary_index": summary_index,
        "available_sections": available_sections,
        "missing_sections": missing_sections,
        "sections": sections,
    }


def get_evidence_metrics(request_id: str, *, base_dir: Path = DEFAULT_BASE_DIR) -> JsonDict:
    return get_evidence_section(request_id, "metrics", base_dir=base_dir)


def get_evidence_device(request_id: str, *, base_dir: Path = DEFAULT_BASE_DIR) -> JsonDict:
    return get_evidence_section(request_id, "device", base_dir=base_dir)


def get_evidence_review(request_id: str, *, base_dir: Path = DEFAULT_BASE_DIR) -> JsonDict:
    return get_evidence_section(request_id, "review", base_dir=base_dir)


def api_route_manifest() -> Dict[str, Iterable[str]]:
    """Return route manifest for tests and release audit."""
    return {
        "batch": "v10_batch5",
        "routes": [
            "GET /evidence/{request_id}",
            "GET /evidence/{request_id}/summary",
            "GET /evidence/{request_id}/raw",
            "GET /evidence/{request_id}/metrics",
            "GET /evidence/{request_id}/device",
            "GET /evidence/{request_id}/review",
        ],
    }


__all__ = [
    "SECTION_ALIASES",
    "api_route_manifest",
    "detail_exists",
    "get_evidence_detail",
    "get_evidence_device",
    "get_evidence_metrics",
    "get_evidence_review",
    "get_evidence_section",
    "get_evidence_summary",
]
