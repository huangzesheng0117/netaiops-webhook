"""Evidence Hub list/search API helpers for v10 Batch 6.

This module provides a read-only index over data/evidence_hub/requests.
Design boundaries:
- scan only data/evidence_hub/requests/<request_id>/
- read summary.json and meta.json only for list/search
- never reads token/env/secret files
- never touches devices and never sends DingDong notifications
- never builds or mutates Evidence Hub details
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from .schema import DEFAULT_BASE_DIR, evidence_hub_root, safe_request_id

JsonDict = Dict[str, Any]

DEFAULT_LIMIT = 50
MAX_LIMIT = 500


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _casefold(value: Any) -> str:
    return _as_text(value).casefold()


def _nested(data: Mapping[str, Any], *keys: str) -> Any:
    cur: Any = data
    for key in keys:
        if not isinstance(cur, Mapping):
            return ""
        cur = cur.get(key)
    return cur if cur is not None else ""


def _read_json(path: Path) -> Tuple[JsonDict, str]:
    if not path.exists():
        return {}, "missing"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"error": str(exc)}, "read_error"
    if isinstance(data, dict):
        return data, "ok"
    return {"_value": data}, "non_object"


def _rel_path(path: Path, base_dir: Path) -> str:
    try:
        return str(path.relative_to(base_dir))
    except Exception:
        return str(path)


def _dir_mtime_iso(path: Path) -> str:
    try:
        ts = path.stat().st_mtime
    except OSError:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _normalize_limit(limit: Any) -> int:
    try:
        number = int(limit)
    except Exception:
        raise ValueError("limit must be an integer")
    if number <= 0:
        raise ValueError("limit must be greater than 0")
    if number > MAX_LIMIT:
        return MAX_LIMIT
    return number


def _normalize_offset(offset: Any) -> int:
    try:
        number = int(offset)
    except Exception:
        raise ValueError("offset must be an integer")
    if number < 0:
        raise ValueError("offset must be greater than or equal to 0")
    return number


def _summary_payload(summary_doc: Mapping[str, Any]) -> JsonDict:
    value = summary_doc.get("summary")
    return value if isinstance(value, dict) else {}


def _meta_payload(meta_doc: Mapping[str, Any]) -> JsonDict:
    value = meta_doc.get("data")
    return value if isinstance(value, dict) else {}


def _recommendations(value: Any) -> List[str]:
    if isinstance(value, list):
        return [_as_text(item) for item in value if _as_text(item)][:3]
    text = _as_text(value)
    return [text] if text else []


def _request_summary_from_dir(detail_dir: Path, base_dir: Path) -> JsonDict:
    request_id = detail_dir.name
    try:
        request_id = safe_request_id(request_id)
    except ValueError:
        return {
            "request_id": detail_dir.name,
            "status": "invalid_request_dir",
            "detail_dir": _rel_path(detail_dir, base_dir),
            "errors": ["invalid request_id directory name"],
        }

    summary_doc, summary_status = _read_json(detail_dir / "summary.json")
    meta_doc, meta_status = _read_json(detail_dir / "meta.json")
    summary = _summary_payload(summary_doc)
    meta = _meta_payload(meta_doc)

    device = summary.get("device") if isinstance(summary.get("device"), Mapping) else {}
    evidence_status = summary.get("evidence_status") if isinstance(summary.get("evidence_status"), Mapping) else {}
    command_stats = summary.get("command_stats") if isinstance(summary.get("command_stats"), Mapping) else {}

    hostname = _as_text(device.get("hostname")) or _as_text(meta.get("hostname"))
    device_ip = _as_text(device.get("device_ip")) or _as_text(meta.get("device_ip"))
    family = _as_text(summary.get("family")) or _as_text(meta.get("family"))
    object_name = _as_text(summary.get("object")) or _as_text(meta.get("object_name"))
    detail_url = _as_text(summary.get("detail_url")) or _as_text(meta.get("detail_url"))
    generated_at = _as_text(summary_doc.get("generated_at"))
    created_at = _as_text(meta_doc.get("captured_at")) or _as_text(meta.get("created_at"))
    updated_at = generated_at or created_at or _dir_mtime_iso(detail_dir)

    errors = []
    if summary_status not in {"ok", "missing"}:
        errors.append(f"summary:{summary_status}")
    if meta_status not in {"ok", "missing"}:
        errors.append(f"meta:{meta_status}")

    return {
        "request_id": request_id,
        "status": "ok" if not errors else "partial",
        "schema_version": _as_text(summary_doc.get("schema_version")) or _as_text(meta_doc.get("schema_version")),
        "generated_at": generated_at,
        "created_at": created_at,
        "updated_at": updated_at,
        "detail_dir": _rel_path(detail_dir, base_dir),
        "detail_url": detail_url,
        "title": _as_text(summary.get("title")),
        "family": family,
        "hostname": hostname,
        "device_ip": device_ip,
        "object_name": object_name,
        "judgement": _as_text(summary.get("judgement")),
        "recommendations": _recommendations(summary.get("recommendations")),
        "evidence_status": dict(evidence_status),
        "command_stats": dict(command_stats),
        "missing_sections": summary_doc.get("missing_sections") if isinstance(summary_doc.get("missing_sections"), list) else [],
        "read_error_sections": summary_doc.get("read_error_sections") if isinstance(summary_doc.get("read_error_sections"), list) else [],
        "source_status": {
            "summary": summary_status,
            "meta": meta_status,
        },
        "errors": errors,
    }


def _contains(actual: Any, expected: Any) -> bool:
    text = _casefold(actual)
    pattern = _casefold(expected)
    if not pattern:
        return True
    return pattern in text


def _matches_filters(item: Mapping[str, Any], filters: Mapping[str, str]) -> bool:
    if filters.get("request_id") and not _contains(item.get("request_id"), filters["request_id"]):
        return False
    if filters.get("device_ip") and _as_text(item.get("device_ip")) != _as_text(filters["device_ip"]):
        return False
    if filters.get("hostname") and not _contains(item.get("hostname"), filters["hostname"]):
        return False
    if filters.get("family") and not _contains(item.get("family"), filters["family"]):
        return False
    q = filters.get("q")
    if q:
        haystack = " ".join(
            _as_text(item.get(key))
            for key in [
                "request_id",
                "title",
                "family",
                "hostname",
                "device_ip",
                "object_name",
                "judgement",
            ]
        )
        if not _contains(haystack, q):
            return False
    return True


def iter_evidence_request_summaries(*, base_dir: Path = DEFAULT_BASE_DIR) -> Iterable[JsonDict]:
    """Yield compact summaries for all Evidence Hub requests."""
    base = Path(base_dir)
    root = evidence_hub_root(base)
    if not root.exists() or not root.is_dir():
        return []
    items = []
    for detail_dir in root.iterdir():
        if detail_dir.is_dir():
            items.append(_request_summary_from_dir(detail_dir, base))
    items.sort(
        key=lambda item: (_as_text(item.get("updated_at")), _as_text(item.get("request_id"))),
        reverse=True,
    )
    return items


def get_evidence_list(
    *,
    base_dir: Path = DEFAULT_BASE_DIR,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
    device_ip: str = "",
    family: str = "",
    hostname: str = "",
    request_id: str = "",
    q: str = "",
) -> JsonDict:
    """Return latest Evidence Hub requests with simple filters."""
    base = Path(base_dir)
    normalized_limit = _normalize_limit(limit)
    normalized_offset = _normalize_offset(offset)
    filters = {
        "device_ip": _as_text(device_ip),
        "family": _as_text(family),
        "hostname": _as_text(hostname),
        "request_id": _as_text(request_id),
        "q": _as_text(q),
    }

    all_items = list(iter_evidence_request_summaries(base_dir=base))
    filtered = [item for item in all_items if _matches_filters(item, filters)]
    paged = filtered[normalized_offset : normalized_offset + normalized_limit]

    return {
        "status": "ok",
        "root": _rel_path(evidence_hub_root(base), base),
        "total": len(filtered),
        "count": len(paged),
        "limit": normalized_limit,
        "offset": normalized_offset,
        "has_more": normalized_offset + normalized_limit < len(filtered),
        "filters": filters,
        "requests": paged,
    }


def list_api_route_manifest() -> JsonDict:
    return {
        "batch": "v10_batch6",
        "routes": [
            "GET /evidence",
            "GET /evidence?limit=50",
            "GET /evidence?device_ip=...",
            "GET /evidence?family=...",
            "GET /evidence?hostname=...",
            "GET /evidence?q=...",
        ],
    }


__all__ = [
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "get_evidence_list",
    "iter_evidence_request_summaries",
    "list_api_route_manifest",
]
