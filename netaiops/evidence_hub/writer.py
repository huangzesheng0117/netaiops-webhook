"""Evidence Hub detail writer for v10 Batch 2.

The writer aggregates existing request artifacts into a single request detail
directory under data/evidence_hub/requests/<request_id>/.

Design boundaries:
- read existing data artifacts only
- write only under data/evidence_hub/requests/<request_id>/
- do not mutate original data/raw, data/normalized, data/plans, etc.
- do not access devices
- do not send DingDong notifications
- do not integrate into the production pipeline yet
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import os
import tempfile
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from .schema import (
    DEFAULT_BASE_DIR,
    DETAIL_ROOT_REL_PATH,
    REQUIRED_SECTION_FILES,
    SCHEMA_VERSION,
    build_empty_detail,
    request_detail_dir,
    safe_request_id,
    utc_now,
)

JsonDict = Dict[str, Any]

SOURCE_PATTERNS: Dict[str, List[str]] = {
    "raw_payload": [
        "data/raw/*{request_id}*.json",
        "data/raw/**/*{request_id}*.json",
    ],
    "normalized_event": [
        "data/normalized/*{request_id}*.json",
        "data/normalized/**/*{request_id}*.json",
    ],
    "analysis_result": [
        "data/analysis/*{request_id}*.analysis.json",
        "data/analysis/*{request_id}*.json",
        "data/analysis/**/*{request_id}*.json",
    ],
    "plan": [
        "data/plans/*{request_id}*.plan.json",
        "data/plans/*{request_id}*.json",
        "data/plans/**/*{request_id}*.json",
    ],
    "metrics_evidence": [
        "data/prometheus_evidence/*{request_id}*.prometheus_evidence.json",
        "data/prometheus_evidence/*{request_id}*.json",
        "data/prometheus_evidence/**/*{request_id}*.json",
    ],
    "device_evidence": [
        "data/execution/*{request_id}*.execution.json",
        "data/execution/*{request_id}*.json",
        "data/execution/**/*{request_id}*.json",
        "data/callback/{request_id}.runner.result.json",
        "data/callback/*{request_id}*.runner.result.json",
        "data/callback/**/*{request_id}*.runner.result.json",
        "data/callback/{request_id}.callback.payload.json",
        "data/callback/*{request_id}*.callback.payload.json",
        "data/callback/**/*{request_id}*.callback.payload.json",
    ],
    "review": [
        "data/reviews/*{request_id}*.review.json",
        "data/reviews/*{request_id}*.json",
        "data/reviews/**/*{request_id}*.json",
    ],
}

DERIVED_SECTIONS = {
    "meta",
    "alert_context",
    "classification",
    "notification_summary",
}


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _shorten(value: Any, limit: int = 300) -> str:
    text = " ".join(_as_text(value).replace("\r", " ").replace("\n", " ").split())
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3] + "..."


def _rel_path(path: Path, base_dir: Path) -> str:
    try:
        return str(path.relative_to(base_dir))
    except Exception:
        return str(path)


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _glob_first(base_dir: Path, patterns: Iterable[str], request_id: str) -> Optional[Path]:
    matches: List[Path] = []
    for pattern in patterns:
        rendered = pattern.format(request_id=request_id)
        matches.extend([p for p in base_dir.glob(rendered) if p.is_file()])
    if not matches:
        return None
    unique = sorted(set(matches), key=_mtime, reverse=True)
    return unique[0]


def _read_json_file(path: Path) -> Tuple[JsonDict, str, str]:
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)
    except UnicodeDecodeError:
        try:
            text = path.read_text(encoding="utf-8-sig")
            data = json.loads(text)
        except Exception as exc:
            return {}, "read_error", str(exc)
    except Exception as exc:
        return {}, "read_error", str(exc)

    if isinstance(data, dict):
        return data, "found", ""
    return {"_value": data}, "found_non_object", "source json is not an object"


def _write_json_atomic(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
        text=True,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp_name, path)
    finally:
        try:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
        except OSError:
            pass


@dataclass(frozen=True)
class SourceArtifact:
    section: str
    source_path: str = ""
    source_rel_path: str = ""
    status: str = "missing"
    error: str = ""
    data: Optional[JsonDict] = None

    def to_section_document(self) -> JsonDict:
        warnings: List[str] = []
        if self.error:
            warnings.append(self.error)
        return {
            "section": self.section,
            "schema_version": SCHEMA_VERSION,
            "status": self.status,
            "source_file": self.source_path,
            "source_rel_path": self.source_rel_path,
            "captured_at": utc_now(),
            "warnings": warnings,
            "data": self.data or {},
        }

    def to_meta_ref(self) -> JsonDict:
        return {
            "section": self.section,
            "source_file": self.source_path,
            "source_rel_path": self.source_rel_path,
            "status": self.status,
            "error": self.error,
        }


def find_request_artifacts(
    request_id: str,
    *,
    base_dir: Path = DEFAULT_BASE_DIR,
) -> Dict[str, SourceArtifact]:
    """Find source artifacts for one request_id without writing anything."""
    rid = safe_request_id(request_id)
    base = Path(base_dir)
    found: Dict[str, SourceArtifact] = {}

    for section, patterns in SOURCE_PATTERNS.items():
        path = _glob_first(base, patterns, rid)
        if not path:
            found[section] = SourceArtifact(section=section)
            continue
        data, status, error = _read_json_file(path)
        found[section] = SourceArtifact(
            section=section,
            source_path=str(path),
            source_rel_path=_rel_path(path, base),
            status=status,
            error=error,
            data=data,
        )

    return found


def _first_event(normalized_event: JsonDict) -> JsonDict:
    events = normalized_event.get("events")
    if isinstance(events, list) and events and isinstance(events[0], dict):
        return events[0]
    if isinstance(normalized_event.get("event"), dict):
        return normalized_event.get("event") or {}
    return {}


def _nested(data: Mapping[str, Any], *keys: str) -> Any:
    cur: Any = data
    for key in keys:
        if not isinstance(cur, Mapping):
            return ""
        cur = cur.get(key)
    return cur if cur is not None else ""


def _family_from_plan_or_review(plan: JsonDict, review: JsonDict, analysis: JsonDict) -> str:
    candidates = [
        _nested(plan, "family_result", "family"),
        _nested(plan, "classification", "family"),
        _nested(plan, "classification", "playbook_type"),
        _nested(plan, "playbook", "playbook_id"),
        review.get("family"),
        analysis.get("family"),
    ]
    for value in candidates:
        text = _as_text(value)
        if text:
            return text
    return ""


def _classification_doc(plan: JsonDict, analysis: JsonDict, review: JsonDict) -> JsonDict:
    family = _family_from_plan_or_review(plan, review, analysis)
    return {
        "section": "classification",
        "schema_version": SCHEMA_VERSION,
        "status": "derived" if family else "missing",
        "captured_at": utc_now(),
        "source_file": "",
        "source_rel_path": "",
        "warnings": [] if family else ["family/classification not found in plan/review/analysis"],
        "data": {
            "family": family,
            "family_result": plan.get("family_result") if isinstance(plan.get("family_result"), dict) else {},
            "classification": plan.get("classification") if isinstance(plan.get("classification"), dict) else {},
            "playbook": plan.get("playbook") if isinstance(plan.get("playbook"), dict) else {},
            "analysis_status": analysis.get("analysis_status", ""),
            "review_status": review.get("review_status", ""),
        },
    }


def _alert_context_doc(raw: JsonDict, normalized: JsonDict) -> JsonDict:
    event = _first_event(normalized)
    labels = event.get("labels") if isinstance(event.get("labels"), dict) else {}
    annotations = event.get("annotations") if isinstance(event.get("annotations"), dict) else {}
    status = event.get("status") or raw.get("status") or ""
    return {
        "section": "alert_context",
        "schema_version": SCHEMA_VERSION,
        "status": "derived" if event or raw else "missing",
        "captured_at": utc_now(),
        "source_file": "",
        "source_rel_path": "",
        "warnings": [] if event or raw else ["raw/normalized alert context not found"],
        "data": {
            "source": normalized.get("source") or event.get("source") or raw.get("source") or "",
            "timestamp": event.get("timestamp") or raw.get("startsAt") or "",
            "status": status,
            "alarm_type": event.get("alarm_type") or labels.get("alertname") or "",
            "severity": event.get("severity") or labels.get("severity") or "",
            "hostname": event.get("hostname") or labels.get("hostname") or labels.get("instance") or "",
            "device_ip": event.get("device_ip") or labels.get("ip") or labels.get("device_ip") or "",
            "vendor": event.get("vendor") or labels.get("vendor") or "",
            "object_type": event.get("object_type") or labels.get("job") or labels.get("type") or "",
            "object_name": event.get("object_name") or labels.get("interface") or labels.get("name") or "",
            "summary": annotations.get("summary") or "",
            "description": annotations.get("description") or event.get("raw_text") or "",
            "generator_url": event.get("generator_url") or "",
        },
    }


def _execution_stats(device: JsonDict, review: JsonDict) -> JsonDict:
    stats = device.get("stats") if isinstance(device.get("stats"), dict) else {}
    review_stats = review.get("stats") if isinstance(review.get("stats"), dict) else {}
    command_results = device.get("command_results")
    if not isinstance(command_results, list):
        command_results = []
    return {
        "execution_status": device.get("execution_status") or stats.get("execution_status") or "",
        "total_commands": stats.get("total_commands") or stats.get("command_total") or review_stats.get("command_total") or len(command_results),
        "completed_commands": stats.get("completed_commands") or stats.get("command_completed") or review_stats.get("command_completed"),
        "failed_commands": stats.get("failed_commands") or stats.get("command_failed") or review_stats.get("command_failed"),
        "partial_commands": stats.get("partial_commands") or stats.get("command_partial") or review_stats.get("command_partial"),
        "hard_error_count": stats.get("hard_error_count") or review_stats.get("hard_error_count") or 0,
    }


def _recommendations(review: JsonDict, analysis: JsonDict) -> List[str]:
    values: Any = review.get("recommendations")
    if not values:
        values = analysis.get("recommendations")
    if isinstance(values, list):
        return [_shorten(x, 220) for x in values if _as_text(x)][:5]
    text = _as_text(values)
    return [_shorten(text, 220)] if text else []


def _judgement(review: JsonDict, analysis: JsonDict) -> str:
    for value in [
        review.get("conclusion"),
        review.get("judgement"),
        _nested(review, "final_judgement", "summary"),
        _nested(analysis, "result", "summary"),
        analysis.get("summary"),
    ]:
        text = _shorten(value, 260)
        if text:
            return text
    return ""


def _notification_summary_doc(
    request_id: str,
    alert_context: JsonDict,
    classification: JsonDict,
    metrics: JsonDict,
    device: JsonDict,
    review: JsonDict,
    analysis: JsonDict,
    detail_url: str,
) -> JsonDict:
    alert_data = alert_context.get("data") if isinstance(alert_context.get("data"), dict) else {}
    class_data = classification.get("data") if isinstance(classification.get("data"), dict) else {}
    stats = _execution_stats(device, review)
    recommendations = _recommendations(review, analysis)
    evidence_status = {
        "metrics": "found" if metrics else "missing",
        "device": "found" if device else "missing",
        "review": "found" if review else "missing",
        "analysis": "found" if analysis else "missing",
        "detail": "generated",
    }
    return {
        "section": "notification_summary",
        "schema_version": SCHEMA_VERSION,
        "status": "derived",
        "captured_at": utc_now(),
        "source_file": "",
        "source_rel_path": "",
        "warnings": [],
        "data": {
            "request_id": request_id,
            "title": "NetAIOps告警分析 - " + (_as_text(alert_data.get("alarm_type")) or _as_text(class_data.get("family")) or "未知告警"),
            "device": {
                "hostname": _as_text(alert_data.get("hostname")),
                "device_ip": _as_text(alert_data.get("device_ip")),
            },
            "object": _as_text(alert_data.get("object_name")),
            "family": _as_text(class_data.get("family")),
            "judgement": _judgement(review, analysis),
            "recommendations": recommendations[:2],
            "evidence_status": evidence_status,
            "command_stats": stats,
            "detail_url": detail_url,
        },
    }


def _git_info(base_dir: Path) -> JsonDict:
    head = base_dir / ".git" / "HEAD"
    if not head.exists():
        return {}
    return {
        "available": True,
        "note": "full git branch/commit will be added by later pipeline integration if needed",
    }


def _section_path(detail_dir: Path, section: str) -> Path:
    return detail_dir / REQUIRED_SECTION_FILES[section]


def build_evidence_detail(
    request_id: str,
    *,
    base_dir: Path = DEFAULT_BASE_DIR,
    detail_url: str = "",
    overwrite: bool = True,
) -> JsonDict:
    """Build and persist Evidence Hub detail files for one request_id.

    Returns a compact build result. The function is intentionally tolerant:
    missing source artifacts are recorded as missing section files rather than
    raising an exception.
    """
    rid = safe_request_id(request_id)
    base = Path(base_dir)
    detail_dir = request_detail_dir(rid, base_dir=base)
    artifacts = find_request_artifacts(rid, base_dir=base)

    raw_doc = artifacts["raw_payload"].to_section_document()
    normalized_doc = artifacts["normalized_event"].to_section_document()
    analysis_doc = artifacts["analysis_result"].to_section_document()
    plan_doc = artifacts["plan"].to_section_document()
    metrics_doc = artifacts["metrics_evidence"].to_section_document()
    device_doc = artifacts["device_evidence"].to_section_document()
    review_doc = artifacts["review"].to_section_document()

    raw = raw_doc.get("data") if isinstance(raw_doc.get("data"), dict) else {}
    normalized = normalized_doc.get("data") if isinstance(normalized_doc.get("data"), dict) else {}
    analysis = analysis_doc.get("data") if isinstance(analysis_doc.get("data"), dict) else {}
    plan = plan_doc.get("data") if isinstance(plan_doc.get("data"), dict) else {}
    metrics = metrics_doc.get("data") if isinstance(metrics_doc.get("data"), dict) else {}
    device = device_doc.get("data") if isinstance(device_doc.get("data"), dict) else {}
    review = review_doc.get("data") if isinstance(review_doc.get("data"), dict) else {}

    alert_context_doc = _alert_context_doc(raw, normalized)
    classification_doc = _classification_doc(plan, analysis, review)
    notification_doc = _notification_summary_doc(
        rid,
        alert_context_doc,
        classification_doc,
        metrics,
        device,
        review,
        analysis,
        detail_url,
    )

    alert_data = alert_context_doc.get("data") if isinstance(alert_context_doc.get("data"), dict) else {}
    class_data = classification_doc.get("data") if isinstance(classification_doc.get("data"), dict) else {}
    summary_data = notification_doc.get("data") if isinstance(notification_doc.get("data"), dict) else {}

    empty_detail = build_empty_detail(
        rid,
        source=_as_text(alert_data.get("source")),
        family=_as_text(class_data.get("family")),
        hostname=_as_text(alert_data.get("hostname")),
        device_ip=_as_text(alert_data.get("device_ip")),
        object_name=_as_text(alert_data.get("object_name")),
        detail_url=detail_url,
        git_info=_git_info(base),
    )

    missing_sections = [
        name for name, artifact in artifacts.items() if artifact.status == "missing"
    ]
    read_error_sections = [
        name for name, artifact in artifacts.items() if artifact.status == "read_error"
    ]

    meta_doc = {
        "section": "meta",
        "schema_version": SCHEMA_VERSION,
        "status": "generated",
        "captured_at": utc_now(),
        "data": {
            **empty_detail["meta"],
            "status": "detail_generated",
            "detail_dir": _rel_path(detail_dir, base),
            "detail_root_rel_path": str(DETAIL_ROOT_REL_PATH),
            "source_files": {k: v.to_meta_ref() for k, v in artifacts.items()},
            "missing_sections": missing_sections,
            "read_error_sections": read_error_sections,
            "build_options": {"overwrite": bool(overwrite)},
        },
    }

    section_docs: Dict[str, JsonDict] = {
        "meta": meta_doc,
        "alert_context": alert_context_doc,
        "normalized_event": normalized_doc,
        "classification": classification_doc,
        "plan": plan_doc,
        "metrics_evidence": metrics_doc,
        "device_evidence": device_doc,
        "review": review_doc,
        "analysis_result": analysis_doc,
        "notification_summary": notification_doc,
        "raw_payload": raw_doc,
    }

    files_written: Dict[str, str] = {}
    detail_dir.mkdir(parents=True, exist_ok=True)
    for section, doc in section_docs.items():
        target = _section_path(detail_dir, section)
        if target.exists() and not overwrite:
            files_written[section] = str(target)
            continue
        _write_json_atomic(target, doc)
        files_written[section] = str(target)

    index_doc = {
        "schema_version": SCHEMA_VERSION,
        "request_id": rid,
        "generated_at": utc_now(),
        "detail_dir": str(detail_dir),
        "summary": summary_data,
        "missing_sections": missing_sections,
        "read_error_sections": read_error_sections,
        "files": {section: _rel_path(Path(path), base) for section, path in files_written.items()},
    }
    _write_json_atomic(detail_dir / "summary.json", index_doc)

    return {
        "status": "ok",
        "request_id": rid,
        "detail_dir": str(detail_dir),
        "detail_dir_rel": _rel_path(detail_dir, base),
        "files_written": files_written,
        "missing_sections": missing_sections,
        "read_error_sections": read_error_sections,
        "summary": summary_data,
    }


__all__ = [
    "SOURCE_PATTERNS",
    "SourceArtifact",
    "build_evidence_detail",
    "find_request_artifacts",
]
