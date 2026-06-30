"""Slim notification summary builder for NetAIOps Webhook v10 Batch 9.

This module prepares the compact AI-analysis notification summary that will be
used by later batches to shorten DingDong messages.

Boundaries:
- read-only: only reads Evidence Hub artifacts
- no device access
- no DingDong sending
- no FastAPI route changes
- no service restart required
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import os
import tempfile
from typing import Any, Dict, Iterable, List, Mapping, Optional

SCHEMA_VERSION = "v10.notification_summary.slim.v1"
DEFAULT_BASE_DIR = Path("/opt/netaiops-webhook")
DETAIL_ROOT_REL_PATH = Path("data/evidence_hub/requests")
SLIM_SUMMARY_FILENAME = "notification_summary_slim.json"

JsonDict = Dict[str, Any]


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _compact_text(value: Any) -> str:
    text = _as_text(value).replace("\r", " ").replace("\n", " ")
    return " ".join(text.split())


def _shorten(value: Any, limit: int) -> str:
    text = _compact_text(value)
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3] + "..."


def _first_non_empty(*values: Any) -> str:
    for value in values:
        text = _compact_text(value)
        if text:
            return text
    return ""


def _read_json(path: Path) -> JsonDict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except UnicodeDecodeError:
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:
            return {}
    except Exception:
        return {}
    return data if isinstance(data, dict) else {"_value": data}


def _section_data(doc: Mapping[str, Any]) -> JsonDict:
    data = doc.get("data") if isinstance(doc, Mapping) else {}
    return data if isinstance(data, dict) else {}


def _section_status(doc: Mapping[str, Any]) -> str:
    status = _compact_text(doc.get("status") if isinstance(doc, Mapping) else "")
    return status or "missing"


def _detail_dir(request_id: str, base_dir: Path = DEFAULT_BASE_DIR) -> Path:
    rid = _compact_text(request_id)
    if not rid or "/" in rid or "\\" in rid or rid in {".", ".."}:
        raise ValueError(f"invalid request_id: {request_id!r}")
    return Path(base_dir) / DETAIL_ROOT_REL_PATH / rid


def _load_detail_sections(request_id: str, base_dir: Path = DEFAULT_BASE_DIR) -> JsonDict:
    root = _detail_dir(request_id, base_dir=base_dir)
    return {
        "root": str(root),
        "exists": root.exists(),
        "summary_index": _read_json(root / "summary.json"),
        "meta": _read_json(root / "meta.json"),
        "notification_summary": _read_json(root / "notification_summary.json"),
        "alert_context": _read_json(root / "alert_context.json"),
        "classification": _read_json(root / "classification.json"),
        "metrics_evidence": _read_json(root / "metrics_evidence.json"),
        "device_evidence": _read_json(root / "device_evidence.json"),
        "review": _read_json(root / "review.json"),
        "analysis_result": _read_json(root / "analysis_result.json"),
    }


def _get_summary_data(sections: Mapping[str, Any]) -> JsonDict:
    notification_doc = sections.get("notification_summary") or {}
    notification_data = _section_data(notification_doc)
    if notification_data:
        return notification_data
    summary_index = sections.get("summary_index") or {}
    data = summary_index.get("summary") if isinstance(summary_index, Mapping) else {}
    return data if isinstance(data, dict) else {}


def _extract_device(summary_data: Mapping[str, Any], alert_data: Mapping[str, Any]) -> JsonDict:
    device = summary_data.get("device") if isinstance(summary_data.get("device"), dict) else {}
    hostname = _first_non_empty(device.get("hostname"), alert_data.get("hostname"))
    device_ip = _first_non_empty(device.get("device_ip"), alert_data.get("device_ip"))
    if hostname and device_ip:
        display = f"{hostname}（{device_ip}）"
    else:
        display = hostname or device_ip or "未知设备"
    return {"hostname": hostname, "device_ip": device_ip, "display": display}


def _extract_recommendations(summary_data: Mapping[str, Any], review_data: Mapping[str, Any], limit: int) -> List[str]:
    values: Any = summary_data.get("recommendations")
    if not values:
        values = review_data.get("recommendations")
    if isinstance(values, str):
        candidates = [x for x in values.splitlines() if _compact_text(x)]
    elif isinstance(values, Iterable) and not isinstance(values, (bytes, bytearray, dict)):
        candidates = list(values)
    else:
        candidates = []

    result: List[str] = []
    seen = set()
    for item in candidates:
        text = _shorten(item, 130)
        if not text:
            continue
        # Drop numeric prefixes from existing long notification recommendations.
        text = text.lstrip("0123456789.、) ）")
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
        if len(result) >= limit:
            break
    return result


def _status_label(status: str, *, success_words: Iterable[str]) -> str:
    value = _compact_text(status).lower()
    if value in {"", "missing", "not_found"}:
        return "未生成"
    for word in success_words:
        if word in value:
            return "已生成"
    if value in {"found", "derived", "generated", "ok", "success"}:
        return "已生成"
    if "error" in value or "failed" in value:
        return "异常"
    return "已生成"


def _command_stats_text(summary_data: Mapping[str, Any], device_data: Mapping[str, Any]) -> str:
    stats = summary_data.get("command_stats") if isinstance(summary_data.get("command_stats"), dict) else {}
    if not stats:
        stats = device_data.get("stats") if isinstance(device_data.get("stats"), dict) else {}
    total = _first_non_empty(stats.get("total_commands"), stats.get("command_total"))
    completed = _first_non_empty(stats.get("completed_commands"), stats.get("command_completed"))
    failed = _first_non_empty(stats.get("failed_commands"), stats.get("command_failed"))
    if total:
        return f"设备取证已完成：共 {total} 条，成功 {completed or '未知'} 条，失败 {failed or '未知'} 条"
    return "设备取证已完成"


def _evidence_summary(summary_data: Mapping[str, Any], sections: Mapping[str, Any]) -> JsonDict:
    metrics_doc = sections.get("metrics_evidence") or {}
    device_doc = sections.get("device_evidence") or {}
    review_doc = sections.get("review") or {}
    meta_doc = sections.get("meta") or {}
    device_data = _section_data(device_doc)
    meta_data = _section_data(meta_doc)

    metrics_status = _status_label(_section_status(metrics_doc), success_words=["found", "generated", "success"])
    device_status_raw = _section_status(device_doc)
    device_status = _status_label(device_status_raw, success_words=["found", "generated", "success", "completed"])
    review_status = _status_label(_section_status(review_doc), success_words=["found", "generated", "success"])
    detail_url = _first_non_empty(summary_data.get("detail_url"), meta_data.get("detail_url"))
    detail_status = "已生成" if detail_url else "未生成"

    device_text = _command_stats_text(summary_data, device_data) if device_status == "已生成" else "设备取证未生成"
    parts = [
        f"Prometheus：{metrics_status}",
        device_text,
        f"Review：{review_status}",
        f"详情页：{detail_status}",
    ]
    return {
        "metrics": metrics_status,
        "device": device_status,
        "review": review_status,
        "detail": detail_status,
        "text": "；".join(parts),
    }


def _extract_detail_url(summary_data: Mapping[str, Any], sections: Mapping[str, Any]) -> str:
    meta_doc = sections.get("meta") or {}
    meta_data = _section_data(meta_doc)
    summary_index = sections.get("summary_index") or {}
    summary_from_index = summary_index.get("summary") if isinstance(summary_index, Mapping) else {}
    if not isinstance(summary_from_index, dict):
        summary_from_index = {}
    return _first_non_empty(
        summary_data.get("detail_url"),
        meta_data.get("detail_url"),
        summary_from_index.get("detail_url"),
    )


@dataclass(frozen=True)
class SlimSummaryLimits:
    judgement_chars: int = 170
    recommendation_chars: int = 130
    max_recommendations: int = 2
    title_chars: int = 80
    object_chars: int = 80
    alert_chars: int = 120


def build_slim_notification_summary(
    request_id: str,
    *,
    base_dir: Path = DEFAULT_BASE_DIR,
    limits: Optional[SlimSummaryLimits] = None,
) -> JsonDict:
    """Build a compact notification summary from Evidence Hub artifacts.

    This function is read-only. It returns structured data and a rendered text
    preview, but does not send DingDong messages and does not mutate the
    production pipeline.
    """
    rid = _compact_text(request_id)
    limits = limits or SlimSummaryLimits()
    sections = _load_detail_sections(rid, base_dir=base_dir)
    summary_data = _get_summary_data(sections)
    alert_data = _section_data(sections.get("alert_context") or {})
    class_data = _section_data(sections.get("classification") or {})
    review_data = _section_data(sections.get("review") or {})

    device = _extract_device(summary_data, alert_data)
    family = _first_non_empty(summary_data.get("family"), class_data.get("family"), "unknown")
    title = _shorten(
        _first_non_empty(summary_data.get("title"), f"NetAIOps告警分析 - {family}"),
        limits.title_chars,
    )
    obj = _shorten(_first_non_empty(summary_data.get("object"), alert_data.get("object_name"), "未知对象"), limits.object_chars)
    alert_content = _shorten(
        _first_non_empty(alert_data.get("summary"), alert_data.get("description"), alert_data.get("alarm_type"), family),
        limits.alert_chars,
    )
    judgement = _shorten(
        _first_non_empty(summary_data.get("judgement"), review_data.get("conclusion"), "当前证据不足，请打开详情页查看完整证据。"),
        limits.judgement_chars,
    )
    recommendations = [
        _shorten(item, limits.recommendation_chars)
        for item in _extract_recommendations(summary_data, review_data, limits.max_recommendations)
    ]
    if not recommendations:
        recommendations = ["打开详情页查看完整证据，优先确认当前状态、指标趋势和设备取证结果。"]

    detail_url = _extract_detail_url(summary_data, sections)
    evidence = _evidence_summary(summary_data, sections)
    detail_available = bool(detail_url)
    if not detail_available:
        evidence["text"] = evidence["text"] + "；详情页生成失败，请按 request_id 排查"

    result: JsonDict = {
        "schema_version": SCHEMA_VERSION,
        "request_id": rid,
        "title": title,
        "device": device,
        "object": obj,
        "family": family,
        "alert_content": alert_content,
        "judgement": judgement,
        "recommendations": recommendations[: limits.max_recommendations],
        "evidence_summary": evidence,
        "detail_url": detail_url,
        "detail_available": detail_available,
        "source": "evidence_hub" if sections.get("exists") else "evidence_hub_missing",
        "limits": {
            "judgement_chars": limits.judgement_chars,
            "recommendation_chars": limits.recommendation_chars,
            "max_recommendations": limits.max_recommendations,
            "title_chars": limits.title_chars,
            "object_chars": limits.object_chars,
            "alert_chars": limits.alert_chars,
        },
        "safety": {
            "full_commands_included": False,
            "full_metrics_included": False,
            "raw_payload_included": False,
        },
    }
    result["text"] = render_slim_notification_text(result)
    return result


def render_slim_notification_text(summary: Mapping[str, Any]) -> str:
    device = summary.get("device") if isinstance(summary.get("device"), dict) else {}
    recommendations = summary.get("recommendations") if isinstance(summary.get("recommendations"), list) else []
    recommendation_lines = [f"{idx}. {_compact_text(item)}" for idx, item in enumerate(recommendations[:2], start=1) if _compact_text(item)]
    if not recommendation_lines:
        recommendation_lines = ["1. 打开详情页查看完整证据。"]

    detail_url = _compact_text(summary.get("detail_url"))
    detail_line = detail_url or f"详情页生成失败，请按 request_id 排查：{_compact_text(summary.get('request_id'))}"
    evidence = summary.get("evidence_summary") if isinstance(summary.get("evidence_summary"), dict) else {}

    lines = [
        f"标题：{_compact_text(summary.get('title')) or 'NetAIOps告警分析'}",
        f"设备：{_compact_text(device.get('display')) or '未知设备'}",
        f"对象：{_compact_text(summary.get('object')) or '未知对象'}",
        f"告警内容：{_compact_text(summary.get('alert_content')) or '无'}",
        f"判断：{_compact_text(summary.get('judgement')) or '当前证据不足，请查看详情页。'}",
        "建议：",
        *recommendation_lines,
        f"证据：{_compact_text(evidence.get('text')) or '详见 Evidence Hub'}",
        f"详情：{detail_line}",
    ]
    return "\n".join(lines)


def _write_json_atomic(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(dict(data), fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp_name, path)
    finally:
        try:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
        except OSError:
            pass


def write_slim_notification_summary(
    request_id: str,
    *,
    base_dir: Path = DEFAULT_BASE_DIR,
    output_filename: str = SLIM_SUMMARY_FILENAME,
) -> JsonDict:
    """Build and persist slim summary under one Evidence Hub request directory."""
    summary = build_slim_notification_summary(request_id, base_dir=base_dir)
    target = _detail_dir(request_id, base_dir=base_dir) / output_filename
    _write_json_atomic(target, summary)
    return {"status": "ok", "request_id": _compact_text(request_id), "output_file": str(target), "summary": summary}


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Build v10 slim notification summary preview")
    parser.add_argument("request_id")
    parser.add_argument("--base-dir", default=str(DEFAULT_BASE_DIR))
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()

    if args.write:
        result = write_slim_notification_summary(args.request_id, base_dir=Path(args.base_dir))
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        result = build_slim_notification_summary(args.request_id, base_dir=Path(args.base_dir))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        print()
        print(result.get("text", ""))


__all__ = [
    "SCHEMA_VERSION",
    "SLIM_SUMMARY_FILENAME",
    "SlimSummaryLimits",
    "build_slim_notification_summary",
    "render_slim_notification_text",
    "write_slim_notification_summary",
]


if __name__ == "__main__":
    main()
