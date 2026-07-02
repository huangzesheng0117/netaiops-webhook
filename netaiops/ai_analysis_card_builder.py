from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence
from urllib.parse import urlparse


CARD_SCHEMA_VERSION = "v10.ai_analysis_card.v1"
CARD_TYPE = "universal_card"
DEFAULT_HEADER_TEMPLATE = "default"
DEFAULT_DATA_ROOT = Path("data")

FORBIDDEN_FULL_EVIDENCE_KEYS = {
    "command_results",
    "commands",
    "completed_commands",
    "failed_commands",
    "prometheus_metrics",
    "metrics",
    "query_range",
    "raw_payload",
    "raw",
    "device_evidence",
    "metrics_evidence",
    "full_evidence",
}

FIELD_LIMITS = {
    "title": 120,
    "status": 24,
    "device": 160,
    "object": 160,
    "alert_content": 360,
    "judgement": 420,
    "recommendation": 360,
    "evidence_summary": 320,
}


class CardBuildError(ValueError):
    """Raised when a slim summary cannot be converted into a safe card."""


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        for key in ("text", "content", "summary", "value", "name"):
            candidate = value.get(key)
            if candidate not in (None, ""):
                return _as_text(candidate)
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return "；".join(_as_text(item) for item in value if _as_text(item))
    return str(value)


def _clean_text(value: Any) -> str:
    text = _as_text(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [" ".join(line.split()) for line in text.split("\n")]
    return "\n".join(line for line in lines if line).strip()


def _trim(value: Any, limit: int) -> str:
    text = _clean_text(value)
    if len(text) <= limit:
        return text
    if limit <= 1:
        return text[:limit]
    return text[: limit - 1].rstrip() + "…"


def _first(mapping: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, "", [], {}):
            return value
    return ""


def _nested_first(mapping: Mapping[str, Any], paths: Iterable[Sequence[str]]) -> Any:
    for path in paths:
        current: Any = mapping
        ok = True
        for key in path:
            if not isinstance(current, Mapping) or key not in current:
                ok = False
                break
            current = current[key]
        if ok and current not in (None, "", [], {}):
            return current
    return ""


def _normalize_status(summary: Mapping[str, Any]) -> str:
    value = _first(summary, "alert_status", "status", "state")
    if not value:
        value = _nested_first(
            summary,
            (
                ("alert", "status"),
                ("alert_context", "status"),
                ("normalized_event", "status"),
            ),
        )
    text = _clean_text(value).lower()
    mapping = {
        "firing": "告警中",
        "resolved": "已恢复",
        "active": "告警中",
        "recovered": "已恢复",
    }
    return mapping.get(text, text or "未知")


def _normalize_device(summary: Mapping[str, Any]) -> str:
    device = summary.get("device")
    hostname = _first(summary, "hostname", "device_name", "sys_name")
    device_ip = _first(summary, "device_ip", "ip", "instance")

    if isinstance(device, Mapping):
        hostname = hostname or _first(device, "hostname", "device_name", "name", "sys_name")
        device_ip = device_ip or _first(device, "device_ip", "ip", "address")
    elif device not in (None, ""):
        raw_device = _clean_text(device)
        if raw_device:
            return _trim(raw_device, FIELD_LIMITS["device"])

    hostname_text = _clean_text(hostname)
    ip_text = _clean_text(device_ip)
    if hostname_text and ip_text:
        return _trim(f"{hostname_text}（{ip_text}）", FIELD_LIMITS["device"])
    return _trim(hostname_text or ip_text or "未知设备", FIELD_LIMITS["device"])


def _normalize_object(summary: Mapping[str, Any]) -> str:
    value = _first(
        summary,
        "object",
        "object_name",
        "alert_object",
        "interface",
        "link",
        "target",
    )
    if isinstance(value, Mapping):
        value = _first(value, "name", "interface", "object_name", "value")
    return _trim(value or "未指定", FIELD_LIMITS["object"])


def _normalize_recommendations(summary: Mapping[str, Any]) -> List[str]:
    value = _first(
        summary,
        "recommendations",
        "recommendation",
        "suggestions",
        "suggestion",
        "advice",
    )
    if isinstance(value, Mapping):
        value = _first(value, "items", "recommendations", "text", "summary")

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        items = [_trim(item, FIELD_LIMITS["recommendation"]) for item in value]
    else:
        text = _clean_text(value)
        if not text:
            items = []
        else:
            raw_lines = [line.strip(" -•\t") for line in text.split("\n")]
            items = [_trim(line, FIELD_LIMITS["recommendation"]) for line in raw_lines if line]

    unique: List[str] = []
    for item in items:
        if item and item not in unique:
            unique.append(item)
    return unique[:3]


def _normalize_detail_url(summary: Mapping[str, Any]) -> str:
    value = _first(summary, "detail_url", "detail_link", "url")
    if not value:
        value = _nested_first(
            summary,
            (
                ("data", "detail_url"),
                ("summary", "detail_url"),
                ("meta", "detail_url"),
            ),
        )
    url = _clean_text(value)
    if not url:
        return ""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return url


def _normalize_evidence_summary(summary: Mapping[str, Any]) -> str:
    value = _first(
        summary,
        "evidence_summary",
        "evidence",
        "evidence_status",
        "evidence_overview",
    )
    if isinstance(value, Mapping):
        preferred = _first(value, "summary", "text", "overview")
        if preferred:
            value = preferred
        else:
            parts: List[str] = []
            for key in ("prometheus", "device", "review", "detail"):
                item = value.get(key)
                if item not in (None, "", [], {}):
                    parts.append(f"{key}: {_clean_text(item)}")
            value = "；".join(parts)
    return _trim(value or "详情页已生成，可查看完整证据。", FIELD_LIMITS["evidence_summary"])


def normalize_slim_summary(summary: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(summary, Mapping):
        raise CardBuildError("summary must be a mapping")

    title = _first(summary, "title", "alert_title", "alert_name", "alertname")
    alert_content = _first(
        summary,
        "alert_content",
        "description",
        "alert_description",
        "content",
        "message",
    )
    judgement = _first(
        summary,
        "judgement",
        "current_judgement",
        "assessment",
        "analysis",
        "conclusion",
    )

    normalized = {
        "request_id": _clean_text(_first(summary, "request_id", "id")),
        "title": _trim(title or "NetAIOps 告警分析", FIELD_LIMITS["title"]),
        "alert_status": _trim(_normalize_status(summary), FIELD_LIMITS["status"]),
        "device": _normalize_device(summary),
        "alert_object": _normalize_object(summary),
        "alert_content": _trim(alert_content or "未提供告警内容", FIELD_LIMITS["alert_content"]),
        "judgement": _trim(judgement or "当前证据不足，建议查看详情页。", FIELD_LIMITS["judgement"]),
        "recommendations": _normalize_recommendations(summary),
        "evidence_summary": _normalize_evidence_summary(summary),
        "detail_url": _normalize_detail_url(summary),
    }

    if not normalized["recommendations"]:
        normalized["recommendations"] = ["请查看详情页中的完整证据后再进行处置。"]
    return normalized


def _field(label: str, value: str) -> Dict[str, str]:
    return {"label": label, "value": value}


def _div(label: str, value: str) -> Dict[str, Any]:
    return {
        "tag": "div",
        "text": {
            "tag": "plain_text",
            "content": f"{label}：{value}",
        },
    }


def _action(detail_url: str) -> Optional[Dict[str, Any]]:
    if not detail_url:
        return None
    return {
        "tag": "action",
        "actions": [
            {
                "tag": "button",
                "text": {"tag": "plain_text", "content": "查看详情"},
                "type": "default",
                "url": detail_url,
            }
        ],
    }


def _contains_forbidden_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).strip().lower() in FORBIDDEN_FULL_EVIDENCE_KEYS:
                return True
            if _contains_forbidden_key(child):
                return True
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(_contains_forbidden_key(item) for item in value)
    return False


def build_ai_analysis_card(
    summary: Mapping[str, Any],
    *,
    header_template: str = DEFAULT_HEADER_TEMPLATE,
) -> Dict[str, Any]:
    normalized = normalize_slim_summary(summary)
    recommendation_text = "\n".join(
        f"{index}. {item}"
        for index, item in enumerate(normalized["recommendations"], start=1)
    )

    fields = [
        _field("告警状态", normalized["alert_status"]),
        _field("设备", normalized["device"]),
        _field("告警对象", normalized["alert_object"]),
        _field("告警内容", normalized["alert_content"]),
        _field("当前判断", normalized["judgement"]),
        _field("处理建议", recommendation_text),
        _field("证据摘要", normalized["evidence_summary"]),
    ]
    if normalized["detail_url"]:
        fields.append(_field("详情链接", normalized["detail_url"]))

    elements: List[Dict[str, Any]] = [
        _div(item["label"], item["value"])
        for item in fields
        if item["value"]
    ]
    action = _action(normalized["detail_url"])
    if action:
        elements.append(action)

    card = {
        "schema_version": CARD_SCHEMA_VERSION,
        "card_type": CARD_TYPE,
        "request_id": normalized["request_id"],
        "title": normalized["title"],
        "header": {
            "template": _clean_text(header_template) or DEFAULT_HEADER_TEMPLATE,
            "title": normalized["title"],
        },
        "fields": fields,
        "universal_card": {
            "header": {
                "template": _clean_text(header_template) or DEFAULT_HEADER_TEMPLATE,
                "title": {
                    "tag": "plain_text",
                    "content": normalized["title"],
                },
            },
            "elements": elements,
        },
        "meta": {
            "source_schema_version": _clean_text(summary.get("schema_version")),
            "detail_available": bool(normalized["detail_url"]),
            "full_evidence_embedded": False,
        },
    }

    if _contains_forbidden_key(card):
        raise CardBuildError("card contains forbidden full-evidence keys")
    return card


def load_slim_summary_file(path: Path | str) -> Dict[str, Any]:
    target = Path(path)
    if not target.is_file():
        raise CardBuildError(f"summary file not found: {target}")
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CardBuildError(f"cannot read summary file: {target}: {exc}") from exc
    if not isinstance(value, dict):
        raise CardBuildError("summary JSON root must be an object")
    return value


def slim_summary_path(request_id: str, data_root: Path | str = DEFAULT_DATA_ROOT) -> Path:
    rid = _clean_text(request_id)
    if not rid or "/" in rid or "\\" in rid or rid in {".", ".."}:
        raise CardBuildError("invalid request_id")
    return Path(data_root) / "evidence_hub" / "requests" / rid / "notification_summary_slim.json"


def build_ai_analysis_card_from_request(
    request_id: str,
    *,
    data_root: Path | str = DEFAULT_DATA_ROOT,
    header_template: str = DEFAULT_HEADER_TEMPLATE,
) -> Dict[str, Any]:
    summary = load_slim_summary_file(slim_summary_path(request_id, data_root))
    return build_ai_analysis_card(summary, header_template=header_template)


def write_card_preview(card: Mapping[str, Any], output_path: Path | str) -> Path:
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(dict(card), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return target


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a local AI analysis universal-card preview without sending it."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--summary-file", help="Path to notification_summary_slim.json")
    source.add_argument("--request-id", help="Evidence Hub request_id")
    parser.add_argument("--data-root", default=str(DEFAULT_DATA_ROOT))
    parser.add_argument("--header-template", default=DEFAULT_HEADER_TEMPLATE)
    parser.add_argument("--output", help="Optional JSON preview output path")
    parser.add_argument("--compact", action="store_true", help="Print compact JSON")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    try:
        if args.summary_file:
            summary = load_slim_summary_file(args.summary_file)
            card = build_ai_analysis_card(summary, header_template=args.header_template)
        else:
            card = build_ai_analysis_card_from_request(
                args.request_id,
                data_root=args.data_root,
                header_template=args.header_template,
            )
    except CardBuildError as exc:
        raise SystemExit(f"[FAIL] {exc}") from exc

    if args.output:
        write_card_preview(card, args.output)
    if args.compact:
        print(json.dumps(card, ensure_ascii=False, separators=(",", ":")))
    else:
        print(json.dumps(card, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
