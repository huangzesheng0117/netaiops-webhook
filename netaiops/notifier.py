from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Mapping

from netaiops.ai_analysis_card_builder import build_ai_analysis_card
from netaiops.ai_analysis_card_sender import (
    DEFAULT_CONFIG_PATH as DEFAULT_AI_CARD_CONFIG_PATH,
    send_ai_analysis_card,
)
from netaiops.dongdong_sender import send_dongdong_message
from netaiops.notification_payload import (
    build_notification_text,
    generate_notification_payload,
)
from netaiops.notification_summary_builder import write_slim_notification_summary
from netaiops.request_summary import get_request_summary
from netaiops.settings import get_notify_settings


FINAL_EXECUTION_STATUSES = {"completed", "failed", "partial"}
FINAL_REVIEW_STATUSES = {"completed", "needs_attention", "partial"}


def _safe_lower(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _safe_bool(value: Any, default: bool = False) -> bool:
    text = _safe_lower(value)
    if not text:
        return default
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return default


def should_send_notification(request_id: str) -> bool:
    summary = get_request_summary(request_id)
    execution_status = _safe_lower(((summary.get("execution") or {}).get("status")))
    review_status = _safe_lower(((summary.get("review") or {}).get("status")))
    if execution_status not in FINAL_EXECUTION_STATUSES:
        return False
    if review_status not in FINAL_REVIEW_STATUSES:
        return False
    return True


def _settings_value(settings: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        if not key:
            continue
        value = settings.get(key) if isinstance(settings, Mapping) else None
        text = _safe_text(value)
        if text:
            return text
    return ""


def get_notification_mode(settings: Mapping[str, Any]) -> str:
    """Return text content mode: slim or full.

    DINGTALK_NOTIFICATION_MODE remains the preferred environment variable for
    Batch 10 slim/full text content. AI_NOTIFICATION_MODE is reserved by Batch
    16 for card/text transport, but legacy slim/full values remain accepted.
    """
    legacy_ai_mode = _safe_lower(os.getenv("AI_NOTIFICATION_MODE"))
    legacy_value = legacy_ai_mode if legacy_ai_mode in {"slim", "summary", "brief", "short", "full", "legacy", "long"} else ""
    value = _safe_text(
        os.getenv("DINGTALK_NOTIFICATION_MODE")
        or legacy_value
        or _settings_value(
            settings,
            "notification_mode",
            "dingtalk_notification_mode",
            "dingdong_notification_mode",
        )
        or "slim"
    ).lower()
    if value in {"full", "legacy", "long"}:
        return "full"
    return "slim"


def get_ai_delivery_mode(settings: Mapping[str, Any]) -> str:
    value = _safe_lower(
        os.getenv("AI_NOTIFICATION_MODE")
        or _settings_value(settings, "ai_notification_mode", "ai_delivery_mode")
        or "card"
    )
    if value in {"text", "legacy_text", "plain_text"}:
        return "text"
    if value in {"card", "universal_card", "universalcard"}:
        return "card"
    if value in {"slim", "summary", "brief", "short", "full", "legacy", "long"}:
        return "card"
    return "card"


def get_ai_card_config_path(settings: Mapping[str, Any]) -> str:
    return _safe_text(
        os.getenv("AI_DONGDONG_CARD_CONFIG")
        or _settings_value(settings, "ai_card_config_path")
        or DEFAULT_AI_CARD_CONFIG_PATH
    )


def get_ai_card_fallback_to_text(settings: Mapping[str, Any]) -> bool:
    env_value = os.getenv("AI_CARD_FALLBACK_TO_TEXT")
    if env_value is not None:
        return _safe_bool(env_value, True)
    return _safe_bool(settings.get("ai_card_fallback_to_text"), True)


def _title_from_payload(payload: Mapping[str, Any], request_id: str) -> str:
    return _safe_text(payload.get("title")) or f"NetAIOps AI分析结果 - {request_id}"


def build_notification_send_view(
    request_id: str,
    *,
    mode: str,
    payload: Mapping[str, Any],
    full_text: str,
) -> Dict[str, Any]:
    normalized_mode = _safe_text(mode).lower() or "slim"
    if normalized_mode == "full":
        return {
            "mode": "full",
            "title": _title_from_payload(payload, request_id),
            "text": full_text,
            "slim_summary": None,
            "slim_summary_file": "",
            "slim_error": "",
        }

    try:
        slim_result = write_slim_notification_summary(request_id)
        slim_summary = slim_result.get("summary") if isinstance(slim_result, dict) else {}
        if not isinstance(slim_summary, dict):
            slim_summary = {}
        slim_text = _safe_text(slim_summary.get("text"))
        if not slim_text:
            raise RuntimeError("slim summary text is empty")
        slim_title = _safe_text(slim_summary.get("title")) or _title_from_payload(payload, request_id)
        return {
            "mode": "slim",
            "title": slim_title,
            "text": slim_text,
            "slim_summary": slim_summary,
            "slim_summary_file": _safe_text(slim_result.get("output_file")) if isinstance(slim_result, dict) else "",
            "slim_error": "",
        }
    except Exception as exc:
        return {
            "mode": "full_fallback",
            "title": _title_from_payload(payload, request_id),
            "text": full_text,
            "slim_summary": None,
            "slim_summary_file": "",
            "slim_error": str(exc),
        }


def _artifact_dir(send_view: Mapping[str, Any]) -> Path | None:
    slim_file = _safe_text(send_view.get("slim_summary_file"))
    if not slim_file:
        return None
    path = Path(slim_file)
    if path.name != "notification_summary_slim.json" or not path.parent.is_dir():
        return None
    return path.parent


def _write_artifact(send_view: Mapping[str, Any], name: str, data: Mapping[str, Any]) -> str:
    target_dir = _artifact_dir(send_view)
    if target_dir is None:
        return ""
    target = target_dir / name
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(dict(data), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(target)
    return str(target)


def _decorate_result(
    result: Dict[str, Any],
    *,
    request_id: str,
    payload: Mapping[str, Any],
    full_text: str,
    send_view: Mapping[str, Any],
    delivery_mode: str,
) -> Dict[str, Any]:
    result["request_id"] = request_id
    result["provider"] = "dongdong"
    result["payload"] = dict(payload)
    result["text"] = send_view.get("text") or full_text
    result["full_text"] = full_text
    result["notification_mode"] = send_view.get("mode")
    result["delivery_mode"] = delivery_mode
    result["slim_summary"] = send_view.get("slim_summary")
    result["slim_summary_file"] = send_view.get("slim_summary_file")
    if send_view.get("slim_error"):
        result["slim_error"] = send_view.get("slim_error")
    return result


def _send_text(
    request_id: str,
    *,
    payload: Mapping[str, Any],
    full_text: str,
    send_view: Mapping[str, Any],
    delivery_mode: str = "text",
) -> Dict[str, Any]:
    result = send_dongdong_message(
        title=send_view.get("title") or _title_from_payload(payload, request_id),
        detail=send_view.get("text") or full_text,
    )
    return _decorate_result(
        result,
        request_id=request_id,
        payload=payload,
        full_text=full_text,
        send_view=send_view,
        delivery_mode=delivery_mode,
    )


def send_notification(request_id: str) -> Dict[str, Any]:
    settings = get_notify_settings()
    if not settings.get("enabled", False):
        return {"ok": True, "sent": False, "reason": "notify_disabled", "request_id": request_id}
    if not should_send_notification(request_id):
        return {"ok": True, "sent": False, "reason": "not_final_stage", "request_id": request_id}

    provider = str(settings.get("provider", "")).strip().lower()
    payload = generate_notification_payload(request_id)
    full_text = build_notification_text(payload)
    content_mode = get_notification_mode(settings)
    send_view = build_notification_send_view(
        request_id,
        mode=content_mode,
        payload=payload,
        full_text=full_text,
    )

    if provider != "dongdong":
        return {
            "ok": False,
            "sent": False,
            "reason": "unsupported_provider",
            "provider": provider,
            "request_id": request_id,
            "payload": payload,
            "text": send_view.get("text") or full_text,
            "full_text": full_text,
            "notification_mode": send_view.get("mode"),
            "delivery_mode": get_ai_delivery_mode(settings),
            "slim_summary": send_view.get("slim_summary"),
            "slim_summary_file": send_view.get("slim_summary_file"),
            "slim_error": send_view.get("slim_error"),
        }

    delivery_mode = get_ai_delivery_mode(settings)
    if delivery_mode == "text":
        return _send_text(
            request_id,
            payload=payload,
            full_text=full_text,
            send_view=send_view,
            delivery_mode="text",
        )

    card_result: Dict[str, Any] = {}
    card_error = ""
    card_file = ""
    card_send_result_file = ""
    try:
        slim_summary = send_view.get("slim_summary")
        if not isinstance(slim_summary, Mapping):
            raise RuntimeError("slim summary unavailable for card build")
        card = build_ai_analysis_card(slim_summary)
        card_file = _write_artifact(send_view, "ai_analysis_card.json", card)
        card_result = send_ai_analysis_card(
            card,
            config_path=get_ai_card_config_path(settings),
        )
        card_send_result_file = _write_artifact(
            send_view,
            "ai_analysis_card_send_result.json",
            card_result,
        )
        if card_result.get("ok"):
            decorated = _decorate_result(
                card_result,
                request_id=request_id,
                payload=payload,
                full_text=full_text,
                send_view=send_view,
                delivery_mode="card",
            )
            decorated["card"] = card
            decorated["card_file"] = card_file
            decorated["card_send_result_file"] = card_send_result_file
            decorated["fallback_used"] = False
            return decorated
        card_error = _safe_text(card_result.get("error") or card_result.get("business_msg") or "card send failed")
    except Exception as exc:
        card_error = str(exc)
        card_result = {"ok": False, "sent": False, "error": card_error, "transport": "universal_card"}
        card_send_result_file = _write_artifact(
            send_view,
            "ai_analysis_card_send_result.json",
            card_result,
        )

    if not get_ai_card_fallback_to_text(settings):
        result = _decorate_result(
            card_result,
            request_id=request_id,
            payload=payload,
            full_text=full_text,
            send_view=send_view,
            delivery_mode="card",
        )
        result["card_error"] = card_error
        result["card_file"] = card_file
        result["card_send_result_file"] = card_send_result_file
        result["fallback_used"] = False
        return result

    result = _send_text(
        request_id,
        payload=payload,
        full_text=full_text,
        send_view=send_view,
        delivery_mode="text_fallback",
    )
    result["card_result"] = card_result
    result["card_error"] = card_error
    result["card_file"] = card_file
    result["card_send_result_file"] = card_send_result_file
    result["fallback_used"] = True
    return result
