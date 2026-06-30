from typing import Any, Dict, Mapping
import os

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
    """Return v10 AI notification mode.

    Supported values:
    - slim / summary / brief: send Batch 9 slim text
    - full / legacy: send original long text

    Batch 10 defaults to slim so the AI analysis DingDong notification uses the
    Evidence Hub detail link instead of embedding full commands and metrics.
    """
    value = _safe_text(
        os.getenv("DINGTALK_NOTIFICATION_MODE")
        or os.getenv("AI_NOTIFICATION_MODE")
        or _settings_value(
            settings,
            "notification_mode",
            "dingtalk_notification_mode",
            "dingdong_notification_mode",
            "ai_notification_mode",
        )
        or "slim"
    ).lower()

    if value in {"full", "legacy", "long"}:
        return "full"
    if value in {"slim", "summary", "brief", "short", "card_ready"}:
        return "slim"
    return "slim"


def _title_from_payload(payload: Mapping[str, Any], request_id: str) -> str:
    return _safe_text(payload.get("title")) or f"NetAIOps AI分析结果 - {request_id}"


def build_notification_send_view(
    request_id: str,
    *,
    mode: str,
    payload: Mapping[str, Any],
    full_text: str,
) -> Dict[str, Any]:
    """Build the final text/title sent to DingDong.

    This function is deliberately isolated for unit tests. It does not send
    DingDong messages. Slim mode writes notification_summary_slim.json under
    Evidence Hub; failures fall back to full text and must not block notify.
    """
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
        # Safety boundary: slim summary failure cannot block AI notification.
        return {
            "mode": "full_fallback",
            "title": _title_from_payload(payload, request_id),
            "text": full_text,
            "slim_summary": None,
            "slim_summary_file": "",
            "slim_error": str(exc),
        }


def send_notification(request_id: str) -> Dict[str, Any]:
    settings = get_notify_settings()

    if not settings.get("enabled", False):
        return {
            "ok": True,
            "sent": False,
            "reason": "notify_disabled",
            "request_id": request_id,
        }

    if not should_send_notification(request_id):
        return {
            "ok": True,
            "sent": False,
            "reason": "not_final_stage",
            "request_id": request_id,
        }

    provider = str(settings.get("provider", "")).strip().lower()
    payload = generate_notification_payload(request_id)
    full_text = build_notification_text(payload)
    mode = get_notification_mode(settings)
    send_view = build_notification_send_view(
        request_id,
        mode=mode,
        payload=payload,
        full_text=full_text,
    )

    if provider == "dongdong":
        result = send_dongdong_message(
            title=send_view.get("title") or payload.get("title", f"NetAIOps AI分析结果 - {request_id}"),
            detail=send_view.get("text") or full_text,
        )
        result["request_id"] = request_id
        result["provider"] = "dongdong"
        result["payload"] = payload
        result["text"] = send_view.get("text") or full_text
        result["full_text"] = full_text
        result["notification_mode"] = send_view.get("mode")
        result["slim_summary"] = send_view.get("slim_summary")
        result["slim_summary_file"] = send_view.get("slim_summary_file")
        if send_view.get("slim_error"):
            result["slim_error"] = send_view.get("slim_error")
        return result

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
        "slim_summary": send_view.get("slim_summary"),
        "slim_summary_file": send_view.get("slim_summary_file"),
        "slim_error": send_view.get("slim_error"),
    }
