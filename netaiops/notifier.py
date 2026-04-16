from typing import Any, Dict

from netaiops.dongdong_sender import send_dongdong_message
from netaiops.notification_payload import (
    build_notification_text,
    generate_notification_payload,
)
from netaiops.request_summary import get_request_summary
from netaiops.settings import get_notify_settings


FINAL_EXECUTION_STATUSES = {"completed", "failed", "partial"}
FINAL_REVIEW_STATUSES = {"completed", "needs_attention", "partial"}


def _safe_lower(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def should_send_notification(request_id: str) -> bool:
    summary = get_request_summary(request_id)

    execution_status = _safe_lower(((summary.get("execution") or {}).get("status")))
    review_status = _safe_lower(((summary.get("review") or {}).get("status")))

    if execution_status not in FINAL_EXECUTION_STATUSES:
        return False

    if review_status not in FINAL_REVIEW_STATUSES:
        return False

    return True


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
    text = build_notification_text(payload)

    if provider == "dongdong":
        result = send_dongdong_message(
            title=payload.get("title", f"NetAIOps AI分析结果 - {request_id}"),
            detail=text,
        )
        result["request_id"] = request_id
        result["provider"] = "dongdong"
        result["payload"] = payload
        result["text"] = text
        return result

    return {
        "ok": False,
        "sent": False,
        "reason": "unsupported_provider",
        "provider": provider,
        "request_id": request_id,
        "payload": payload,
        "text": text,
    }
