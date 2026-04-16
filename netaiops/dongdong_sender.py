from typing import Dict, Any

import requests

from netaiops.settings import get_notify_config


def send_dongdong_message(title: str, detail: str) -> Dict[str, Any]:
    cfg = get_notify_config()

    primary_url = str(cfg.get("webhook_url", "")).strip()
    fallback_url = str(cfg.get("fallback_webhook_url", "")).strip()
    timeout = int(cfg.get("timeout", 10) or 10)
    user_ids = str(cfg.get("userIds", "")).strip()
    group_ids = str(cfg.get("groupIds", "")).strip()

    if not primary_url:
        return {
            "ok": False,
            "sent": False,
            "reason": "webhook_url_not_configured",
        }

    if not user_ids and not group_ids:
        return {
            "ok": False,
            "sent": False,
            "reason": "userIds_and_groupIds_both_empty",
        }

    data = {
        "title": title,
        "detail": detail,
    }

    if user_ids:
        data["userIds"] = user_ids
    if group_ids:
        data["groupIds"] = group_ids

    headers = {
        "Content-Type": "application/json",
    }

    try:
        r = requests.post(primary_url, headers=headers, json=data, timeout=timeout)
        return {
            "ok": r.ok,
            "sent": r.ok,
            "status_code": r.status_code,
            "url": primary_url,
            "response_text": r.text,
            "request_data": data,
        }
    except Exception as e:
        if not fallback_url:
            return {
                "ok": False,
                "sent": False,
                "reason": f"primary_request_exception: {e}",
                "request_data": data,
            }

        try:
            r = requests.post(fallback_url, headers=headers, json=data, timeout=timeout)
            return {
                "ok": r.ok,
                "sent": r.ok,
                "status_code": r.status_code,
                "url": fallback_url,
                "response_text": r.text,
                "request_data": data,
                "fallback_used": True,
            }
        except Exception as e2:
            return {
                "ok": False,
                "sent": False,
                "reason": f"fallback_request_exception: {e2}",
                "request_data": data,
            }
