from __future__ import annotations

import copy
from typing import Any, Dict, List, Tuple


RESOLVED_STATUSES = {
    "resolved",
    "resolve",
    "recovered",
    "recovery",
    "ok",
    "normal",
    "inactive",
    "closed",
}

FIRING_STATUSES = {
    "firing",
    "fire",
    "alerting",
    "problem",
    "active",
    "critical",
    "warning",
}


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def normalize_status(value: Any) -> str:
    return safe_text(value).lower()


def get_alert_status(alert: Dict[str, Any]) -> str:
    if not isinstance(alert, dict):
        return ""

    for key in ("status", "state", "alert_status", "event_status"):
        value = normalize_status(alert.get(key))
        if value:
            return value

    labels = alert.get("labels")
    if isinstance(labels, dict):
        for key in ("status", "state", "alert_status", "alertstate"):
            value = normalize_status(labels.get(key))
            if value:
                return value

    annotations = alert.get("annotations")
    if isinstance(annotations, dict):
        for key in ("status", "state", "alert_status"):
            value = normalize_status(annotations.get(key))
            if value:
                return value

    return ""


def is_resolved_status(status: Any) -> bool:
    return normalize_status(status) in RESOLVED_STATUSES


def is_firing_status(status: Any) -> bool:
    value = normalize_status(status)

    if not value:
        return False

    if value in FIRING_STATUSES:
        return True

    if value in RESOLVED_STATUSES:
        return False

    return False


def filter_firing_alerts(payload: Dict[str, Any]) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
    """
    返回：
    action:
      - pass: 原样放行
      - pass_filtered: mixed payload，只放行 firing alerts
      - skip_resolved: 全部为 resolved，跳过分析
    filtered_payload:
      - 需要继续传给原 webhook endpoint 的 payload
    meta:
      - 统计信息
    """

    if not isinstance(payload, dict):
        return "pass", payload, {
            "reason": "payload_not_dict",
            "total_alerts": 0,
            "firing_alerts": 0,
            "resolved_alerts": 0,
        }

    top_status = normalize_status(payload.get("status"))
    alerts = payload.get("alerts")

    if isinstance(alerts, list):
        firing_alerts: List[Dict[str, Any]] = []
        resolved_alerts: List[Dict[str, Any]] = []
        unknown_alerts: List[Dict[str, Any]] = []

        for alert in alerts:
            if not isinstance(alert, dict):
                unknown_alerts.append(alert)
                continue

            alert_status = get_alert_status(alert)

            if is_resolved_status(alert_status):
                resolved_alerts.append(alert)
            elif is_firing_status(alert_status):
                firing_alerts.append(alert)
            else:
                if is_resolved_status(top_status):
                    resolved_alerts.append(alert)
                else:
                    unknown_alerts.append(alert)

        # unknown 在 top_status=firing 或 top_status 为空时保守放行，避免误杀真实告警。
        kept_alerts = firing_alerts + unknown_alerts

        meta = {
            "reason": "",
            "top_status": top_status,
            "total_alerts": len(alerts),
            "firing_alerts": len(firing_alerts),
            "resolved_alerts": len(resolved_alerts),
            "unknown_alerts": len(unknown_alerts),
            "kept_alerts": len(kept_alerts),
        }

        if not kept_alerts:
            meta["reason"] = "all_alerts_resolved"
            return "skip_resolved", payload, meta

        if len(kept_alerts) != len(alerts):
            filtered = copy.deepcopy(payload)
            filtered["alerts"] = kept_alerts
            filtered["status"] = "firing"
            meta["reason"] = "mixed_payload_filtered"
            return "pass_filtered", filtered, meta

        meta["reason"] = "all_alerts_kept"
        return "pass", payload, meta

    if is_resolved_status(top_status):
        return "skip_resolved", payload, {
            "reason": "top_status_resolved",
            "top_status": top_status,
            "total_alerts": 0,
            "firing_alerts": 0,
            "resolved_alerts": 0,
            "unknown_alerts": 0,
            "kept_alerts": 0,
        }

    return "pass", payload, {
        "reason": "no_alerts_array_and_not_resolved",
        "top_status": top_status,
        "total_alerts": 0,
        "firing_alerts": 0,
        "resolved_alerts": 0,
        "unknown_alerts": 0,
        "kept_alerts": 0,
    }
