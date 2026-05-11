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

# ===== v5 resolved alert text detection enhancement begin =====
# 增强 resolved 恢复告警识别：
# 部分告警平台不会把恢复状态放在 status 字段，而是放在 title / summary / annotations 中，
# 例如：[Resolved][network] 2026-05-11 16:26:05
#
# 因此这里在原 status 判断之外，增加文本特征判断，避免恢复告警继续触发 analysis / MCP / notify。

import copy as _v14_copy
import json as _v14_json
import re as _v14_re
from typing import Any as _V14Any, Dict as _V14Dict, List as _V14List, Tuple as _V14Tuple


try:
    _v14_original_filter_firing_alerts = filter_firing_alerts
except NameError:
    _v14_original_filter_firing_alerts = None


V14_RESOLVED_TEXT_PATTERNS = [
    # 只保留强恢复特征，避免普通描述中出现 resolved 单词时误杀 firing 告警。
    r"\[resolved\]",
    r"resolved\s*\]\s*\[",
    r"告警恢复",
    r"恢复告警",
    r"已恢复",
    r"恢复通知",
    r"恢复时间",
    r"恢复正常",
]


V14_FIRING_TEXT_PATTERNS = [
    r"\[firing\]",
    r"\bfiring\b",
    r"告警触发",
    r"触发告警",
    r"当前告警",
    r"严重告警",
]


def _v14_safe_text(value: _V14Any) -> str:
    if value is None:
        return ""

    if isinstance(value, (dict, list, tuple, set)):
        try:
            return _v14_json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)

    return str(value).strip()


def _v14_text_blob(obj: _V14Any, max_depth: int = 4) -> str:
    parts: _V14List[str] = []

    def walk(value: _V14Any, depth: int) -> None:
        if depth > max_depth:
            return

        if value is None:
            return

        if isinstance(value, dict):
            # 优先抓取告警状态常见字段
            for key in (
                "status",
                "state",
                "alert_status",
                "event_status",
                "title",
                "summary",
                "description",
                "message",
                "text",
                "content",
                "alarm_type",
                "alertname",
                "raw_text",
            ):
                if key in value:
                    parts.append(_v14_safe_text(value.get(key)))

            for key in (
                "labels",
                "annotations",
                "commonLabels",
                "commonAnnotations",
                "groupLabels",
            ):
                if key in value:
                    walk(value.get(key), depth + 1)

            return

        if isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item, depth + 1)
            return

        parts.append(_v14_safe_text(value))

    walk(obj, 0)

    return " ".join(x for x in parts if x)


def _v14_matches_any(patterns: _V14List[str], text: str) -> bool:
    for pattern in patterns:
        if _v14_re.search(pattern, text or "", flags=_v14_re.IGNORECASE):
            return True
    return False


def _v14_looks_resolved(obj: _V14Any) -> bool:
    text = _v14_text_blob(obj)

    if not text:
        return False

    if _v14_matches_any(V14_RESOLVED_TEXT_PATTERNS, text):
        return True

    return False


def _v14_looks_firing(obj: _V14Any) -> bool:
    text = _v14_text_blob(obj)

    if not text:
        return False

    if _v14_matches_any(V14_FIRING_TEXT_PATTERNS, text):
        return True

    return False


def _v14_filter_firing_alerts(payload: _V14Dict[str, _V14Any]) -> _V14Tuple[str, _V14Dict[str, _V14Any], _V14Dict[str, _V14Any]]:
    if not isinstance(payload, dict):
        return "pass", payload, {
            "reason": "payload_not_dict",
            "filter_version": "v14_text_detection",
            "total_alerts": 0,
            "firing_alerts": 0,
            "resolved_alerts": 0,
            "unknown_alerts": 0,
            "kept_alerts": 0,
        }

    top_status = normalize_status(payload.get("status"))
    top_looks_resolved = _v14_looks_resolved(payload)
    top_looks_firing = _v14_looks_firing(payload)

    alerts = payload.get("alerts")

    if isinstance(alerts, list):
        firing_alerts: _V14List[_V14Dict[str, _V14Any]] = []
        resolved_alerts: _V14List[_V14Dict[str, _V14Any]] = []
        unknown_alerts: _V14List[_V14Dict[str, _V14Any]] = []

        for alert in alerts:
            if not isinstance(alert, dict):
                unknown_alerts.append(alert)
                continue

            alert_status = get_alert_status(alert)
            alert_looks_resolved = _v14_looks_resolved(alert)
            alert_looks_firing = _v14_looks_firing(alert)

            if is_resolved_status(alert_status) or alert_looks_resolved:
                resolved_alerts.append(alert)
                continue

            if is_firing_status(alert_status) or alert_looks_firing:
                firing_alerts.append(alert)
                continue

            if is_resolved_status(top_status) or top_looks_resolved:
                resolved_alerts.append(alert)
                continue

            # 没有明确恢复特征时，保守放行，避免误杀真实告警。
            unknown_alerts.append(alert)

        kept_alerts = firing_alerts + unknown_alerts

        meta = {
            "reason": "",
            "filter_version": "v14_text_detection",
            "top_status": top_status,
            "top_looks_resolved": top_looks_resolved,
            "top_looks_firing": top_looks_firing,
            "total_alerts": len(alerts),
            "firing_alerts": len(firing_alerts),
            "resolved_alerts": len(resolved_alerts),
            "unknown_alerts": len(unknown_alerts),
            "kept_alerts": len(kept_alerts),
        }

        if not kept_alerts:
            meta["reason"] = "all_alerts_resolved_or_looks_resolved"
            return "skip_resolved", payload, meta

        if len(kept_alerts) != len(alerts):
            filtered = _v14_copy.deepcopy(payload)
            filtered["alerts"] = kept_alerts
            filtered["status"] = "firing"
            meta["reason"] = "mixed_payload_filtered"
            return "pass_filtered", filtered, meta

        meta["reason"] = "all_alerts_kept"
        return "pass", payload, meta

    if is_resolved_status(top_status) or top_looks_resolved:
        return "skip_resolved", payload, {
            "reason": "top_status_or_text_resolved",
            "filter_version": "v14_text_detection",
            "top_status": top_status,
            "top_looks_resolved": top_looks_resolved,
            "top_looks_firing": top_looks_firing,
            "total_alerts": 0,
            "firing_alerts": 0,
            "resolved_alerts": 0,
            "unknown_alerts": 0,
            "kept_alerts": 0,
        }

    return "pass", payload, {
        "reason": "no_alerts_array_and_not_resolved",
        "filter_version": "v14_text_detection",
        "top_status": top_status,
        "top_looks_resolved": top_looks_resolved,
        "top_looks_firing": top_looks_firing,
        "total_alerts": 0,
        "firing_alerts": 0,
        "resolved_alerts": 0,
        "unknown_alerts": 0,
        "kept_alerts": 0,
    }


if _v14_original_filter_firing_alerts is not None:
    def filter_firing_alerts(payload: _V14Dict[str, _V14Any]) -> _V14Tuple[str, _V14Dict[str, _V14Any], _V14Dict[str, _V14Any]]:
        return _v14_filter_firing_alerts(payload)
# ===== v5 resolved alert text detection enhancement end =====
