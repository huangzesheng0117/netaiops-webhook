from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def now_utc_str() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_lite_request_id() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f") + "_" + uuid.uuid4().hex[:8]


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def pick_first(*values: Any) -> str:
    for value in values:
        text = safe_text(value)
        if text:
            return text
    return ""


def as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def merge_labels(alert: Dict[str, Any], payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload = payload or {}
    common = as_dict(payload.get("commonLabels"))
    labels = as_dict(alert.get("labels"))
    return {**common, **labels}


def merge_annotations(alert: Dict[str, Any], payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload = payload or {}
    common = as_dict(payload.get("commonAnnotations"))
    annotations = as_dict(alert.get("annotations"))
    return {**common, **annotations}


def normalize_status(alert: Dict[str, Any], payload: Optional[Dict[str, Any]] = None) -> str:
    payload = payload or {}
    status = pick_first(alert.get("status"), alert.get("state"), payload.get("status"))
    status_l = status.lower()

    labels = merge_labels(alert, payload)
    annotations = merge_annotations(alert, payload)
    restored = pick_first(alert.get("restored"), labels.get("restored"), annotations.get("restored")).lower()

    if status_l in {"resolved", "resolve", "restored"}:
        return "resolved"
    if restored in {"true", "1", "yes", "y"}:
        return "resolved"
    if status_l == "pending":
        return "pending"
    return "firing"


def status_title_word(status: str) -> str:
    if status == "resolved":
        return "恢复"
    if status == "pending":
        return "待触发"
    return "告警"


def display_status_word(status: str) -> str:
    if status == "resolved":
        return "resolved"
    if status == "pending":
        return "pending"
    return "firing"


def get_alert_name(labels: Dict[str, Any], annotations: Dict[str, Any], alert: Optional[Dict[str, Any]] = None) -> str:
    alert = alert or {}
    return pick_first(
        annotations.get("display_name"),
        annotations.get("notify_title"),
        labels.get("alertname"),
        alert.get("name"),
        annotations.get("alertname"),
        "未知告警",
    )


def get_device_ip(labels: Dict[str, Any], annotations: Dict[str, Any]) -> str:
    return pick_first(
        annotations.get("device_ip"),
        labels.get("ip"),
        labels.get("device_ip"),
        labels.get("instance"),
        labels.get("host"),
    )


def format_value_with_unit(value: Any, unit: Any) -> str:
    value_text = safe_text(value)
    unit_text = safe_text(unit)
    if not value_text:
        return ""
    if not unit_text:
        return value_text

    no_space_units = {"%", "℃", "/秒"}
    if unit_text in no_space_units:
        return f"{value_text}{unit_text}"
    return f"{value_text} {unit_text}"


def add_line(lines: List[str], label: str, value: Any) -> None:
    text = safe_text(value)
    if text:
        lines.append(f"{label}: {text}")


def add_dynamic_object_lines(lines: List[str], labels: Dict[str, Any], annotations: Dict[str, Any]) -> None:
    interfaces = safe_text(annotations.get("interfaces"))
    if interfaces:
        add_line(lines, "接口", interfaces)

    object_label = safe_text(annotations.get("object_label"))
    object_key = safe_text(annotations.get("object_label_key"))
    if object_label and object_key:
        object_value = labels.get(object_key)
        add_line(lines, object_label, object_value)

    optional_label = safe_text(annotations.get("optional_object_label"))
    optional_key = safe_text(annotations.get("optional_object_label_key"))
    if optional_label and optional_key:
        optional_value = labels.get(optional_key)
        add_line(lines, optional_label, optional_value)


def render_alert_text(alert: Dict[str, Any], payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload = payload or {}
    labels = merge_labels(alert, payload)
    annotations = merge_annotations(alert, payload)
    status = normalize_status(alert, payload)

    alert_name = get_alert_name(labels, annotations, alert)
    title = f"[network][{status_title_word(status)}] {alert_name}"

    lines: List[str] = []
    add_line(lines, "告警状态", display_status_word(status))

    description = pick_first(
        annotations.get("description"),
        annotations.get("summary"),
        labels.get("alertname"),
        alert.get("name"),
        alert_name,
    )
    add_line(lines, "告警描述", description)
    add_line(lines, "方向", annotations.get("direction"))

    device_ip = get_device_ip(labels, annotations)
    add_line(lines, "设备IP", device_ip)

    sys_name = pick_first(labels.get("sysName"), labels.get("hostname"), labels.get("device_name"))
    add_line(lines, "设备名称", sys_name)

    add_dynamic_object_lines(lines, labels, annotations)

    bandwidth = safe_text(annotations.get("bandwidth_mbps"))
    if bandwidth:
        add_line(lines, "链路带宽", f"{bandwidth} Mbps")

    value_name = safe_text(annotations.get("value_name"))
    current_value = annotations.get("current_value")
    if not safe_text(current_value):
        current_value = alert.get("value")
    value_unit = annotations.get("value_unit")
    formatted_value = format_value_with_unit(current_value, value_unit)

    # resolved 卡片不展示动态当前值字段。
    # 原因：Alertmanager resolved payload 中的 current_value 通常是 firing 时保留下来的 $value，
    # 不是恢复时刻重新查询得到的真实当前值。这里统一跳过所有由 value_name/current_value/value_unit
    # 渲染出的动态字段，例如：当前活跃连接数、当前流量、当前利用率、当前响应率、当前值等。
    if status != "resolved" and value_name and formatted_value:
        add_line(lines, value_name, formatted_value)

    add_line(lines, "持续时间", annotations.get("for_duration"))

    return {
        "title": title,
        "detail": "\n".join(lines),
        "status": status,
        "alert_name": alert_name,
        "labels": labels,
        "annotations": annotations,
    }


def extract_alerts(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    alerts = payload.get("alerts")
    if isinstance(alerts, list):
        return [item for item in alerts if isinstance(item, dict)]

    data = payload.get("data")
    if isinstance(data, dict) and isinstance(data.get("alerts"), list):
        return [item for item in data.get("alerts") if isinstance(item, dict)]

    if isinstance(payload.get("labels"), dict) or isinstance(payload.get("annotations"), dict):
        return [payload]

    return []


def build_light_notifications(payload: Dict[str, Any]) -> Dict[str, Any]:
    lite_request_id = make_lite_request_id()
    alerts = extract_alerts(payload)

    notifications: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    for index, alert in enumerate(alerts):
        rendered = render_alert_text(alert, payload)
        rendered["index"] = index

        if rendered.get("status") == "pending":
            skipped.append({
                "index": index,
                "reason": "pending_not_sent",
                "alert_name": rendered.get("alert_name"),
            })
            continue

        notifications.append(rendered)

    return {
        "ok": True,
        "lite_request_id": lite_request_id,
        "created_at": now_utc_str(),
        "alert_count": len(alerts),
        "notification_count": len(notifications),
        "skipped_count": len(skipped),
        "notifications": notifications,
        "skipped": skipped,
    }
