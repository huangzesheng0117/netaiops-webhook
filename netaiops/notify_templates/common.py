from typing import Any, Dict, List, Callable, Optional


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def get_nested(data: Dict[str, Any], *keys: str, default: Any = "") -> Any:
    cur: Any = data or {}
    for key in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
    return cur if cur is not None else default


def get_family(payload: Dict[str, Any]) -> str:
    return safe_text(
        get_nested(payload, "target", "family")
        or get_nested(payload, "family_result", "family")
        or get_nested(payload, "review", "family")
        or get_nested(payload, "review_data", "family")
    )


def get_device(payload: Dict[str, Any]) -> str:
    return safe_text(
        get_nested(payload, "notify_view", "device")
        or get_nested(payload, "target", "device")
        or get_nested(payload, "target", "device_ip")
        or get_nested(payload, "target_scope", "device_ip")
        or "无"
    )


def get_alarm_text(payload: Dict[str, Any]) -> str:
    return safe_text(
        get_nested(payload, "notify_view", "alarm_text")
        or get_nested(payload, "alarm", "text")
        or get_nested(payload, "event", "raw_text")
        or get_nested(payload, "event", "summary")
        or get_nested(payload, "analysis", "summary")
        or get_nested(payload, "analysis_result", "summary")
        or "无"
    )


def get_analysis_process(payload: Dict[str, Any]) -> str:
    return safe_text(
        get_nested(payload, "notify_view", "analysis_process")
        or get_nested(payload, "analysis_process")
        or ""
    )


def get_recommendations(payload: Dict[str, Any]) -> str:
    return safe_text(
        get_nested(payload, "notify_view", "recommendations")
        or get_nested(payload, "recommendations")
        or ""
    )


def render_by_fallback(
    payload: Dict[str, Any],
    fallback_renderer: Optional[Callable[[Dict[str, Any]], str]] = None,
) -> str:
    if fallback_renderer:
        return fallback_renderer(payload)
    return render_minimal(payload)


def render_minimal(payload: Dict[str, Any]) -> str:
    lines: List[str] = []

    lines.append(f"设备：{get_device(payload)}")
    lines.append("")
    lines.append("告警内容：")
    lines.append(get_alarm_text(payload))

    analysis_process = get_analysis_process(payload)
    if analysis_process:
        lines.append("")
        lines.append("分析过程：")
        lines.append(analysis_process)

    recommendations = get_recommendations(payload)
    if recommendations:
        lines.append("")
        lines.append("建议：")
        lines.append(recommendations)

    return "\n".join(lines).rstrip()


def render_family_not_supported(
    payload: Dict[str, Any],
    fallback_renderer: Optional[Callable[[Dict[str, Any]], str]] = None,
) -> str:
    return render_by_fallback(payload, fallback_renderer)
