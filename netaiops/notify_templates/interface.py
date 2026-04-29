from typing import Any, Dict, Callable, Optional

from netaiops.notify_templates.common import render_by_fallback


def render(
    payload: Dict[str, Any],
    fallback_renderer: Optional[Callable[[Dict[str, Any]], str]] = None,
) -> str:
    # 接口类通知已经经过真实告警验证，当前优先保持原格式不变。
    return render_by_fallback(payload, fallback_renderer)
