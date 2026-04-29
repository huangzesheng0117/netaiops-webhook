from typing import Any, Dict, Callable, Optional

from netaiops.notify_templates.common import render_by_fallback


def render(
    payload: Dict[str, Any],
    fallback_renderer: Optional[Callable[[Dict[str, Any]], str]] = None,
) -> str:
    # CPU/内存类后续可在这里单独优化资源指标展示。
    return render_by_fallback(payload, fallback_renderer)
