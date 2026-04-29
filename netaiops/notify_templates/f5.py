from typing import Any, Dict, Callable, Optional

from netaiops.notify_templates.common import render_by_fallback


def render(
    payload: Dict[str, Any],
    fallback_renderer: Optional[Callable[[Dict[str, Any]], str]] = None,
) -> str:
    # F5 pool/member 类后续可在这里单独优化 pool、member、monitor 展示。
    return render_by_fallback(payload, fallback_renderer)
