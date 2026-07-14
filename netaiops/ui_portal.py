"""Read-only frontend navigation portal for NetAIOps Webhook."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

PORTAL_VERSION = "11.1-ui-navigation-v1"

_PORTAL_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetAIOps Webhook</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f5f7fb;
      --panel: #ffffff;
      --line: #dfe5ef;
      --text: #152238;
      --muted: #667085;
      --blue: #2563eb;
      --violet: #7c3aed;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 28px;
      background:
        radial-gradient(circle at top left, #e8efff 0, transparent 38%),
        radial-gradient(circle at bottom right, #f0eaff 0, transparent 38%),
        var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
        "Microsoft YaHei", sans-serif;
    }
    main {
      width: min(920px, 100%);
    }
    header {
      margin-bottom: 22px;
      text-align: center;
    }
    h1 {
      margin: 0;
      font-size: clamp(30px, 5vw, 46px);
      letter-spacing: -0.03em;
    }
    header p {
      margin: 10px 0 0;
      color: var(--muted);
      font-size: 16px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 18px;
    }
    .card {
      display: block;
      min-height: 220px;
      padding: 28px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: rgba(255, 255, 255, 0.94);
      color: inherit;
      text-decoration: none;
      box-shadow: 0 14px 36px rgba(15, 23, 42, 0.08);
      transition: transform 160ms ease, box-shadow 160ms ease,
        border-color 160ms ease;
    }
    .card:hover {
      transform: translateY(-4px);
      box-shadow: 0 20px 44px rgba(15, 23, 42, 0.13);
    }
    .card.evidence:hover { border-color: var(--blue); }
    .card.governance:hover { border-color: var(--violet); }
    .tag {
      display: inline-block;
      margin-bottom: 36px;
      padding: 5px 10px;
      border-radius: 999px;
      font-size: 13px;
      font-weight: 700;
    }
    .evidence .tag {
      color: #1d4ed8;
      background: #dbeafe;
    }
    .governance .tag {
      color: #6d28d9;
      background: #ede9fe;
    }
    h2 {
      margin: 0 0 10px;
      font-size: 26px;
    }
    .card p {
      margin: 0;
      color: var(--muted);
      line-height: 1.65;
    }
    .enter {
      display: inline-block;
      margin-top: 24px;
      font-weight: 700;
    }
    .evidence .enter { color: var(--blue); }
    .governance .enter { color: var(--violet); }
    footer {
      margin-top: 20px;
      text-align: center;
      color: var(--muted);
      font-size: 13px;
    }
  </style>
</head>
<body>
  <main>
    <header>
      <h1>NetAIOps Webhook</h1>
      <p>请选择需要进入的只读功能页面</p>
    </header>
    <section class="grid" aria-label="功能导航">
      <a class="card evidence" href="/evidence-ui">
        <span class="tag">v10</span>
        <h2>Evidence Hub</h2>
        <p>查看单次告警分析的指标、设备取证、Review 和完整证据详情。</p>
        <span class="enter">进入 Evidence Hub →</span>
      </a>
      <a class="card governance" href="/governance-ui">
        <span class="tag">v11</span>
        <h2>Governance</h2>
        <p>查看 Incident Memory、Learning Signals、Proposals、Replay 和 Audit。</p>
        <span class="enter">进入 Governance →</span>
      </a>
    </section>
    <footer>只读导航 · 不触发 GLM、MCP、设备命令或通知</footer>
  </main>
</body>
</html>
"""


def _portal_response() -> HTMLResponse:
    return HTMLResponse(
        _PORTAL_HTML,
        headers={"Cache-Control": "no-store"},
    )


def create_ui_portal_router() -> APIRouter:
    router = APIRouter(tags=["ui-portal"])

    @router.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def ui_portal_root() -> HTMLResponse:
        return _portal_response()

    @router.get("/ui", response_class=HTMLResponse, include_in_schema=False)
    async def ui_portal_alias() -> HTMLResponse:
        return _portal_response()

    return router


router = create_ui_portal_router()

__all__ = ["PORTAL_VERSION", "create_ui_portal_router", "router"]
