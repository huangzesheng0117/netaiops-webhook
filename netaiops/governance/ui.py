"""Read-only HTML UI for NetAIOps Webhook v11 Governance.

Batch 9 adds a compact browser view over the Batch 8 Governance API service.
It renders only Governance Store summaries and records; it never calls GLM,
Prometheus MCP, Netmiko MCP, notification endpoints, or writes production data.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from html import escape
from typing import Any, Mapping
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse

from .service import (
    COLLECTION_DISPLAY_NAMES,
    GovernanceReadService,
    default_governance_service,
    normalise_collection_name,
)
from .store import COLLECTION_ID_FIELD

UI_VERSION = "11.0.0-governance-ui-v1"

ServiceFactory = Callable[[], GovernanceReadService]

_SECTION_TO_COLLECTION: Mapping[str, str] = {
    "memories": "incident_memory",
    "signals": "signals",
    "proposals": "proposals",
    "replays": "replays",
    "reports": "reports",
    "audits": "audits",
    "backfill": "backfill",
}

_SECTION_LABELS: Mapping[str, str] = {
    "memories": "Memories",
    "signals": "Signals",
    "proposals": "Proposals",
    "replays": "Replays",
    "reports": "Reports",
    "audits": "Audits",
    "backfill": "Backfill",
}

_SECTION_HELP: Mapping[str, str] = {
    "memories": "历史告警治理摘要，不展示完整 Raw Payload、设备输出或指标样本。",
    "signals": "从 Incident Memory 中检测到的平台治理信号。",
    "proposals": "只读改进建议，默认 draft，不自动修改 Skill / Playbook。",
    "replays": "离线回放 before / after 对比，不调用真实外部系统。",
    "reports": "日 / 周 / 月 Governance Learning Report。",
    "audits": "发布审计、敏感文件检查、测试和回放结果。",
    "backfill": "回填任务运行记录。",
}

_EXTERNAL_CALLS_FALSE = {
    "glm": False,
    "prometheus": False,
    "device": False,
    "notification": False,
    "production_write": False,
}


def _jsonable(value: Any) -> Any:
    try:
        json.dumps(value, ensure_ascii=False, allow_nan=False)
        return value
    except (TypeError, ValueError):
        if isinstance(value, Mapping):
            return {str(key): _jsonable(child) for key, child in value.items()}
        if isinstance(value, (list, tuple, set, frozenset)):
            return [_jsonable(child) for child in value]
        return str(value)


def _html(value: Any) -> str:
    return escape(str(value if value is not None else ""), quote=True)


def _json_pre(value: Any) -> str:
    text = json.dumps(_jsonable(value), ensure_ascii=False, indent=2, sort_keys=True)
    return f"<pre>{_html(text)}</pre>"


def _status_class(value: Any) -> str:
    status = str(value or "").strip().lower()
    if status in {"ok", "pass", "passed", "success", "completed", "ready"}:
        return "ok"
    if status in {"warning", "partial", "no_data", "not_available"}:
        return "warn"
    if status in {"blocked", "failed", "error", "regressed"}:
        return "bad"
    return "muted"


def _badge(label: Any, value: Any | None = None) -> str:
    text = str(label if value is None else f"{label}: {value}")
    return f'<span class="badge {_status_class(value if value is not None else label)}">{_html(text)}</span>'


def _first_present(data: Mapping[str, Any], names: tuple[str, ...], default: str = "") -> str:
    for name in names:
        value = data.get(name)
        if value not in (None, ""):
            return str(value)
    return default


def _record_id(collection: str, record: Mapping[str, Any]) -> str:
    id_field = COLLECTION_ID_FIELD.get(collection, "record_id")
    return str(record.get(id_field) or record.get("record_id") or record.get("request_id") or "")


def _record_title(collection: str, record: Mapping[str, Any]) -> str:
    if collection == "incident_memory":
        return _first_present(record, ("request_id", "memory_id"), "memory")
    if collection == "signals":
        return _first_present(record, ("signal_type", "signal_id"), "signal")
    if collection == "proposals":
        return _first_present(record, ("signal_type", "proposal_id"), "proposal")
    if collection == "replays":
        return _first_present(record, ("request_id", "replay_id"), "replay")
    if collection == "reports":
        return _first_present(record, ("period", "report_id"), "report")
    if collection == "audits":
        return _first_present(record, ("status", "audit_id"), "audit")
    return _record_id(collection, record) or collection


def _record_subtitle(collection: str, record: Mapping[str, Any]) -> str:
    if collection == "incident_memory":
        return " / ".join(
            item
            for item in (
                str(record.get("device", {}).get("hostname", "")) if isinstance(record.get("device"), Mapping) else "",
                str(record.get("device", {}).get("ip", "")) if isinstance(record.get("device"), Mapping) else "",
                str(record.get("family", "")),
            )
            if item
        )
    if collection == "signals":
        return f"severity={record.get('severity', '')} proposal_eligible={record.get('proposal_eligible', '')}"
    if collection == "proposals":
        return f"status={record.get('status', '')} family={record.get('affected_family', '')}"
    if collection == "replays":
        quality = record.get("quality_delta") if isinstance(record.get("quality_delta"), Mapping) else {}
        safety = record.get("safety_delta") if isinstance(record.get("safety_delta"), Mapping) else {}
        return f"quality={quality.get('outcome', '')} safety_regression={safety.get('regression', '')}"
    if collection == "reports":
        summary = record.get("summary") if isinstance(record.get("summary"), Mapping) else {}
        return f"requests={summary.get('request_count', '')} signals={summary.get('signal_count', '')}"
    if collection == "audits":
        return f"branch={record.get('branch', '')} commit={str(record.get('commit', ''))[:12]}"
    return ""


def _layout(title: str, body: str, *, active: str = "") -> str:
    nav_items = ['<a href="/governance-ui" class="home">Overview</a>']
    for section, label in _SECTION_LABELS.items():
        css = "active" if section == active else ""
        nav_items.append(f'<a class="{css}" href="/governance-ui/{section}">{_html(label)}</a>')
    nav = "\n".join(nav_items)
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_html(title)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7fb;
      --panel: #ffffff;
      --line: #e5e7eb;
      --text: #111827;
      --muted: #6b7280;
      --primary: #2563eb;
      --ok: #047857;
      --warn: #b45309;
      --bad: #b91c1c;
      --code: #0f172a;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    header {{
      padding: 18px 24px;
      background: #111827;
      color: white;
    }}
    header h1 {{ margin: 0; font-size: 22px; }}
    header p {{ margin: 6px 0 0; color: #cbd5e1; }}
    nav {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      padding: 12px 24px;
      background: var(--panel);
      border-bottom: 1px solid var(--line);
    }}
    nav a {{
      color: var(--text);
      text-decoration: none;
      padding: 7px 10px;
      border-radius: 8px;
      border: 1px solid var(--line);
      background: #fff;
      font-size: 14px;
    }}
    nav a.active, nav a:hover {{
      color: white;
      border-color: var(--primary);
      background: var(--primary);
    }}
    main {{ padding: 20px 24px 40px; max-width: 1280px; margin: 0 auto; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 14px;
      box-shadow: 0 1px 2px rgba(15, 23, 42, .04);
    }}
    .card h2, .card h3 {{ margin-top: 0; }}
    .muted {{ color: var(--muted); }}
    .badge {{
      display: inline-block;
      padding: 3px 8px;
      border-radius: 999px;
      font-size: 12px;
      margin: 2px 4px 2px 0;
      background: #eef2ff;
      color: #3730a3;
    }}
    .badge.ok {{ background: #dcfce7; color: var(--ok); }}
    .badge.warn {{ background: #fef3c7; color: var(--warn); }}
    .badge.bad {{ background: #fee2e2; color: var(--bad); }}
    .badge.muted {{ background: #f3f4f6; color: var(--muted); }}
    table {{ width: 100%; border-collapse: collapse; background: var(--panel); }}
    th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid var(--line); vertical-align: top; }}
    th {{ font-size: 13px; color: var(--muted); background: #f9fafb; }}
    a {{ color: var(--primary); }}
    pre {{
      white-space: pre-wrap;
      word-break: break-word;
      background: var(--code);
      color: #e5e7eb;
      padding: 12px;
      border-radius: 10px;
      overflow-x: auto;
    }}
    .toolbar {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }}
    .pill {{ padding: 6px 8px; border: 1px solid var(--line); border-radius: 999px; background: #fff; }}
  </style>
</head>
<body>
  <header>
    <h1>NetAIOps Governance UI</h1>
    <p>v11 read-only governance views · no GLM / MCP / notification calls</p>
  </header>
  <nav>{nav}</nav>
  <main>{body}</main>
</body>
</html>"""


def _section_card(section: str, total: Any, corrupt: Any = 0) -> str:
    label = _SECTION_LABELS.get(section, section)
    help_text = _SECTION_HELP.get(section, "")
    return f"""
    <div class="card">
      <h3><a href="/governance-ui/{section}">{_html(label)}</a></h3>
      <p class="muted">{_html(help_text)}</p>
      <p>{_badge("total", total)} {_badge("corrupt", corrupt)}</p>
    </div>
    """


def _dashboard(service: GovernanceReadService) -> HTMLResponse:
    health = service.health()
    summary = service.summary()
    collections = health.get("collections") if isinstance(health.get("collections"), Mapping) else {}
    cards = []
    for section, collection in _SECTION_TO_COLLECTION.items():
        values = collections.get(collection) if isinstance(collections.get(collection), Mapping) else {}
        cards.append(_section_card(section, values.get("total", 0), values.get("corrupt_count", 0)))
    external_calls = health.get("external_calls") if isinstance(health.get("external_calls"), Mapping) else {}
    body = f"""
    <div class="card">
      <h2>Overview</h2>
      <p>
        {_badge("status", health.get("status"))}
        {_badge("read_only", health.get("read_only"))}
        {_badge("schema", health.get("schema_version"))}
        {_badge("ui", UI_VERSION)}
      </p>
      <p class="muted">Governance root: {_html(health.get("root"))}</p>
      <p>{_badge("total_records", summary.get("total_records", 0))} {_badge("corrupt_total", health.get("corrupt_total", 0))}</p>
      <h3>External calls</h3>
      <p>{" ".join(_badge(name, value) for name, value in sorted(external_calls.items()))}</p>
    </div>
    <div class="grid">{''.join(cards)}</div>
    """
    return HTMLResponse(_layout("Governance Overview", body))


def _render_table(section: str, collection: str, payload: Mapping[str, Any]) -> str:
    items = payload.get("items") if isinstance(payload.get("items"), list) else []
    rows = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        rid = _record_id(collection, item)
        link = f"/governance-ui/{section}/{quote(rid, safe='')}" if rid else "#"
        title = _record_title(collection, item)
        subtitle = _record_subtitle(collection, item)
        created = item.get("created_at", "")
        flags = item.get("quality_flags") if isinstance(item.get("quality_flags"), list) else []
        rows.append(
            "<tr>"
            f'<td><a href="{_html(link)}">{_html(title)}</a><br><span class="muted">{_html(rid)}</span></td>'
            f"<td>{_html(subtitle)}</td>"
            f"<td>{_html(created)}</td>"
            f"<td>{''.join(_badge(flag) for flag in flags[:6])}</td>"
            "</tr>"
        )
    if not rows:
        rows.append('<tr><td colspan="4" class="muted">No records found.</td></tr>')
    return f"""
    <table>
      <thead><tr><th>Record</th><th>Summary</th><th>Created At</th><th>Flags</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
    """


def _section_page(
    service: GovernanceReadService,
    section: str,
    *,
    page: int,
    page_size: int,
    descending: bool,
) -> HTMLResponse:
    if section not in _SECTION_TO_COLLECTION:
        raise HTTPException(status_code=400, detail=f"unsupported governance UI section: {section}")
    collection = _SECTION_TO_COLLECTION[section]
    payload = service.list_records(collection, page=page, page_size=page_size, descending=descending)
    label = _SECTION_LABELS[section]
    body = f"""
    <div class="card">
      <h2>{_html(label)}</h2>
      <p class="muted">{_html(_SECTION_HELP.get(section, ""))}</p>
      <div class="toolbar">
        <span class="pill">page={_html(payload.get("page"))}</span>
        <span class="pill">page_size={_html(payload.get("page_size"))}</span>
        <span class="pill">total={_html(payload.get("total"))}</span>
        <span class="pill">corrupt={_html(payload.get("corrupt_count"))}</span>
        <a class="pill" href="/governance/{_html(section)}">JSON API</a>
      </div>
    </div>
    {_render_table(section, collection, payload)}
    """
    return HTMLResponse(_layout(f"Governance {label}", body, active=section))


def _detail_page(service: GovernanceReadService, section: str, record_id: str) -> HTMLResponse:
    if section not in _SECTION_TO_COLLECTION:
        raise HTTPException(status_code=400, detail=f"unsupported governance UI section: {section}")
    collection = _SECTION_TO_COLLECTION[section]
    try:
        payload = service.get_record(collection, record_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    data = payload.get("data") if isinstance(payload.get("data"), Mapping) else {}
    label = _SECTION_LABELS[section]
    title = _record_title(collection, data) if isinstance(data, Mapping) else record_id
    body = f"""
    <div class="card">
      <h2>{_html(label)} Detail</h2>
      <p>
        <a href="/governance-ui/{section}">← Back to {_html(label)}</a>
        · <a href="/governance/{section}/{quote(record_id, safe='')}">JSON API</a>
      </p>
      <p>{_badge("record_id", record_id)} {_badge("read_only", payload.get("read_only"))}</p>
      <h3>{_html(title)}</h3>
    </div>
    <div class="card">
      <h3>Record JSON</h3>
      {_json_pre(data)}
    </div>
    """
    return HTMLResponse(_layout(f"Governance {label} Detail", body, active=section))


def create_governance_ui_router(
    service_factory: ServiceFactory = default_governance_service,
) -> APIRouter:
    router = APIRouter(tags=["governance-ui"])

    def service() -> GovernanceReadService:
        return service_factory()

    @router.get("/governance-ui", response_class=HTMLResponse)
    async def governance_ui_index() -> HTMLResponse:
        return _dashboard(service())

    @router.get("/governance-ui/", response_class=HTMLResponse)
    async def governance_ui_index_slash() -> HTMLResponse:
        return _dashboard(service())

    @router.get("/governance-ui/{section}", response_class=HTMLResponse)
    async def governance_ui_section(
        section: str,
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=500),
        descending: bool = True,
    ) -> HTMLResponse:
        return _section_page(
            service(),
            section,
            page=page,
            page_size=page_size,
            descending=descending,
        )

    @router.get("/governance-ui/{section}/{record_id}", response_class=HTMLResponse)
    async def governance_ui_detail(section: str, record_id: str) -> HTMLResponse:
        return _detail_page(service(), section, record_id)

    return router


router = create_governance_ui_router()

__all__ = ["UI_VERSION", "create_governance_ui_router", "router"]
