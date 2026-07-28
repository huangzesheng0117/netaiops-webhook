"""Read-only HTML UI for v12 Agent Trace observability."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from html import escape
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse

from .api import (
    AgentTraceCorruptError,
    AgentTraceReadError,
    AgentTraceReadService,
    default_agent_trace_service,
)


AGENT_UI_VERSION = "12.0-agent-trace-ui-v1"
TraceServiceFactory = Callable[[], AgentTraceReadService]


def _html(value: Any) -> str:
    return escape(
        str(value if value is not None else ""),
        quote=True,
    )


def _status_class(value: Any) -> str:
    status = str(value or "").strip().lower()
    if status in {"success", "completed", "ready", "ok"}:
        return "ok"
    if status in {
        "partial",
        "not_available",
        "no_data",
        "skipped",
        "warning",
        "not_persisted",
    }:
        return "warn"
    if status in {
        "failed",
        "blocked",
        "insufficient",
        "error",
        "timed_out",
    }:
        return "bad"
    return "muted"


def _badge(label: Any, value: Any | None = None) -> str:
    shown = label if value is None else f"{label}: {value}"
    target = label if value is None else value
    return (
        f'<span class="badge {_status_class(target)}">'
        f"{_html(shown)}</span>"
    )


def _refs(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return '<span class="muted">none</span>'
    return "<br>".join(
        f"<code>{_html(value)}</code>" for value in values
    )


def _list(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return '<span class="muted">none</span>'
    return "<ul>" + "".join(
        f"<li>{_html(value)}</li>" for value in values
    ) + "</ul>"


def _layout(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_html(title)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f3f6fb;
      --panel: #ffffff;
      --line: #dfe6ef;
      --text: #142033;
      --muted: #667085;
      --primary: #047857;
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
      font-family: -apple-system, BlinkMacSystemFont,
        "Segoe UI", "Microsoft YaHei", sans-serif;
    }}
    header {{
      padding: 20px 26px;
      color: white;
      background: linear-gradient(120deg, #064e3b, #047857);
    }}
    header h1 {{ margin: 0; font-size: 24px; }}
    header p {{ margin: 7px 0 0; color: #d1fae5; }}
    nav {{
      display: flex;
      gap: 9px;
      flex-wrap: wrap;
      padding: 12px 26px;
      background: white;
      border-bottom: 1px solid var(--line);
    }}
    nav a {{
      padding: 7px 10px;
      color: var(--text);
      text-decoration: none;
      border: 1px solid var(--line);
      border-radius: 8px;
    }}
    nav a.active, nav a:hover {{
      color: white;
      border-color: var(--primary);
      background: var(--primary);
    }}
    main {{
      width: min(1500px, 100%);
      margin: 0 auto;
      padding: 22px 26px 42px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 14px;
    }}
    .card {{
      margin-bottom: 16px;
      padding: 16px;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 14px;
      box-shadow: 0 2px 8px rgba(15, 23, 42, .05);
    }}
    .card h2, .card h3 {{ margin-top: 0; }}
    .badge {{
      display: inline-block;
      margin: 2px 4px 2px 0;
      padding: 4px 9px;
      border-radius: 999px;
      color: #334155;
      background: #e2e8f0;
      font-size: 12px;
    }}
    .badge.ok {{ color: var(--ok); background: #d1fae5; }}
    .badge.warn {{ color: var(--warn); background: #fef3c7; }}
    .badge.bad {{ color: var(--bad); background: #fee2e2; }}
    .muted {{ color: var(--muted); }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: white;
    }}
    th, td {{
      padding: 10px;
      text-align: left;
      vertical-align: top;
      border-bottom: 1px solid var(--line);
    }}
    th {{
      color: var(--muted);
      font-size: 13px;
      background: #f8fafc;
    }}
    code {{
      color: #d1fae5;
      background: var(--code);
      padding: 2px 5px;
      border-radius: 5px;
      word-break: break-all;
    }}
    ul {{ margin: 5px 0; padding-left: 20px; }}
    a {{ color: var(--primary); }}
    .toolbar {{
      display: flex;
      gap: 10px;
      align-items: center;
      flex-wrap: wrap;
      margin-bottom: 14px;
    }}
    input {{
      min-width: 260px;
      padding: 8px 10px;
      border: 1px solid var(--line);
      border-radius: 8px;
    }}
    button {{
      padding: 8px 12px;
      color: white;
      background: var(--primary);
      border: 0;
      border-radius: 8px;
      cursor: pointer;
    }}
  </style>
</head>
<body>
  <header>
    <h1>NetAIOps Agent Trace</h1>
    <p>v12 read-only execution, evidence, Judge and RCA observability</p>
  </header>
  <nav>
    <a href="/">Home</a>
    <a href="/evidence-ui">Evidence Hub</a>
    <a href="/governance-ui">Governance</a>
    <a class="active" href="/agent-ui">Agent Trace</a>
  </nav>
  <main>{body}</main>
</body>
</html>"""


def _list_page(
    service: AgentTraceReadService,
    *,
    limit: int,
    offset: int,
    status: str,
    q: str,
) -> HTMLResponse:
    result = service.list_traces(
        limit=limit,
        offset=offset,
        status=status,
        q=q,
    )
    rows = []
    for item in result["items"]:
        request_id = str(item["request_id"])
        href = "/agent-ui/" + quote(request_id, safe="")
        rows.append(
            "<tr>"
            f'<td><a href="{href}">{_html(request_id)}</a></td>'
            f"<td>{_badge(item['final_state'])}</td>"
            f"<td>{_html(item['agent_count'])}</td>"
            f"<td>{_badge(item['judge_status'])}</td>"
            f"<td>{_badge(item['rca_status'])}</td>"
            f"<td>{_html(item['elapsed_ms'])}</td>"
            f"<td>{_html(item['fallback_to_legacy'])}</td>"
            "</tr>"
        )
    if not rows:
        rows.append(
            '<tr><td colspan="7" class="muted">'
            "No v12 Agent Trace artifacts found.</td></tr>"
        )
    body = f"""
    <div class="card">
      <h2>Agent Trace Requests</h2>
      <p class="muted">
        只显示状态、引用和受控摘要；不展示完整日志、命令输出、
        Prometheus 样本或 Raw Payload。
      </p>
      <form class="toolbar" method="get" action="/agent-ui">
        <input name="q" value="{_html(q)}"
          placeholder="request_id / state / status">
        <input name="status" value="{_html(status)}"
          placeholder="status">
        <button type="submit">Search</button>
        {_badge("total", result["total"])}
        {_badge("corrupt", result["corrupt_count"])}
      </form>
      <table>
        <thead><tr>
          <th>Request ID</th><th>Final State</th><th>Agents</th>
          <th>Judge</th><th>RCA</th><th>Elapsed ms</th>
          <th>Fallback</th>
        </tr></thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    </div>
    """
    return HTMLResponse(
        _layout("Agent Trace", body),
        headers={"Cache-Control": "no-store"},
    )


def _detail_page(
    service: AgentTraceReadService,
    request_id: str,
) -> HTMLResponse:
    detail = service.get_trace(request_id)
    run_rows = []
    for run in detail["agent_runs"]:
        run_rows.append(
            "<tr>"
            f"<td>{_html(run['order'])}</td>"
            f"<td>{_html(run['agent_name'])}</td>"
            f"<td>{_badge(run['status'])}</td>"
            f"<td>{_html(run['duration_ms'])}</td>"
            f"<td>{_refs(run['inputs_ref'])}</td>"
            f"<td>{_refs(run['outputs_ref'])}</td>"
            f"<td>{_list(run['error_categories'])}</td>"
            "</tr>"
        )
    evidence_rows = []
    for source in detail["evidence_sources"]:
        evidence_rows.append(
            "<tr>"
            f"<td>{_html(source['source'])}</td>"
            f"<td>{_badge(source['status'])}</td>"
            f"<td>{_html(source['reason'])}</td>"
            f"<td>{_html(source['ref_count'])}</td>"
            f"<td>{_refs(source['evidence_refs'])}</td>"
            "</tr>"
        )

    judge = detail.get("judge")
    if isinstance(judge, Mapping):
        conflict_rows = []
        for conflict in judge["conflicts"]:
            conflict_rows.append(
                "<tr>"
                f"<td>{_html(conflict['statement'])}</td>"
                f"<td>{_badge(conflict['severity'])}</td>"
                f"<td>{_refs(conflict['evidence_refs'])}</td>"
                "</tr>"
            )
        conflict_body = "".join(conflict_rows)
        if not conflict_body:
            conflict_body = (
                '<tr><td colspan="3" class="muted">none</td></tr>'
            )
        judge_html = f"""
        <p>
          {_badge("status", judge["status"])}
          {_badge("rca_allowed", judge["rca_allowed"])}
          {_badge("confidence_cap", judge["confidence_cap"])}
        </p>
        <div class="grid">
          <div><h3>Missing required</h3>
            {_list(judge["missing_required_sources"])}</div>
          <div><h3>Missing optional</h3>
            {_list(judge["missing_optional_sources"])}</div>
        </div>
        <h3>Conflicts</h3>
        <table><thead><tr><th>Conflict</th><th>Severity</th>
          <th>Evidence refs</th></tr></thead>
          <tbody>{conflict_body}</tbody></table>
        """
    else:
        judge_html = '<p class="muted">judge_result.json not persisted.</p>'

    rca = detail.get("rca")
    if isinstance(rca, Mapping):
        candidate_rows = []
        for index, candidate in enumerate(rca["candidates"], start=1):
            candidate_rows.append(
                "<tr>"
                f"<td>{index}</td>"
                f"<td>{_html(candidate['statement'])}</td>"
                f"<td>{_html(candidate['confidence'])}</td>"
                f"<td>{_refs(candidate['supporting_evidence_refs'])}</td>"
                f"<td>{_refs(candidate['contradicting_evidence_refs'])}</td>"
                f"<td>{_list(candidate['missing_evidence'])}</td>"
                f"<td>{_list(candidate['uncertainties'])}</td>"
                "</tr>"
            )
        candidate_body = "".join(candidate_rows)
        if not candidate_body:
            candidate_body = (
                '<tr><td colspan="7" class="muted">none</td></tr>'
            )
        rca_html = f"""
        <p>{_badge("status", rca["status"])}
          {_badge("provider", rca["provider"])}</p>
        <table><thead><tr>
          <th>#</th><th>Candidate</th><th>Confidence</th>
          <th>Supporting refs</th><th>Contradicting refs</th>
          <th>Missing evidence</th><th>Uncertainties</th>
        </tr></thead><tbody>{candidate_body}</tbody></table>
        """
    else:
        rca_html = '<p class="muted">rca_result.json not persisted.</p>'

    shadow = detail.get("shadow")
    if isinstance(shadow, Mapping):
        shadow_html = f"""
        <p>
          {_badge("status", shadow["status"])}
          {_badge("legacy_preserved", shadow["legacy_preserved"])}
          {_badge("fail_open", shadow["fail_open_to_legacy"])}
          {_badge("notification_delta",
            shadow["notification_count_delta"])}
          {_badge("second_card", shadow["second_card_sent"])}
          {_badge("card_replaced",
            shadow["production_card_replaced"])}
        </p>
        """
    else:
        shadow_html = (
            '<p class="muted">shadow_integration.json not persisted.</p>'
        )

    run_body = "".join(run_rows)
    evidence_body = "".join(evidence_rows)
    if not evidence_body:
        evidence_body = (
            '<tr><td colspan="5" class="muted">none</td></tr>'
        )
    boundaries = detail["data_boundaries"]
    body = f"""
    <div class="card">
      <h2>{_html(detail["request_id"])}</h2>
      <p>
        {_badge("final_state", detail["final_state"])}
        {_badge("fallback_to_legacy", detail["fallback_to_legacy"])}
        {_badge("elapsed_ms", detail["elapsed_ms"])}
        {_badge("stop_reason", detail["stop_reason"])}
      </p>
    </div>
    <div class="card">
      <h2>Agent execution order</h2>
      <table><thead><tr>
        <th>#</th><th>Agent</th><th>Status</th><th>Duration ms</th>
        <th>inputs_ref</th><th>outputs_ref</th>
        <th>Error categories</th>
      </tr></thead><tbody>{run_body}</tbody></table>
    </div>
    <div class="card">
      <h2>Evidence source status</h2>
      <table><thead><tr>
        <th>Source</th><th>Status</th><th>Reason</th>
        <th>Ref count</th><th>Evidence refs</th>
      </tr></thead><tbody>{evidence_body}</tbody></table>
    </div>
    <div class="card"><h2>Evidence Judge</h2>{judge_html}</div>
    <div class="card"><h2>RCA candidates</h2>{rca_html}</div>
    <div class="card"><h2>Shadow / fallback</h2>{shadow_html}</div>
    <div class="card">
      <h2>Artifact references</h2>{_refs(detail["artifact_refs"])}
    </div>
    <div class="card">
      <h2>Data boundaries</h2>
      <p>
        {_badge("full_logs_exposed", boundaries["full_logs_exposed"])}
        {_badge("full_device_output_exposed",
          boundaries["full_device_output_exposed"])}
        {_badge("full_metrics_exposed",
          boundaries["full_metrics_exposed"])}
        {_badge("raw_payload_exposed",
          boundaries["raw_payload_exposed"])}
      </p>
    </div>
    """
    return HTMLResponse(
        _layout(f"Agent Trace {detail['request_id']}", body),
        headers={"Cache-Control": "no-store"},
    )


def _translate_error(exc: Exception) -> HTTPException:
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, AgentTraceCorruptError):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, AgentTraceReadError):
        return HTTPException(status_code=500, detail=str(exc))
    return HTTPException(
        status_code=500,
        detail=f"{type(exc).__name__}: {exc}",
    )


def create_agent_trace_ui_router(
    service_factory: TraceServiceFactory = default_agent_trace_service,
) -> APIRouter:
    router = APIRouter(tags=["agent-trace-ui"])

    @router.get(
        "/agent-ui",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    async def agent_trace_index(
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
        status: str = "",
        q: str = "",
    ) -> HTMLResponse:
        try:
            return _list_page(
                service_factory(),
                limit=limit,
                offset=offset,
                status=status,
                q=q,
            )
        except Exception as exc:
            raise _translate_error(exc) from exc

    @router.get(
        "/agent-ui/{request_id}",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    async def agent_trace_request(
        request_id: str,
    ) -> HTMLResponse:
        try:
            return _detail_page(service_factory(), request_id)
        except Exception as exc:
            raise _translate_error(exc) from exc

    return router


router = create_agent_trace_ui_router()


__all__ = [
    "AGENT_UI_VERSION",
    "create_agent_trace_ui_router",
    "router",
]
