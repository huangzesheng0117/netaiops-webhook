"""Evidence Hub HTML UI helpers for v10 Batch 8.

Batch 8 builds on the minimal Batch 7 UI and adds basic interaction:
- richer list page actions
- request_id filtering
- copy request_id buttons
- section quick links on detail page
- JSON API shortcuts for detail / summary / metrics / device / review

Boundaries:
- server-rendered HTML only, no external JS/CSS dependencies
- read-only view over Evidence Hub files and APIs
- no device access, no DingDong sending, no data mutation
"""

from __future__ import annotations

from html import escape
from pathlib import Path
import json
from typing import Any, Dict, Iterable, Mapping
from urllib.parse import urlencode

from .detail_api import get_evidence_detail
from .list_api import get_evidence_list
from .schema import DEFAULT_BASE_DIR, safe_request_id

JsonDict = Dict[str, Any]

SECTION_TITLES: Dict[str, str] = {
    "meta": "Meta / 索引信息",
    "alert_context": "告警基本信息",
    "normalized_event": "Normalized Event",
    "classification": "Classification / Family",
    "plan": "Plan / Playbook",
    "metrics_evidence": "Prometheus Evidence",
    "device_evidence": "MCP 命令执行结果",
    "review": "Review / Analysis",
    "analysis_result": "LLM Analysis Result",
    "notification_summary": "Notification Summary",
    "raw_payload": "Raw Payload",
}

SECTION_ANCHORS: Dict[str, str] = {
    "metrics_evidence": "Prometheus",
    "device_evidence": "Device",
    "review": "Review",
    "plan": "Plan",
    "normalized_event": "Normalized",
    "raw_payload": "Raw",
}

SUPPORTED_SECTION_API: Dict[str, str] = {
    "summary": "summary",
    "metrics": "metrics",
    "device": "device",
    "review": "review",
}


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True)
        except Exception:
            return str(value)
    return str(value)


def _h(value: Any) -> str:
    return escape(_text(value), quote=True)


def _short(value: Any, limit: int = 180) -> str:
    text = _text(value).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _as_list(value: Any) -> Iterable[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def _json_pre(data: Any, *, max_chars: int = 60000) -> str:
    try:
        text = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)
    except Exception:
        text = _text(data)
    if len(text) > max_chars:
        text = text[:max_chars] + "\n... [truncated by Evidence Hub UI]"
    return f"<pre>{_h(text)}</pre>"


def _query(params: Mapping[str, Any], **updates: Any) -> str:
    merged: Dict[str, Any] = {k: v for k, v in params.items() if v not in (None, "")}
    for key, value in updates.items():
        if value in (None, ""):
            merged.pop(key, None)
        else:
            merged[key] = value
    return urlencode(merged, doseq=False)


def _copy_button(value: Any, label: str = "复制") -> str:
    text = _h(value)
    return f'<button type="button" class="copy-btn" data-copy-value="{text}">{_h(label)}</button>'


def _page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang=\"zh-CN\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>{_h(title)}</title>
  <style>
    :root {{ color-scheme: light; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif; margin: 24px; line-height: 1.55; color: #1f2937; background: #f8fafc; }}
    a {{ color: #2563eb; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .wrap {{ max-width: 1360px; margin: 0 auto; }}
    .card {{ background: white; border: 1px solid #e5e7eb; border-radius: 12px; padding: 16px 18px; margin: 14px 0; box-shadow: 0 1px 2px rgba(15, 23, 42, .05); }}
    .muted {{ color: #6b7280; font-size: 13px; }}
    .badge {{ display: inline-block; border: 1px solid #d1d5db; border-radius: 999px; padding: 2px 8px; margin: 2px 6px 2px 0; font-size: 12px; background: #f9fafb; }}
    .toolbar {{ display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin: 10px 0; }}
    .actions {{ display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid #e5e7eb; padding: 8px 6px; text-align: left; vertical-align: top; }}
    th {{ color: #374151; background: #f9fafb; position: sticky; top: 0; }}
    input {{ padding: 8px; border: 1px solid #d1d5db; border-radius: 8px; min-width: 160px; }}
    button, .btn {{ display: inline-block; padding: 7px 10px; border: 1px solid #2563eb; background: #2563eb; color: white; border-radius: 8px; cursor: pointer; font-size: 13px; }}
    .btn.secondary, button.secondary {{ border-color: #d1d5db; background: #fff; color: #374151; }}
    .btn.warning {{ border-color: #f59e0b; background: #fffbeb; color: #92400e; }}
    pre {{ white-space: pre-wrap; word-break: break-word; background: #0f172a; color: #e5e7eb; padding: 14px; border-radius: 8px; overflow-x: auto; max-height: 520px; }}
    details {{ margin: 10px 0; }}
    details.evidence-section {{ scroll-margin-top: 16px; }}
    summary {{ cursor: pointer; font-weight: 600; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 12px; }}
    .kv {{ display: grid; grid-template-columns: 140px 1fr; gap: 6px 12px; }}
    .kv div:nth-child(odd) {{ color: #6b7280; }}
    .nowrap {{ white-space: nowrap; }}
  </style>
  <script>
    function fallbackCopy(text) {{
      var ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      try {{ document.execCommand('copy'); }} catch (e) {{}}
      document.body.removeChild(ta);
    }}
    function copyEvidenceText(text, btn) {{
      if (navigator.clipboard && navigator.clipboard.writeText) {{
        navigator.clipboard.writeText(text).catch(function() {{ fallbackCopy(text); }});
      }} else {{
        fallbackCopy(text);
      }}
      if (btn) {{
        var old = btn.textContent;
        btn.textContent = '已复制';
        setTimeout(function() {{ btn.textContent = old; }}, 1200);
      }}
    }}
    function setAllEvidenceSections(openState) {{
      document.querySelectorAll('details.evidence-section').forEach(function(el) {{ el.open = openState; }});
    }}
    document.addEventListener('click', function(ev) {{
      var btn = ev.target.closest('[data-copy-value]');
      if (!btn) return;
      copyEvidenceText(btn.getAttribute('data-copy-value') || '', btn);
    }});
  </script>
</head>
<body>
<div class=\"wrap\">
{body}
</div>
</body>
</html>"""


def _filters_form(params: Mapping[str, Any]) -> str:
    def val(key: str) -> str:
        return _h(params.get(key, ""))

    return f"""
<form method=\"get\" action=\"/evidence-ui\" class=\"card\">
  <div class=\"grid\">
    <label>Request ID<br><input name=\"request_id\" value=\"{val('request_id')}\" placeholder=\"20260630_...\"></label>
    <label>设备 IP<br><input name=\"device_ip\" value=\"{val('device_ip')}\" placeholder=\"10.x.x.x\"></label>
    <label>主机名<br><input name=\"hostname\" value=\"{val('hostname')}\" placeholder=\"hostname\"></label>
    <label>Family<br><input name=\"family\" value=\"{val('family')}\" placeholder=\"family\"></label>
    <label>关键字<br><input name=\"q\" value=\"{val('q')}\" placeholder=\"interface/judgement\"></label>
    <label>Limit<br><input name=\"limit\" value=\"{val('limit') or '50'}\"></label>
    <label>Offset<br><input name=\"offset\" value=\"{val('offset') or '0'}\"></label>
  </div>
  <div class=\"toolbar\"><button type=\"submit\">筛选</button> <a class=\"btn secondary\" href=\"/evidence-ui\">清空筛选</a> <a class=\"btn secondary\" href=\"/evidence?limit=20\">JSON API</a></div>
</form>"""


def _pager(params: Mapping[str, Any], total: int, count: int, limit: int, offset: int) -> str:
    links = []
    if offset > 0:
        prev_offset = max(0, offset - limit)
        links.append(f'<a class="btn secondary" href="/evidence-ui?{_h(_query(params, offset=prev_offset))}">上一页</a>')
    if offset + count < total:
        next_offset = offset + limit
        links.append(f'<a class="btn secondary" href="/evidence-ui?{_h(_query(params, offset=next_offset))}">下一页</a>')
    if not links:
        return '<span class="muted">没有更多分页</span>'
    return " ".join(links)


def _row_actions(rid: str) -> str:
    return (
        '<div class="actions">'
        f'<a class="btn" href="/evidence-ui/{_h(rid)}">详情</a>'
        f'{_copy_button(rid, "复制ID")}'
        f'<a class="btn secondary" href="/evidence/{_h(rid)}">Full JSON</a>'
        f'<a class="btn secondary" href="/evidence/{_h(rid)}/summary">Summary</a>'
        f'<a class="btn secondary" href="/evidence/{_h(rid)}/metrics">Metrics</a>'
        f'<a class="btn secondary" href="/evidence/{_h(rid)}/device">Device</a>'
        f'<a class="btn secondary" href="/evidence/{_h(rid)}/review">Review</a>'
        '</div>'
    )


def build_evidence_index_html(
    *,
    base_dir: Path = DEFAULT_BASE_DIR,
    limit: int = 50,
    offset: int = 0,
    device_ip: str = "",
    family: str = "",
    hostname: str = "",
    request_id: str = "",
    q: str = "",
) -> str:
    """Build the Evidence Hub list page HTML."""
    data = get_evidence_list(
        base_dir=Path(base_dir),
        limit=limit,
        offset=offset,
        device_ip=device_ip,
        family=family,
        hostname=hostname,
        request_id=request_id,
        q=q,
    )
    rows = []
    for item in data.get("requests", []):
        rid = _text(item.get("request_id"))
        rows.append(
            "<tr>"
            f"<td><a href=\"/evidence-ui/{_h(rid)}\">{_h(rid)}</a><br><span class=\"muted\">{_h(item.get('updated_at'))}</span></td>"
            f"<td>{_h(item.get('hostname'))}<br><span class=\"muted\">{_h(item.get('device_ip'))}</span></td>"
            f"<td>{_h(item.get('family'))}<br><span class=\"muted\">{_h(item.get('object_name'))}</span></td>"
            f"<td>{_h(_short(item.get('judgement'), 220))}</td>"
            f"<td>{_row_actions(rid)}</td>"
            "</tr>"
        )
    if not rows:
        table = "<p class=\"muted\">暂无 Evidence Hub 详情记录。</p>"
    else:
        table = """
<table>
<thead><tr><th>Request</th><th>设备</th><th>告警对象</th><th>当前判断</th><th>操作</th></tr></thead>
<tbody>
""" + "\n".join(rows) + "\n</tbody></table>"

    params = {
        "limit": limit,
        "offset": offset,
        "device_ip": device_ip,
        "family": family,
        "hostname": hostname,
        "request_id": request_id,
        "q": q,
    }
    total = int(data.get("total") or 0)
    count = int(data.get("count") or 0)
    real_limit = int(data.get("limit") or limit)
    real_offset = int(data.get("offset") or offset)
    body = f"""
<h1>Evidence Hub</h1>
<p class=\"muted\">v10 Batch 8 前端列表页与基础交互。这里只做只读展示，不触发设备命令、不发送咚咚。</p>
{_filters_form(params)}
<div class=\"card\">
  <div class=\"toolbar\">
    <span class=\"badge\">total: {_h(total)}</span>
    <span class=\"badge\">count: {_h(count)}</span>
    <span class=\"badge\">limit: {_h(real_limit)}</span>
    <span class=\"badge\">offset: {_h(real_offset)}</span>
    {_pager(params, total, count, real_limit, real_offset)}
  </div>
  {table}
</div>
"""
    return _page("Evidence Hub", body)


def _summary_card(summary: Mapping[str, Any], request_id: str) -> str:
    device = summary.get("device") if isinstance(summary.get("device"), Mapping) else {}
    recommendations = "".join(f"<li>{_h(item)}</li>" for item in _as_list(summary.get("recommendations")))
    if not recommendations:
        recommendations = "<li class=\"muted\">暂无建议摘要</li>"
    detail_url = summary.get("detail_url")
    detail_link = '<span class="muted">未生成</span>'
    if detail_url:
        detail_link = f'<a href="{_h(detail_url)}">{_h(detail_url)}</a>'
    return f"""
<div class=\"card\">
  <div class=\"toolbar\"><a class=\"btn secondary\" href=\"/evidence-ui\">返回列表</a>{_copy_button(request_id, "复制 request_id")}<a class=\"btn secondary\" href=\"/evidence/{_h(request_id)}\">Full JSON</a></div>
  <h2>{_h(summary.get('title') or 'NetAIOps告警分析')}</h2>
  <div class=\"kv\">
    <div>request_id</div><div>{_h(request_id)}</div>
    <div>设备</div><div>{_h(device.get('hostname'))} <span class=\"muted\">{_h(device.get('device_ip'))}</span></div>
    <div>告警对象</div><div>{_h(summary.get('object'))}</div>
    <div>Family</div><div>{_h(summary.get('family'))}</div>
    <div>详情链接</div><div>{detail_link}</div>
  </div>
  <h3>当前判断</h3>
  <p>{_h(summary.get('judgement') or '暂无判断摘要')}</p>
  <h3>处理建议</h3>
  <ol>{recommendations}</ol>
</div>"""


def _status_card(summary: Mapping[str, Any]) -> str:
    evidence_status = summary.get("evidence_status") if isinstance(summary.get("evidence_status"), Mapping) else {}
    command_stats = summary.get("command_stats") if isinstance(summary.get("command_stats"), Mapping) else {}
    status_rows = "".join(
        f"<tr><td>{_h(key)}</td><td>{_h(value)}</td></tr>"
        for key, value in evidence_status.items()
    ) or "<tr><td colspan=\"2\" class=\"muted\">暂无 evidence_status</td></tr>"
    command_rows = "".join(
        f"<tr><td>{_h(key)}</td><td>{_h(value)}</td></tr>"
        for key, value in command_stats.items()
    ) or "<tr><td colspan=\"2\" class=\"muted\">暂无 command_stats</td></tr>"
    return f"""
<div class=\"grid\">
  <div class=\"card\"><h3>证据状态</h3><table>{status_rows}</table></div>
  <div class=\"card\"><h3>命令统计</h3><table>{command_rows}</table></div>
</div>"""


def _detail_toolbar(request_id: str, sections: Mapping[str, Any]) -> str:
    section_links = []
    for key, label in SECTION_ANCHORS.items():
        if key in sections:
            section_links.append(f'<a class="btn secondary" href="#section-{_h(key)}">{_h(label)}</a>')
    api_links = [f'<a class="btn secondary" href="/evidence/{_h(request_id)}/{_h(path)}">{_h(label.title())} API</a>' for label, path in SUPPORTED_SECTION_API.items()]
    return (
        '<div class="card">'
        '<div class="toolbar">'
        '<strong>分区入口：</strong>'
        + " ".join(section_links or ['<span class="muted">暂无分区</span>'])
        + '<button type="button" class="secondary" onclick="setAllEvidenceSections(true)">展开全部</button>'
        + '<button type="button" class="secondary" onclick="setAllEvidenceSections(false)">折叠全部</button>'
        + '</div><div class="toolbar"><strong>API：</strong>'
        + f'<a class="btn secondary" href="/evidence/{_h(request_id)}">Full JSON</a>'
        + " ".join(api_links)
        + '</div></div>'
    )


def _sections_card(sections: Mapping[str, Any]) -> str:
    preferred_order = [
        "metrics_evidence",
        "device_evidence",
        "review",
        "analysis_result",
        "alert_context",
        "normalized_event",
        "classification",
        "plan",
        "notification_summary",
        "raw_payload",
        "meta",
    ]
    blocks = []
    for section in preferred_order:
        if section not in sections:
            continue
        title = SECTION_TITLES.get(section, section)
        blocks.append(
            f"<details class=\"evidence-section\" id=\"section-{_h(section)}\">"
            f"<summary>{_h(title)}</summary>"
            f"{_json_pre(sections[section])}"
            "</details>"
        )
    if not blocks:
        return "<div class=\"card muted\">暂无详情分区。</div>"
    return '<div class="card"><h3>完整证据分区</h3>' + "\n".join(blocks) + "</div>"


def build_evidence_detail_html(request_id: str, *, base_dir: Path = DEFAULT_BASE_DIR) -> str:
    """Build one request detail page HTML."""
    rid = safe_request_id(request_id)
    detail = get_evidence_detail(rid, base_dir=Path(base_dir))
    summary_doc = detail.get("summary_index") if isinstance(detail.get("summary_index"), Mapping) else {}
    summary = summary_doc.get("summary") if isinstance(summary_doc.get("summary"), Mapping) else {}
    sections = detail.get("sections") if isinstance(detail.get("sections"), Mapping) else {}
    body = f"""
<h1>Evidence Detail</h1>
<p class=\"muted\">v10 Batch 8 详情页基础交互。页面只读，不触发设备命令、不发送咚咚。</p>
{_summary_card(summary, rid)}
{_status_card(summary)}
{_detail_toolbar(rid, sections)}
{_sections_card(sections)}
"""
    return _page(f"Evidence Detail - {rid}", body)


def ui_route_manifest() -> JsonDict:
    """Return UI routes for smoke tests and documentation."""
    return {
        "version": "v10.batch8.ui",
        "routes": [
            {"method": "GET", "path": "/evidence-ui", "description": "Evidence Hub list page with filters and basic actions"},
            {"method": "GET", "path": "/evidence-ui/{request_id}", "description": "Evidence Hub detail page with section quick links"},
        ],
        "boundaries": [
            "read_only",
            "no_device_commands",
            "no_dingdong_send",
            "no_data_mutation",
            "no_external_assets",
        ],
    }
