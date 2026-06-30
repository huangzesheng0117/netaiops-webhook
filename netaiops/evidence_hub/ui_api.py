"""Evidence Hub minimal HTML UI helpers for v10 Batch 7.

The UI is intentionally small and dependency-light:
- plain server-rendered HTML
- no external JavaScript or CSS assets
- read-only view over Evidence Hub API helpers
- no device access and no DingDong sending
- large JSON sections are placed in collapsible <details> blocks
"""

from __future__ import annotations

from html import escape
from pathlib import Path
import json
from typing import Any, Dict, Iterable, Mapping

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
    .wrap {{ max-width: 1280px; margin: 0 auto; }}
    .card {{ background: white; border: 1px solid #e5e7eb; border-radius: 12px; padding: 16px 18px; margin: 14px 0; box-shadow: 0 1px 2px rgba(15, 23, 42, .05); }}
    .muted {{ color: #6b7280; font-size: 13px; }}
    .badge {{ display: inline-block; border: 1px solid #d1d5db; border-radius: 999px; padding: 2px 8px; margin-right: 6px; font-size: 12px; background: #f9fafb; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid #e5e7eb; padding: 8px 6px; text-align: left; vertical-align: top; }}
    th {{ color: #374151; background: #f9fafb; }}
    input {{ padding: 8px; border: 1px solid #d1d5db; border-radius: 8px; min-width: 160px; }}
    button {{ padding: 8px 12px; border: 1px solid #2563eb; background: #2563eb; color: white; border-radius: 8px; cursor: pointer; }}
    pre {{ white-space: pre-wrap; word-break: break-word; background: #0f172a; color: #e5e7eb; padding: 14px; border-radius: 8px; overflow-x: auto; max-height: 520px; }}
    details {{ margin: 10px 0; }}
    summary {{ cursor: pointer; font-weight: 600; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px; }}
    .kv {{ display: grid; grid-template-columns: 140px 1fr; gap: 6px 12px; }}
    .kv div:nth-child(odd) {{ color: #6b7280; }}
  </style>
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
    <label>设备 IP<br><input name=\"device_ip\" value=\"{val('device_ip')}\" placeholder=\"10.x.x.x\"></label>
    <label>主机名<br><input name=\"hostname\" value=\"{val('hostname')}\" placeholder=\"hostname\"></label>
    <label>Family<br><input name=\"family\" value=\"{val('family')}\" placeholder=\"family\"></label>
    <label>关键字<br><input name=\"q\" value=\"{val('q')}\" placeholder=\"request/interface/judgement\"></label>
    <label>Limit<br><input name=\"limit\" value=\"{val('limit') or '50'}\"></label>
  </div>
  <p><button type=\"submit\">筛选</button> <a href=\"/evidence-ui\">清空筛选</a> <a href=\"/evidence?limit=20\">JSON API</a></p>
</form>"""


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
        rid = _h(item.get("request_id"))
        rows.append(
            "<tr>"
            f"<td><a href=\"/evidence-ui/{rid}\">{rid}</a><br><span class=\"muted\">{_h(item.get('updated_at'))}</span></td>"
            f"<td>{_h(item.get('hostname'))}<br><span class=\"muted\">{_h(item.get('device_ip'))}</span></td>"
            f"<td>{_h(item.get('family'))}<br><span class=\"muted\">{_h(item.get('object_name'))}</span></td>"
            f"<td>{_h(_short(item.get('judgement'), 160))}</td>"
            f"<td><a href=\"/evidence/{rid}\">JSON</a></td>"
            "</tr>"
        )
    if not rows:
        table = "<p class=\"muted\">暂无 Evidence Hub 详情记录。</p>"
    else:
        table = """
<table>
<thead><tr><th>Request</th><th>设备</th><th>告警对象</th><th>当前判断</th><th>API</th></tr></thead>
<tbody>
""" + "\n".join(rows) + "\n</tbody></table>"

    params = {
        "limit": limit,
        "device_ip": device_ip,
        "family": family,
        "hostname": hostname,
        "q": q,
    }
    body = f"""
<h1>Evidence Hub</h1>
<p class=\"muted\">v10 Batch 7 最小前端页面。这里只做只读展示，不触发设备命令、不发送咚咚。</p>
{_filters_form(params)}
<div class=\"card\">
  <span class=\"badge\">total: {_h(data.get('total'))}</span>
  <span class=\"badge\">count: {_h(data.get('count'))}</span>
  <span class=\"badge\">limit: {_h(data.get('limit'))}</span>
  <span class=\"badge\">offset: {_h(data.get('offset'))}</span>
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
        open_attr = " open" if section in {"metrics_evidence", "device_evidence", "review"} else ""
        blocks.append(
            f"<details{open_attr}><summary>{_h(title)}</summary>{_json_pre(sections.get(section))}</details>"
        )
    if not blocks:
        blocks.append("<p class=\"muted\">暂无可展示 section。</p>")
    return f"<div class=\"card\"><h3>完整证据 Section</h3>{''.join(blocks)}</div>"


def build_evidence_detail_html(request_id: str, *, base_dir: Path = DEFAULT_BASE_DIR) -> str:
    """Build one request detail page HTML."""
    rid = safe_request_id(request_id)
    detail = get_evidence_detail(rid, base_dir=Path(base_dir))
    summary_index = detail.get("summary_index") if isinstance(detail.get("summary_index"), Mapping) else {}
    summary = summary_index.get("summary") if isinstance(summary_index.get("summary"), Mapping) else {}
    sections = detail.get("sections") if isinstance(detail.get("sections"), Mapping) else {}
    missing = detail.get("missing_sections") if isinstance(detail.get("missing_sections"), list) else []
    missing_html = "".join(f"<span class=\"badge\">{_h(item)}</span>" for item in missing) or "<span class=\"muted\">无</span>"
    body = f"""
<p><a href=\"/evidence-ui\">← 返回 Evidence Hub 列表</a> · <a href=\"/evidence/{_h(rid)}\">JSON Detail API</a></p>
{_summary_card(summary, rid)}
{_status_card(summary)}
<div class=\"card\"><h3>缺失 Section</h3>{missing_html}</div>
{_sections_card(sections)}
"""
    return _page(f"Evidence Detail - {rid}", body)


def ui_route_manifest() -> JsonDict:
    return {
        "batch": "v10_batch7",
        "routes": [
            "GET /evidence-ui",
            "GET /evidence-ui/{request_id}",
        ],
    }


__all__ = [
    "build_evidence_detail_html",
    "build_evidence_index_html",
    "ui_route_manifest",
]
