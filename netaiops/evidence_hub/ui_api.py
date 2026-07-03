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

    /* BATCH13_5_HUMAN_READABLE_UI_CSS_START */
    .human-note {{ margin: 10px 0 14px 0; padding: 12px 14px; border: 1px solid #d8e4ff; border-left: 4px solid #2563eb; border-radius: 10px; background: #f6f9ff; color: #172033; line-height: 1.75; }}
    .human-note strong {{ font-weight: 700; }}
    .human-note .muted, .human-note + .muted {{ color: #667085; }}
    .human-note ul {{ margin: 6px 0 0 22px; padding: 0; }}
    .human-note li {{ margin: 3px 0; }}
    .evidence-table {{ margin: 10px 0 18px 0; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden; }}
    .evidence-table th, .evidence-table td {{ font-size: 13px; vertical-align: top; }}
    .evidence-table code {{ background: #f3f4f6; padding: 2px 4px; border-radius: 4px; }}
    .metrics-table th, .metrics-table td {{ white-space: nowrap; }}
    .kv {{ grid-template-columns: 140px 1fr; }}

    /* BATCH13_7_RAW_OUTPUT_CSS_START */
    .raw-output-pre {{ white-space: pre; word-break: normal; overflow: auto; max-height: 720px; min-width: 320px; width: 100%; box-sizing: border-box; line-height: 1.5; tab-size: 4; resize: horizontal; }}
    .raw-output-pre code {{ white-space: inherit; }}
    /* BATCH13_7_RAW_OUTPUT_CSS_END */

    /* BATCH13_8_RAW_OUTPUT_INTERACTION_CSS_START */
    .command-table-shell {{ --raw-output-width: 48%; margin: 10px 0 22px 0; border: 1px solid #e5e7eb; border-radius: 10px; background: #fff; overflow: hidden; }}
    .command-table-toolbar {{ display: flex; align-items: center; justify-content: flex-end; gap: 8px; flex-wrap: wrap; padding: 8px 10px; border-bottom: 1px solid #e5e7eb; background: #f8fafc; }}
    .command-table-toolbar label {{ display: inline-flex; align-items: center; gap: 8px; font-size: 12px; color: #475569; }}
    .command-table-toolbar input[type="range"] {{ width: 180px; min-width: 0; padding: 0; }}
    .command-output-width-value {{ display: inline-block; min-width: 38px; text-align: right; font-variant-numeric: tabular-nums; }}
    .command-table-scroll {{ overflow-x: auto; }}
    .command-evidence-table {{ table-layout: fixed; min-width: 1180px; margin: 0; border: 0; }}
    .command-evidence-table .col-order {{ width: 56px; }}
    .command-evidence-table .col-status {{ width: 76px; }}
    .command-evidence-table .col-command {{ width: 21%; }}
    .command-evidence-table .col-reason {{ width: auto; }}
    .command-evidence-table .col-output {{ width: var(--raw-output-width); }}
    .command-evidence-table td {{ overflow-wrap: anywhere; }}
    .command-evidence-table td.raw-output-cell {{ overflow: visible; }}
    .raw-output-details {{ min-width: 320px; }}
    .raw-output-toolbar {{ display: flex; justify-content: flex-end; align-items: center; gap: 8px; margin: 8px 0 6px 0; }}
    .raw-output-copy {{ padding: 5px 9px; font-size: 12px; }}
    .raw-output-copy-source {{ min-width: 0; }}
    /* BATCH13_8_RAW_OUTPUT_INTERACTION_CSS_END */
    /* BATCH13_5_HUMAN_READABLE_UI_CSS_END */
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
    function setCommandOutputWidth(control) {{
      var shell = control.closest('.command-table-shell');
      if (!shell) return;
      var value = Math.max(35, Math.min(78, parseInt(control.value || '48', 10)));
      shell.style.setProperty('--raw-output-width', value + '%');
      var valueNode = shell.querySelector('.command-output-width-value');
      if (valueNode) valueNode.textContent = value + '%';
    }}
    function setCommandOutputWidthPreset(button) {{
      var shell = button.closest('.command-table-shell');
      if (!shell) return;
      var control = shell.querySelector('.command-output-width');
      if (!control) return;
      control.value = button.getAttribute('data-width') || '48';
      setCommandOutputWidth(control);
    }}
    document.addEventListener('input', function(ev) {{
      var control = ev.target.closest('.command-output-width');
      if (control) setCommandOutputWidth(control);
    }});
    document.addEventListener('click', function(ev) {{
      var rawCopy = ev.target.closest('[data-copy-target]');
      if (rawCopy) {{
        ev.preventDefault();
        ev.stopPropagation();
        var target = document.getElementById(rawCopy.getAttribute('data-copy-target') || '');
        if (target) copyEvidenceText(target.textContent || '', rawCopy);
        return;
      }}
      var preset = ev.target.closest('.command-output-width-preset');
      if (preset) {{
        ev.preventDefault();
        setCommandOutputWidthPreset(preset);
        return;
      }}
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



# BATCH13_5_HUMAN_READABLE_HELPERS_START
# Frontend-only human-readable helpers. These functions only change HTML rendering.
# They do not mutate Evidence Hub stored data and do not trigger device commands or DingDong sending.
def _batch135_status_label(value: Any) -> str:
    v = _text(value).strip().lower()
    if v in {"found", "generated", "ok", "present", "true", "success"}:
        return '<span class="badge">已生成</span>'
    if v in {"missing", "not_found", "false", "none", "", "no_data"}:
        return '<span class="badge warning">缺失/未生成</span>'
    if v in {"error", "fail", "failed", "exception"}:
        return '<span class="badge warning">异常</span>'
    return _h(value or "未知")


def _batch135_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _batch135_data(section_doc: Any) -> Any:
    if isinstance(section_doc, Mapping):
        return section_doc.get("data") if "data" in section_doc else section_doc
    return section_doc


def _batch135_device_fields(summary: Mapping[str, Any]) -> Dict[str, str]:
    device = summary.get("device") if isinstance(summary.get("device"), Mapping) else {}
    hostname = _text(device.get("hostname") or device.get("device_name") or summary.get("hostname") or "")
    device_ip = _text(device.get("device_ip") or device.get("ip") or summary.get("device_ip") or "")
    return {"hostname": hostname, "device_ip": device_ip}


def _batch135_detail_url(summary: Mapping[str, Any], request_id: str) -> str:
    detail_url = _text(summary.get("detail_url") or "").strip()
    if detail_url:
        return detail_url
    return f"/evidence-ui/{request_id}"


def _batch135_evidence_status_sentence(evidence_status: Mapping[str, Any]) -> str:
    if not evidence_status:
        return "当前详情页没有读取到证据状态汇总，建议展开下方完整证据分区查看原始 JSON。"
    parts = []
    labels = {
        "analysis": "AI 分析结果",
        "detail": "详情页索引",
        "metrics": "Prometheus 指标证据",
        "device": "设备取证结果",
        "review": "Review 复核结果",
    }
    for key, label in labels.items():
        if key in evidence_status:
            value = _text(evidence_status.get(key))
            if value in {"found", "generated", "ok", "present"}:
                parts.append(f"{label}已生成")
            elif value in {"missing", "not_found", ""}:
                parts.append(f"{label}缺失")
            else:
                parts.append(f"{label}状态为 {value}")
    if not parts:
        for key, value in evidence_status.items():
            parts.append(f"{key}={_text(value)}")
    return "；".join(parts) + "。"


def _batch135_command_stats_sentence(command_stats: Mapping[str, Any]) -> str:
    if not command_stats:
        return "当前详情页没有读取到命令统计。若该告警不需要设备取证，这可能是正常现象。"
    total = _batch135_int(command_stats.get("total_commands"))
    completed = _batch135_int(command_stats.get("completed_commands"))
    failed = _batch135_int(command_stats.get("failed_commands"))
    partial = _batch135_int(command_stats.get("partial_commands"))
    hard_error = _batch135_int(command_stats.get("hard_error_count"))
    status = _text(command_stats.get("execution_status") or "未知")
    if total <= 0:
        return f"本次没有执行设备侧命令，执行状态为 {status}。"
    if failed == 0 and hard_error == 0:
        return f"本次计划执行 {total} 条设备只读命令，已完成 {completed} 条，未发现失败命令，执行状态为 {status}。"
    return (
        f"本次计划执行 {total} 条设备只读命令，已完成 {completed} 条，失败 {failed} 条，"
        f"部分成功 {partial} 条，硬错误 {hard_error} 条，执行状态为 {status}。"
        "失败命令不会影响详情页展示，但排障时应优先展开 MCP 命令执行结果查看失败原因。"
    )


def _batch135_command_counts(section_doc: Any) -> Dict[str, int]:
    data = _batch135_data(section_doc)
    commands = []
    if isinstance(data, Mapping):
        for key in ("commands", "results", "command_results", "items"):
            if isinstance(data.get(key), list):
                commands = data.get(key) or []
                break
        if not commands and isinstance(data.get("execution"), Mapping):
            execution = data.get("execution")
            for key in ("commands", "results", "command_results"):
                if isinstance(execution.get(key), list):
                    commands = execution.get(key) or []
                    break
    total = len(commands)
    success = 0
    failed = 0
    for item in commands:
        if not isinstance(item, Mapping):
            continue
        status = _text(item.get("status") or item.get("result") or item.get("state")).lower()
        ok = item.get("success")
        if ok is True or status in {"success", "ok", "completed", "done"}:
            success += 1
        elif ok is False or status in {"failed", "fail", "error", "exception", "timeout"}:
            failed += 1
    return {"total": total, "success": success, "failed": failed}


def _batch135_section_note(section: str, section_doc: Any) -> str:
    status = ""
    if isinstance(section_doc, Mapping):
        status = _text(section_doc.get("status") or "")
    data = _batch135_data(section_doc)
    title = SECTION_TITLES.get(section, section)
    body = ""
    if section == "metrics_evidence":
        if status == "missing":
            body = "本次没有生成 Prometheus 指标证据。常见原因包括该 family 暂未配置 PromQL、测试告警没有对应时间序列，或历史样本缺少指标文件。"
        else:
            body = "本区展示 Prometheus 指标侧证据，用于确认告警窗口内的指标走势、阈值命中情况和取证时间点。"
    elif section == "device_evidence":
        counts = _batch135_command_counts(section_doc)
        if counts["total"]:
            body = f"本区展示 MCP/设备侧只读命令取证结果。本区共解析到 {counts['total']} 条命令记录，其中成功 {counts['success']} 条，失败 {counts['failed']} 条。"
        else:
            body = "本区展示 MCP/设备侧只读命令取证结果。当前未解析到标准命令列表，建议直接查看下方原始 JSON。"
    elif section == "review":
        body = "本区展示 Review / Analysis 复核结果，用于说明最终判断、建议和证据充分性。"
    elif section == "analysis_result":
        body = "本区展示 LLM 分析结果，主要用于追溯模型如何根据告警、指标和设备证据形成判断。"
    elif section == "alert_context":
        body = "本区展示告警基础上下文，包括告警名称、设备、接口、labels/annotations 等归一化前后的关键信息。"
    elif section == "normalized_event":
        body = "本区展示 Normalized Event，即系统把原始 Alertmanager payload 标准化后的事件结构。"
    elif section == "classification":
        body = "本区展示告警分类 / Family 识别结果，用于确认本次告警进入了哪类 playbook 或分析分支。"
    elif section == "plan":
        body = "本区展示 Plan / Playbook 计划，包括本次计划取哪些证据、是否允许自动执行只读命令等。"
    elif section == "notification_summary":
        body = "本区展示 Batch 10 生成的短文本通知摘要，用于对应 AI 分析群里看到的瘦身版咚咚通知。"
    elif section == "raw_payload":
        body = "本区保留原始 Alertmanager payload，便于追溯最初输入。该部分通常较长，排障时一般最后查看。"
    elif section == "meta":
        body = "本区展示 Evidence Hub 索引元数据，包括 request_id、生成时间、detail_url、缺失分区等。"
    else:
        body = f"本区展示 {title} 的原始证据内容。"
    return (
        '<div class="human-note">'
        f'<strong>人类可读解读：</strong>{_h(body)}'
        f'<div class="muted">原始状态：{_h(status or "未知")}；下方仍完整保留原始 JSON。</div>'
        '</div>'
    )
# BATCH13_5_HUMAN_READABLE_HELPERS_END



def _summary_card(summary: Mapping[str, Any], request_id: str) -> str:
    device_fields = _batch135_device_fields(summary)
    recommendations = "".join(f"<li>{_h(item)}</li>" for item in _as_list(summary.get("recommendations")))
    if not recommendations:
        recommendations = "<li class=\"muted\">暂无建议摘要</li>"
    detail_url = _batch135_detail_url(summary, request_id)
    detail_link = f'<a href="{_h(detail_url)}">{_h(detail_url)}</a>'
    if not summary.get("detail_url"):
        detail_link += '<br><span class="muted">后端 summary/meta 未写入 detail_url，前端按当前 request_id 补偿展示。</span>'
    return f"""
<div class=\"card\">
  <div class=\"toolbar\"><a class=\"btn secondary\" href=\"/evidence-ui\">返回列表</a>{_copy_button(request_id, "复制 request_id")}<a class=\"btn secondary\" href=\"/evidence/{_h(request_id)}\">Full JSON</a></div>
  <h2>{_h(summary.get('title') or 'NetAIOps告警分析')}</h2>
  <div class=\"kv\">
    <div>request_id</div><div>{_h(request_id)}</div>
    <div>设备名称</div><div>{_h(device_fields.get('hostname'))}</div>
    <div>设备IP</div><div>{_h(device_fields.get('device_ip'))}</div>
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
        f"<tr><td>{_h(key)}</td><td>{_batch135_status_label(value)}</td><td>{_h(value)}</td></tr>"
        for key, value in evidence_status.items()
    ) or "<tr><td colspan=\"3\" class=\"muted\">暂无 evidence_status</td></tr>"
    command_rows = "".join(
        f"<tr><td>{_h(key)}</td><td>{_h(value)}</td></tr>"
        for key, value in command_stats.items()
    ) or "<tr><td colspan=\"2\" class=\"muted\">暂无 command_stats</td></tr>"
    return f"""
<div class=\"grid\">
  <div class=\"card\">
    <h3>证据状态</h3>
    <div class=\"human-note\"><strong>工程师可读摘要：</strong>{_h(_batch135_evidence_status_sentence(evidence_status))}</div>
    <table><thead><tr><th>证据项</th><th>人工解释</th><th>原始状态</th></tr></thead><tbody>{status_rows}</tbody></table>
  </div>
  <div class=\"card\">
    <h3>命令统计</h3>
    <div class=\"human-note\"><strong>工程师可读摘要：</strong>{_h(_batch135_command_stats_sentence(command_stats))}</div>
    <table>{command_rows}</table>
  </div>
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




# BATCH13_6_READABLE_TABLES_START
# Frontend-only readable tables for command evidence and Prometheus evidence.
# These helpers only render already persisted Evidence Hub JSON. They never execute commands.
def _batch136_bool_ok(value: Any) -> bool:
    if value is True:
        return True
    v = _text(value).strip().lower()
    return v in {"ok", "true", "success", "completed", "done", "pass", "passed"}


def _batch136_is_failed(value: Any) -> bool:
    if value is False:
        return True
    v = _text(value).strip().lower()
    return v in {"failed", "fail", "error", "exception", "timeout", "hard_error", "blocked"}


def _batch136_command_results(section_doc: Any) -> list[Any]:
    data = _batch135_data(section_doc)
    candidates = []
    if isinstance(data, Mapping):
        candidates.extend([data.get("command_results"), data.get("commands"), data.get("results"), data.get("items")])
        execution = data.get("execution")
        if isinstance(execution, Mapping):
            candidates.extend([execution.get("command_results"), execution.get("commands"), execution.get("results"), execution.get("items")])
    for item in candidates:
        if isinstance(item, list):
            return item
    return []


def _batch136_cmd_status(item: Mapping[str, Any]) -> str:
    status = _text(item.get("dispatch_status") or item.get("status") or item.get("result") or item.get("state") or "")
    if not status:
        if item.get("success") is True:
            return "completed"
        if item.get("success") is False:
            return "failed"
    return status or "unknown"


def _batch136_cmd_status_label(item: Mapping[str, Any]) -> str:
    status = _batch136_cmd_status(item)
    if _batch136_bool_ok(status) or item.get("success") is True:
        return '<span class="badge">成功</span>'
    if _batch136_is_failed(status) or item.get("success") is False:
        return '<span class="badge warning">失败</span>'
    return f'<span class="badge warning">{_h(status or "未知")}</span>'


def _batch136_cmd_failure_reason(item: Mapping[str, Any]) -> str:
    judge = item.get("judge") if isinstance(item.get("judge"), Mapping) else {}
    parsed = item.get("parsed") if isinstance(item.get("parsed"), Mapping) else {}
    reason_parts = []
    for source in (item, judge, parsed):
        if not isinstance(source, Mapping):
            continue
        for key in ("error", "failure_reason", "reason", "summary", "message", "error_message"):
            value = _text(source.get(key)).strip()
            if value and value not in reason_parts:
                reason_parts.append(value)
    output = _text(item.get("output") or item.get("stdout") or item.get("stderr") or "").strip()
    if "% Invalid command" in output and not any("Invalid command" in p for p in reason_parts):
        reason_parts.append("设备 CLI 返回 % Invalid command，说明该命令不适配当前平台/模式或命令格式不被支持。")
    if "timeout" in output.lower() and not any("timeout" in p.lower() for p in reason_parts):
        reason_parts.append("命令执行或 MCP 调用可能超时。")
    return "；".join(reason_parts) or "未记录明确失败原因，请展开原始输出查看。"


def _batch136_cmd_output(item: Mapping[str, Any]) -> str:
    for key in ("output", "stdout", "stderr", "raw_output", "raw", "result_text"):
        value = _text(item.get(key)).strip()
        if value:
            return value
    return ""



# BATCH13_7_RAW_OUTPUT_NEWLINE_HELPERS_START
# Render command raw output as plain preformatted text instead of JSON-encoding the string.
# Without this, real newline characters in device output are displayed as literal \n, which is unreadable.
def _batch137_normalize_output_text(value: Any) -> str:
    text = _text(value)
    if not text:
        return ""
    # json.loads() normally converts JSON \n into real newlines, but some upstream fields may be double-escaped.
    # This normalization is applied only to device raw output rendering, not to raw JSON sections.
    text = text.replace("\\r\\n", "\n")
    text = text.replace("\\n", "\n")
    text = text.replace("\\r", "\r")
    text = text.replace("\\t", "\t")
    return text


def _batch137_output_pre(value: Any, *, max_chars: int = 40000) -> str:
    text = _batch137_normalize_output_text(value)
    if len(text) > max_chars:
        text = text[:max_chars] + "\n... [truncated by Evidence Hub UI]"
    return f'<pre class="raw-output-pre">{_h(text)}</pre>'
# BATCH13_7_RAW_OUTPUT_NEWLINE_HELPERS_END


# BATCH13_8_RAW_OUTPUT_INTERACTION_HELPERS_START
def _batch138_raw_output_block(value: Any, output_id: str) -> str:
    safe_id = _h(output_id)
    return (
        '<details class="raw-output-details">'
        '<summary>查看设备原始输出</summary>'
        '<div class="raw-output-toolbar">'
        f'<button type="button" class="secondary raw-output-copy" data-copy-target="{safe_id}">复制原始输出</button>'
        '</div>'
        f'<div id="{safe_id}" class="raw-output-copy-source">'
        f'{_batch137_output_pre(value, max_chars=40000)}'
        '</div>'
        '</details>'
    )


def _batch138_command_table_shell(title: str, rows: str) -> str:
    return (
        '<div class="command-table-shell">'
        '<div class="command-table-toolbar">'
        '<label>原始输出列宽 '
        '<input type="range" class="command-output-width" min="35" max="78" value="48" step="1" aria-label="调整原始输出列宽">'
        '<output class="command-output-width-value">48%</output>'
        '</label>'
        '<button type="button" class="secondary command-output-width-preset" data-width="72">扩大输出</button>'
        '<button type="button" class="secondary command-output-width-preset" data-width="48">恢复默认</button>'
        '</div>'
        '<div class="command-table-scroll">'
        '<table class="evidence-table command-evidence-table">'
        '<colgroup>'
        '<col class="col-order"><col class="col-status"><col class="col-command"><col class="col-reason"><col class="col-output">'
        '</colgroup>'
        f'<thead><tr><th>序号</th><th>状态</th><th>命令</th><th>{_h(title)}</th><th>设备返回/原始输出</th></tr></thead>'
        f'<tbody>{rows}</tbody>'
        '</table>'
        '</div>'
        '</div>'
    )
# BATCH13_8_RAW_OUTPUT_INTERACTION_HELPERS_END


def _batch136_render_command_tables(section_doc: Any) -> str:
    commands = [c for c in _batch136_command_results(section_doc) if isinstance(c, Mapping)]
    if not commands:
        return '<div class="human-note"><strong>命令明细：</strong>当前没有解析到标准 command_results 列表。下方仍保留原始 JSON。</div>'
    success = []
    failed = []
    other = []
    for item in commands:
        status = _batch136_cmd_status(item)
        if _batch136_bool_ok(status) or item.get("success") is True:
            success.append(item)
        elif _batch136_is_failed(status) or item.get("success") is False:
            failed.append(item)
        else:
            other.append(item)

    def row(item: Mapping[str, Any], include_reason: bool, output_id: str) -> str:
        command = _text(item.get("command") or item.get("cli") or item.get("cmd") or "")
        capability = _text(item.get("capability") or item.get("name") or "")
        order = _text(item.get("order") or "")
        status = _batch136_cmd_status_label(item)
        reason = _batch136_cmd_failure_reason(item) if include_reason else _text(item.get("reason") or "")
        output = _batch136_cmd_output(item)
        if output:
            output_block = _batch138_raw_output_block(output, output_id)
        else:
            output_block = '<span class="muted">未保存原始输出</span>'
        return (
            '<tr>'
            f'<td>{_h(order)}</td>'
            f'<td>{status}</td>'
            f'<td><code>{_h(command)}</code><br><span class="muted">{_h(capability)}</span></td>'
            f'<td>{_h(reason)}</td>'
            f'<td class="raw-output-cell">{output_block}</td>'
            '</tr>'
        )

    rows_success = "".join(
        row(item, False, f"raw-output-success-{index}")
        for index, item in enumerate(success, start=1)
    ) or '<tr><td colspan="5" class="muted">无成功命令</td></tr>'
    rows_failed = "".join(
        row(item, True, f"raw-output-failed-{index}")
        for index, item in enumerate(failed, start=1)
    ) or '<tr><td colspan="5" class="muted">无失败命令</td></tr>'
    rows_other = "".join(
        row(item, True, f"raw-output-other-{index}")
        for index, item in enumerate(other, start=1)
    )
    other_table = ""
    if rows_other:
        other_table = '<h4>其他状态命令</h4>' + _batch138_command_table_shell("说明", rows_other)
    return (
        '<div class="human-note">'
        f'<strong>命令明细：</strong>本次共记录 {len(commands)} 条设备只读命令，成功 {len(success)} 条，失败 {len(failed)} 条。'
        '前端只展示 Evidence Hub 已保存的命令与输出，不会重新连接设备执行命令。'
        '</div>'
        '<h4>执行成功命令</h4>'
        + _batch138_command_table_shell("说明", rows_success)
        + '<h4>执行失败命令</h4>'
        + _batch138_command_table_shell("失败原因", rows_failed)
        + other_table
    )

def _batch136_metric_value(value: Any, unit: str = "") -> str:
    try:
        num = float(value)
    except Exception:
        text = _text(value)
        return text if text else "-"
    unit_text = _text(unit).strip()
    if unit_text == "bps":
        abs_num = abs(num)
        if abs_num >= 1_000_000_000:
            return f"{num / 1_000_000_000:.2f} Gbps"
        if abs_num >= 1_000_000:
            return f"{num / 1_000_000:.2f} Mbps"
        if abs_num >= 1_000:
            return f"{num / 1_000:.2f} Kbps"
        return f"{num:.2f} bps"
    if unit_text == "percent":
        return f"{num:.2f} percent"
    if unit_text == "count":
        return f"{num:.2f} count"
    if unit_text == "status":
        return f"{num:.2f} status"
    if unit_text:
        return f"{num:.2f} {unit_text}"
    return f"{num:.2f}"


def _batch136_ratio(value: Any) -> str:
    try:
        num = float(value)
    except Exception:
        return "-"
    return f"{num * 100:.2f}%"


def _batch136_query_window_text(window: Any) -> str:
    if not isinstance(window, Mapping):
        return "-"
    lookback = window.get("lookback_minutes")
    offset = window.get("compare_offset_minutes")
    step = window.get("step") or window.get("step_seconds")
    parts = []
    if lookback not in (None, ""):
        parts.append(f"过去{lookback}分钟")
    if step not in (None, ""):
        parts.append(f"step={step}")
    if offset not in (None, ""):
        parts.append(f"对比偏移={offset}分钟")
    if parts:
        return "，".join(parts)
    start = _text(window.get("start_iso_utc") or window.get("start") or "")
    end = _text(window.get("end_iso_utc") or window.get("end") or "")
    return f"{start} ~ {end}" if start or end else "-"


def _batch136_metric_analysis(evidence: Mapping[str, Any]) -> Mapping[str, Any]:
    analysis = evidence.get("analysis") if isinstance(evidence.get("analysis"), Mapping) else {}
    analyses = analysis.get("analyses") if isinstance(analysis.get("analyses"), list) else []
    for item in analyses:
        if isinstance(item, Mapping):
            return item
    return {}


def _batch136_metric_rows(section_doc: Any) -> list[Mapping[str, Any]]:
    data = _batch135_data(section_doc)
    evidences = []
    if isinstance(data, Mapping):
        if isinstance(data.get("evidences"), list):
            evidences = data.get("evidences") or []
        elif isinstance(data.get("data"), Mapping) and isinstance(data["data"].get("evidences"), list):
            evidences = data["data"].get("evidences") or []
    rows = []
    for ev in evidences:
        if isinstance(ev, Mapping):
            row = dict(ev)
            row["_analysis"] = _batch136_metric_analysis(ev)
            rows.append(row)
    return rows


def _batch136_render_prometheus_table(section_doc: Any) -> str:
    status = _text(section_doc.get("status") if isinstance(section_doc, Mapping) else "")
    rows = _batch136_metric_rows(section_doc)
    if not rows:
        reason = "本次没有生成可表格化的 Prometheus 指标证据。"
        if status == "missing":
            reason += "当前分区状态为 missing，通常表示该 family 没有生成 Prometheus evidence 文件，或测试告警缺少对应时间序列。"
        return f'<div class="human-note"><strong>Prometheus指标明细：</strong>{_h(reason)}下方仍保留原始 JSON。</div>'
    success = sum(1 for ev in rows if ev.get("ok") is True or _batch136_bool_ok(ev.get("status")))
    failed = len(rows) - success
    html_rows = []
    for ev in rows:
        name = _text(ev.get("query_name") or ev.get("name") or "")
        unit = _text(ev.get("unit") or "")
        analysis = ev.get("_analysis") if isinstance(ev.get("_analysis"), Mapping) else {}
        ok = ev.get("ok") is True or _batch136_bool_ok(ev.get("status")) or analysis.get("ok") is True
        state = '<span class="badge">成功</span>' if ok else '<span class="badge warning">失败/无数据</span>'
        html_rows.append(
            '<tr>'
            f'<td>{_h(name)}</td><td>{state}</td><td>{_h(_batch136_query_window_text(ev.get("query_window")))}</td>'
            f'<td>{_h(_batch136_metric_value(analysis.get("current"), unit))}</td>'
            f'<td>{_h(_batch136_metric_value(analysis.get("offset"), unit))}</td>'
            f'<td>{_h(_batch136_metric_value(analysis.get("delta"), unit))}</td>'
            f'<td>{_h(_batch136_ratio(analysis.get("change_ratio")))}</td>'
            f'<td>{_h(_batch136_metric_value(analysis.get("window_max"), unit))}</td>'
            f'<td>{_h(_batch136_metric_value(analysis.get("window_min"), unit))}</td>'
            f'<td>{_h(_batch136_metric_value(analysis.get("window_avg"), unit))}</td>'
            f'<td>{_h(analysis.get("trend_verdict") or "-")}</td>'
            f'<td>{_h(ev.get("error") or ev.get("status") or "")}</td>'
            '</tr>'
        )
    return (
        '<div class="human-note">'
        f'<strong>Prometheus指标明细：</strong>本次共解析 {len(rows)} 项 Prometheus 窗口证据，成功 {success} 项，失败/无数据 {failed} 项。'
        '</div>'
        '<table class="evidence-table metrics-table"><thead><tr>'
        '<th>指标名</th><th>状态</th><th>查询窗口</th><th>当前值</th><th>对比值</th><th>变化量</th><th>变化比例</th><th>窗口最大值</th><th>窗口最小值</th><th>窗口平均值</th><th>趋势判断</th><th>错误/状态</th>'
        '</tr></thead><tbody>' + "".join(html_rows) + '</tbody></table>'
    )


def _batch136_section_extra(section: str, section_doc: Any) -> str:
    if section == "device_evidence":
        return _batch136_render_command_tables(section_doc)
    if section == "metrics_evidence":
        return _batch136_render_prometheus_table(section_doc)
    return ""
# BATCH13_6_READABLE_TABLES_END

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
        extra = _batch136_section_extra(section, sections[section])
        blocks.append(
            f"<details class=\"evidence-section\" id=\"section-{_h(section)}\">"
            f"<summary>{_h(title)}</summary>"
            f"{_batch135_section_note(section, sections[section])}"
            f"{extra}"
            f"<div class=\"muted\">原始 JSON</div>"
            f"{_json_pre(sections[section])}"
            "</details>"
        )
    if not blocks:
        return "<div class=\"card muted\">暂无详情分区。</div>"
    return '<div class="card"><h3>完整证据分区</h3><p class="muted">每个分区先给工程师可读解读，再按需要提供表格化证据，最后保留完整原始 JSON，便于继续追溯。</p>' + "\n".join(blocks) + "</div>"
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
            "human_readable_rendering",
        ],
    }
