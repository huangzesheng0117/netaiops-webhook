import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from netaiops.request_summary import get_request_summary
from netaiops.target_resolver import resolve_device_display


BASE_DIR = Path("/opt/netaiops-webhook")
DATA_DIR = BASE_DIR / "data"
ANALYSIS_DIR = DATA_DIR / "analysis"
PLAN_DIR = DATA_DIR / "plans"
EXECUTION_DIR = DATA_DIR / "execution"
REVIEW_DIR = DATA_DIR / "reviews"
CONFIG_FILE = BASE_DIR / "config.yaml"


def read_json_file(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def find_optional_file(directory: Path, request_id: str, suffix: str) -> Optional[Path]:
    files = list(directory.glob(f"*_{request_id}.{suffix}"))
    return files[0] if files else None


def load_config() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def get_external_base_url() -> str:
    config = load_config()
    return str(config.get("external_base_url", "http://127.0.0.1:18080")).rstrip("/")


def get_full_request_context(request_id: str) -> Dict[str, Any]:
    summary = get_request_summary(request_id)

    analysis_file = find_optional_file(ANALYSIS_DIR, request_id, "analysis.json")
    plan_file = find_optional_file(PLAN_DIR, request_id, "plan.json")
    execution_file = find_optional_file(EXECUTION_DIR, request_id, "execution.json")
    review_file = find_optional_file(REVIEW_DIR, request_id, "review.json")

    analysis_data = read_json_file(analysis_file) if analysis_file else {}
    plan_data = read_json_file(plan_file) if plan_file else {}
    execution_data = read_json_file(execution_file) if execution_file else {}
    review_data = read_json_file(review_file) if review_file else {}

    return {
        "summary": summary,
        "analysis_data": analysis_data,
        "plan_data": plan_data,
        "execution_data": execution_data,
        "review_data": review_data,
        "analysis_file": str(analysis_file) if analysis_file else "",
        "plan_file": str(plan_file) if plan_file else "",
        "execution_file": str(execution_file) if execution_file else "",
        "review_file": str(review_file) if review_file else "",
    }


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def first_non_empty(*values: Any) -> str:
    for value in values:
        text = safe_text(value)
        if text:
            return text
    return ""


def shorten_text(text: str, limit: int = 160) -> str:
    text = safe_text(text).replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def extract_result_text_from_nested_output(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, dict):
        structured = value.get("structuredContent") or {}
        result = structured.get("result")
        if result:
            return safe_text(result)

        content = value.get("content") or []
        if isinstance(content, list):
            parts = []
            for item in content:
                if isinstance(item, dict):
                    txt = safe_text(item.get("text"))
                    if txt:
                        parts.append(txt)
            if parts:
                return "\n".join(parts)

        nested_output = value.get("output")
        if nested_output:
            return extract_result_text_from_nested_output(nested_output)

        return safe_text(value)

    if isinstance(value, list):
        parts = [extract_result_text_from_nested_output(item) for item in value]
        parts = [p for p in parts if p]
        return "\n".join(parts)

    text = safe_text(value)
    if not text:
        return ""

    try:
        parsed = json.loads(text)
        return extract_result_text_from_nested_output(parsed)
    except Exception:
        return text


def build_alarm_content(analysis_data: Dict[str, Any], plan_data: Dict[str, Any], summary: Dict[str, Any]) -> str:
    event = (analysis_data or {}).get("event", {}) or {}
    target_scope = (plan_data or {}).get("target_scope", {}) or {}

    raw_text = safe_text(event.get("raw_text"))
    alarm_type = first_non_empty(
        event.get("alarm_type"),
        target_scope.get("alarm_type"),
    )
    analysis_summary = safe_text((((analysis_data or {}).get("result", {}) or {}).get("summary")))
    hostname = first_non_empty(event.get("hostname"), target_scope.get("hostname"))
    device_ip = first_non_empty(event.get("device_ip"), target_scope.get("device_ip"))

    if raw_text:
        return raw_text
    if analysis_summary:
        return analysis_summary
    if alarm_type and hostname and device_ip:
        return f"{device_ip} {hostname} {alarm_type}"
    if alarm_type:
        return alarm_type
    return "无"


def build_capability_display(item: Dict[str, Any]) -> str:
    capability = safe_text(item.get("capability"))
    command = safe_text(item.get("command"))

    if capability and command:
        return f"{capability} -> {command}"
    if capability:
        return capability
    if command:
        return command
    return "未知命令"


def build_command_result_line(item: Dict[str, Any], line_index: int) -> str:
    display = build_capability_display(item)
    status = safe_text(item.get("dispatch_status"))
    judge = (item.get("judge") or {}) if isinstance(item.get("judge"), dict) else {}
    hard_error = bool(judge.get("hard_error", False))
    judge_reason = safe_text(judge.get("judge_reason"))
    matched_rule_id = safe_text(judge.get("matched_rule_id"))
    matched_text = safe_text(judge.get("matched_text"))

    prefix = f"{line_index}. 通过MCP执行 {display}"
    if status:
        prefix += f"（状态：{status}）"

    if hard_error:
        extra = []
        if matched_rule_id:
            extra.append(f"规则={matched_rule_id}")
        if matched_text:
            extra.append(f"命中={matched_text}")
        detail = "；".join(extra) if extra else "设备返回硬错误"
        return f"{prefix}，设备返回硬错误：{detail}"

    output = shorten_text(extract_result_text_from_nested_output(item.get("output")), 140)
    if output:
        if judge_reason and judge_reason not in ("no_hard_fail_pattern_matched", "ignore_pattern_matched_only"):
            return f"{prefix}，返回要点：{output}（判定：{judge_reason}）"
        return f"{prefix}，返回要点：{output}"

    err = shorten_text(safe_text(item.get("error")), 140)
    if err:
        if judge_reason and judge_reason not in ("no_hard_fail_pattern_matched", "ignore_pattern_matched_only"):
            return f"{prefix}，报错：{err}（判定：{judge_reason}）"
        return f"{prefix}，报错：{err}"

    if judge_reason and judge_reason not in ("no_hard_fail_pattern_matched", "ignore_pattern_matched_only"):
        return f"{prefix}，判定：{judge_reason}"

    return prefix


def build_analysis_process(
    analysis_data: Dict[str, Any],
    execution_data: Dict[str, Any],
    review_data: Dict[str, Any],
) -> str:
    lines: List[str] = []

    analysis_result = (analysis_data or {}).get("result", {}) or {}
    command_results = (execution_data or {}).get("command_results", []) or []
    review_conclusion = safe_text((review_data or {}).get("conclusion"))
    evidence_summary = (review_data or {}).get("evidence_summary", {}) or {}

    summary_text = safe_text(analysis_result.get("summary"))

    if summary_text:
        lines.append(f"1. 根据告警内容初步判断：{summary_text}")

    if evidence_summary.get("has_facts"):
        completed_count = 0
        failed_count = 0
        partial_count = 0

        for item in command_results:
            status = safe_text(item.get("dispatch_status")).lower()
            if status == "completed":
                completed_count += 1
            elif status == "failed":
                failed_count += 1
            else:
                partial_count += 1

        if command_results:
            lines.append(
                f"{len(lines) + 1}. 已完成MCP只读取证：共执行 {len(command_results)} 条只读命令，"
                f"成功 {completed_count} 条，失败 {failed_count} 条，部分完成 {partial_count} 条。"
            )

        notify_lines = evidence_summary.get("notify_lines", []) or []
        for item in notify_lines:
            text = safe_text(item)
            if text:
                lines.append(f"{len(lines) + 1}. 取证事实：{text}")

        if review_conclusion:
            lines.append(f"{len(lines) + 1}. 综合执行结果判断：{review_conclusion}")

        if not lines:
            return "无"

        return "\n".join(lines)

    alarm_interpretation = safe_text(analysis_result.get("alarm_interpretation"))
    if alarm_interpretation:
        lines.append(f"{len(lines) + 1}. 告警含义分析：{alarm_interpretation}")

    base_index = len(lines)

    for idx, item in enumerate(command_results, start=1):
        lines.append(build_command_result_line(item, base_index + idx))

    if review_conclusion:
        lines.append(f"{len(lines) + 1}. 综合执行结果判断：{review_conclusion}")

    if not lines:
        return "无"

    return "\n".join(lines)

def build_recommendations(
    analysis_data: Dict[str, Any],
    review_data: Dict[str, Any],
) -> str:
    lines: List[str] = []

    review_recommendations = (review_data or {}).get("recommendations", []) or []
    evidence_summary = (review_data or {}).get("evidence_summary", {}) or {}
    suggested_checks = (((analysis_data or {}).get("result", {}) or {}).get("suggested_checks", [])) or []
    possible_causes = (((analysis_data or {}).get("result", {}) or {}).get("possible_causes", [])) or []

    seen = set()

    def add_line(text: Any) -> None:
        value = safe_text(text)
        if not value:
            return
        if value in seen:
            return
        seen.add(value)
        lines.append(value)

    for item in review_recommendations:
        add_line(item)

    if not evidence_summary.get("has_facts"):
        for item in suggested_checks:
            add_line(item)

        if possible_causes:
            cause_text = "、".join([safe_text(x) for x in possible_causes if safe_text(x)])
            if cause_text:
                add_line(f"重点核查可能原因：{cause_text}")

    if not lines:
        return "1. 暂无明确建议，请登录设备结合现场情况进一步排查。"

    max_items = 5 if evidence_summary.get("has_facts") else 6
    return "\n".join([f"{idx}. {item}" for idx, item in enumerate(lines[:max_items], start=1)])

def build_notification_payload(request_id: str) -> Dict[str, Any]:
    ctx = get_full_request_context(request_id)
    summary = ctx["summary"]
    analysis_data = ctx["analysis_data"]
    plan_data = ctx["plan_data"]
    execution_data = ctx["execution_data"]
    review_data = ctx["review_data"]

    target_scope = (execution_data or {}).get("target_scope", {}) or (plan_data or {}).get("target_scope", {}) or {}
    hostname = safe_text(target_scope.get("hostname"))
    device_ip = safe_text(target_scope.get("device_ip"))

    summary_data = summary or {}
    plan_summary = (summary_data.get("plan") or {})
    execution_summary = (summary_data.get("execution") or {})
    review_summary = (summary_data.get("review") or {})
    analysis_summary = (summary_data.get("analysis") or {})

    base_url = get_external_base_url()

    mcp_name = ""
    for item in (execution_data or {}).get("command_results", []) or []:
        output_text = safe_text(item.get("output"))
        if not output_text:
            continue
        try:
            output_obj = json.loads(output_text)
        except Exception:
            continue
        mcp_name = safe_text(output_obj.get("mcp_name"))
        if mcp_name:
            break

    device_text = resolve_device_display(target_scope, fallback_mcp_name=mcp_name)

    alarm_content = build_alarm_content(analysis_data, plan_data, summary_data)
    analysis_process = build_analysis_process(analysis_data, execution_data, review_data)
    recommendations = build_recommendations(analysis_data, review_data)

    family = first_non_empty(
        ((plan_data or {}).get("family_result") or {}).get("family"),
        ((plan_data or {}).get("classification") or {}).get("family"),
    )
    execution_source = first_non_empty(
        (plan_data or {}).get("execution_source"),
        execution_summary.get("mode"),
    )
    playbook_id = first_non_empty(
        ((plan_data or {}).get("playbook") or {}).get("playbook_id"),
        ((plan_summary.get("playbook") or {}).get("playbook_id")),
    )

    payload = {
        "request_id": request_id,
        "title": f"NetAIOps分析结果-{safe_text(request_id)[:8]}-{safe_text(request_id)[9:13]}",
        "status": {
            "analysis_status": analysis_summary.get("status"),
            "plan_status": plan_summary.get("status"),
            "execution_status": execution_summary.get("status"),
            "review_status": review_summary.get("status"),
        },
        "target": {
            "playbook_id": playbook_id,
            "execution_mode": execution_summary.get("mode") or "",
            "execution_source": execution_source,
            "family": family,
        },
        "target_scope": target_scope,
        "summary": {
            "analysis_summary": analysis_summary.get("summary") or "",
            "review_conclusion": review_summary.get("conclusion") or "",
            "recommendations": review_summary.get("recommendations") or [],
        },
        "execution_stats": execution_summary.get("stats") or {},
        "policy": plan_summary.get("policy_result") or {},
        "query_urls": {
            "summary_url": f"{base_url}/v4/request/{request_id}/summary",
            "dispatch_url": f"{base_url}/v4/dispatch/{request_id}",
        },
        "notify_view": {
            "device": device_text,
            "alarm_content": alarm_content,
            "analysis_process": analysis_process,
            "recommendations_text": recommendations,
        },
    }

    return payload


def generate_notification_payload(request_id: str) -> Dict[str, Any]:
    return build_notification_payload(request_id)


def build_notification_text(payload: dict) -> str:
    notify_view = payload.get("notify_view", {}) or {}
    query_urls = payload.get("query_urls", {}) or {}
    target = payload.get("target", {}) or {}

    device = safe_text(notify_view.get("device")) or "无"
    alarm_content = safe_text(notify_view.get("alarm_content")) or "无"
    analysis_process = safe_text(notify_view.get("analysis_process")) or "无"
    recommendations_text = safe_text(notify_view.get("recommendations_text")) or "无"
    summary_url = safe_text(query_urls.get("summary_url"))

    family = safe_text(target.get("family"))
    execution_source = safe_text(target.get("execution_source"))
    playbook_id = safe_text(target.get("playbook_id"))

    lines = []
    lines.append(f"设备：{device}")

    lines.append("")
    lines.append("告警内容：")
    lines.append(alarm_content)
    lines.append("")
    lines.append("分析过程：")
    lines.append(analysis_process)
    lines.append("")
    lines.append("建议：")
    lines.append(recommendations_text)

    return "\n".join(lines)


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("request_id")
    args = parser.parse_args()

    payload = build_notification_payload(args.request_id)
    text = build_notification_text(payload)

    print(json.dumps(payload, ensure_ascii=False, indent=2))
    print()
    print(text)


if __name__ == "__main__":
    main()


# ===== v5 notify template wrapper begin =====
# 将通知正文渲染入口拆到 netaiops.notify_templates。
# 当前接口类告警仍保持原有已验证格式，后续不同 family 可独立优化模板。
try:
    _v5_original_build_notification_text = build_notification_text

    def build_notification_text(payload):
        from netaiops.notify_templates import render_notification_text as _render_notification_text

        return _render_notification_text(
            payload,
            fallback_renderer=_v5_original_build_notification_text,
        )

except NameError:
    pass
# ===== v5 notify template wrapper end =====

