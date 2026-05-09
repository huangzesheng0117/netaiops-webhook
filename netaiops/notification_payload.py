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


def _v5_command_text(item: Dict[str, Any]) -> str:
    item = item or {}

    for key in ("command", "rendered_command", "cmd"):
        value = safe_text(item.get(key))
        if value:
            return value

    candidate = item.get("candidate")
    if isinstance(candidate, dict):
        for key in ("command", "rendered_command", "cmd"):
            value = safe_text(candidate.get(key))
            if value:
                return value

    return ""


def _v5_command_status(item: Dict[str, Any]) -> str:
    item = item or {}
    judge = item.get("judge", {}) or {}

    if judge.get("hard_error"):
        return "failed"

    status = safe_text(
        judge.get("final_status")
        or item.get("final_status")
        or item.get("dispatch_status")
        or item.get("status")
    ).lower()

    if status in ("completed", "success", "succeeded", "ok"):
        return "completed"

    if status in ("failed", "failure", "error", "timeout"):
        return "failed"

    if status in ("partial", "partially_completed", "partial_completed"):
        return "partial"

    return "partial"


def _v5_format_command_list(commands: List[str]) -> str:
    cleaned = []
    seen = set()

    for cmd in commands or []:
        value = safe_text(cmd)
        if not value:
            continue
        if value in seen:
            continue
        seen.add(value)
        cleaned.append(value)

    if not cleaned:
        return "无"

    return "；".join(cleaned)


def _v5_build_command_execution_summary_line(
    line_no: int,
    command_results: List[Dict[str, Any]],
) -> str:
    completed_commands: List[str] = []
    failed_commands: List[str] = []
    partial_commands: List[str] = []

    for item in command_results or []:
        command = _v5_command_text(item)
        status = _v5_command_status(item)

        if status == "completed":
            completed_commands.append(command)
        elif status == "failed":
            failed_commands.append(command)
        else:
            partial_commands.append(command)

    completed_count = len(completed_commands)
    failed_count = len(failed_commands)
    partial_count = len(partial_commands)
    total_count = len(command_results or [])

    return (
        f"{line_no}. 已完成MCP只读取证：共执行 {total_count} 条只读命令，"
        f"成功 {completed_count} 条，具体内容为：{_v5_format_command_list(completed_commands)}。"
        f"失败 {failed_count} 条，具体内容为：{_v5_format_command_list(failed_commands)}。"
        f"部分完成 {partial_count} 条，具体内容为：{_v5_format_command_list(partial_commands)}。"
    )


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
        if command_results:
            lines.append(
                _v5_build_command_execution_summary_line(
                    len(lines) + 1,
                    command_results,
                )
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

# ===== v5 notification non-traffic interface recommendation final filter begin =====
# 兜底修复：
# 非流量/利用率类接口告警，不允许在最终咚咚通知中出现
# “高利用率、速率曲线、瞬时峰值、Prometheus窗口、指标曲线、流量来源”等流量类建议。
#
# 该过滤发生在 notification_payload 最终出口，不改变 MCP 执行逻辑。

import re as _v11n_re

try:
    _v11n_original_build_notification_payload = build_notification_payload
except NameError:
    _v11n_original_build_notification_payload = None

try:
    _v11n_original_build_notification_text = build_notification_text
except NameError:
    _v11n_original_build_notification_text = None


V11N_TRAFFIC_FAMILIES = {
    "interface_or_link_utilization_high",
    "interface_or_link_traffic_drop",
}


V11N_TRAFFIC_WORDS = [
    "高利用率",
    "利用率",
    "速率曲线",
    "速率",
    "流量趋势",
    "流量来源",
    "业务高峰",
    "瞬时峰值",
    "已恢复",
    "Prometheus",
    "指标曲线",
    "告警窗口",
    "时间窗口",
    "入向速率",
    "出向速率",
    "input rate",
    "output rate",
    "traffic",
    "utilization",
]


V11N_STATUS_RECOMMENDATIONS = [
    "核查接口当前 oper/admin 状态是否与告警状态一致。",
    "结合接口日志时间线确认是否存在链路 up/down、flap、模块异常或对端切换。",
    "如接口属于聚合链路，继续核查 port-channel 成员状态、LACP 状态和对端端口状态。",
    "必要时结合对端设备接口状态、光模块状态和链路物理层信息继续确认。",
]


def _v11n_safe_text(value):
    if value is None:
        return ""
    return str(value).strip()


def _v11n_get_family_from_payload(payload):
    if not isinstance(payload, dict):
        return ""

    candidates = [
        ((payload.get("target") or {}).get("family")),
        ((payload.get("family_result") or {}).get("family")),
        ((payload.get("review") or {}).get("family")),
        ((payload.get("review_data") or {}).get("family")),
        ((payload.get("evidence_summary") or {}).get("family")),
        ((payload.get("notify_view") or {}).get("family")),
    ]

    for item in candidates:
        value = _v11n_safe_text(item)
        if value:
            return value

    return ""


def _v11n_is_non_traffic_interface_payload(payload):
    family = _v11n_get_family_from_payload(payload)

    if family in V11N_TRAFFIC_FAMILIES:
        return False

    if family in {
        "interface_status_or_flap",
        "interface_flap",
        "interface_packet_loss_or_discards_high",
    }:
        return True

    text = "\n".join(
        [
            _v11n_safe_text((payload.get("notify_view") or {}).get("alarm_text")),
            _v11n_safe_text((payload.get("notify_view") or {}).get("analysis_process")),
            _v11n_safe_text((payload.get("notify_view") or {}).get("recommendations")),
            _v11n_safe_text((payload.get("target") or {}).get("interface")),
            _v11n_safe_text((payload.get("target") or {}).get("family")),
        ]
    )

    if "接口" in text or "端口" in text or "Ethernet" in text or "port-channel" in text:
        if "状态变化" in text or "端口状态" in text or "接口状态" in text or "flap" in text.lower():
            return True

    return False


def _v11n_has_traffic_word(line):
    text = _v11n_safe_text(line)
    lower = text.lower()

    for word in V11N_TRAFFIC_WORDS:
        if word in text or word.lower() in lower:
            return True

    return False


def _v11n_strip_number_prefix(line):
    return _v11n_re.sub(r"^\s*\d+[\.、]\s*", "", _v11n_safe_text(line)).strip()


def _v11n_renumber_lines(lines):
    result = []
    for idx, line in enumerate(lines, start=1):
        value = _v11n_strip_number_prefix(line)
        if value:
            result.append(f"{idx}. {value}")
    return "\n".join(result)


def _v11n_clean_recommendations_text(text):
    lines = [_v11n_strip_number_prefix(x) for x in _v11n_safe_text(text).splitlines()]
    kept = []
    seen = set()

    for line in lines:
        if not line:
            continue
        if _v11n_has_traffic_word(line):
            continue
        if line in seen:
            continue
        seen.add(line)
        kept.append(line)

    for item in V11N_STATUS_RECOMMENDATIONS:
        if item not in seen:
            kept.append(item)
            seen.add(item)

    return _v11n_renumber_lines(kept[:8])


def _v11n_extract_interface_status(analysis_process):
    text = _v11n_safe_text(analysis_process)

    m = _v11n_re.search(r"接口状态：\s*([A-Za-z0-9\/\.\-]+)\s+oper=([^\s，,]+)\s+admin=([^\s，,]+)", text)
    if m:
        return m.group(1), m.group(2), m.group(3)

    m = _v11n_re.search(r"([A-Za-z]+[A-Za-z0-9\/\.\-]+)\s+oper=([^\s，,]+)\s+admin=([^\s，,]+)", text)
    if m:
        return m.group(1), m.group(2), m.group(3)

    return "接口", "未知", "未知"


def _v11n_clean_analysis_process_text(text):
    raw_lines = _v11n_safe_text(text).splitlines()
    cleaned = []

    iface, oper, admin = _v11n_extract_interface_status(text)

    for line in raw_lines:
        value = _v11n_safe_text(line)
        if not value:
            continue

        if "综合执行结果判断" in value and _v11n_has_traffic_word(value):
            prefix_match = _v11n_re.match(r"^\s*(\d+[\.、])\s*", value)
            prefix = prefix_match.group(1) if prefix_match else f"{len(cleaned) + 1}."
            cleaned.append(
                f"{prefix} 综合执行结果判断：{iface} 状态类只读取证完成；"
                f"接口状态 oper={oper} / admin={admin}。"
                "建议结合接口状态、聚合关系、对端端口和日志时间线判断是否存在链路抖动、模块异常或链路切换。"
            )
            continue

        if _v11n_has_traffic_word(value) and (
            "取证事实" in value
            or "接口带宽" in value
            or "实时速率" in value
            or "估算利用率" in value
            or "流量判断" in value
            or "告警口径" in value
        ):
            continue

        cleaned.append(value)

    return "\n".join(cleaned)


def _v11n_clean_payload(payload):
    if not isinstance(payload, dict):
        return payload

    if not _v11n_is_non_traffic_interface_payload(payload):
        return payload

    payload = dict(payload)
    notify_view = dict(payload.get("notify_view") or {})

    if "analysis_process" in notify_view:
        notify_view["analysis_process"] = _v11n_clean_analysis_process_text(
            notify_view.get("analysis_process")
        )

    if "recommendations" in notify_view:
        notify_view["recommendations"] = _v11n_clean_recommendations_text(
            notify_view.get("recommendations")
        )

    payload["notify_view"] = notify_view
    payload["v5_non_traffic_interface_notify_filter"] = {
        "enabled": True,
        "reason": "non_traffic_interface_family",
        "family": _v11n_get_family_from_payload(payload),
    }

    return payload


def _v11n_clean_final_text(payload, text):
    if not _v11n_is_non_traffic_interface_payload(payload):
        return text

    value = _v11n_safe_text(text)

    if "\n建议：\n" not in value:
        return value

    before, rec = value.split("\n建议：\n", 1)

    # 如果建议后面未来追加了其他 section，这里先按当前通知结构处理。
    cleaned_rec = _v11n_clean_recommendations_text(rec)

    return before.rstrip() + "\n\n建议：\n" + cleaned_rec


if _v11n_original_build_notification_payload is not None:
    def build_notification_payload(request_id):
        payload = _v11n_original_build_notification_payload(request_id)
        return _v11n_clean_payload(payload)


if _v11n_original_build_notification_text is not None:
    def build_notification_text(payload):
        payload = _v11n_clean_payload(payload)
        text = _v11n_original_build_notification_text(payload)
        return _v11n_clean_final_text(payload, text)
# ===== v5 notification non-traffic interface recommendation final filter end =====
