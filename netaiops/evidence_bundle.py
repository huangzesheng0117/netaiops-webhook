from datetime import datetime, timezone
from typing import Any, Dict, List


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_family(execution_data: Dict[str, Any], review_data: Dict[str, Any], evidence_summary: Dict[str, Any]) -> str:
    return safe_text(
        evidence_summary.get("family")
        or review_data.get("family")
        or ((execution_data.get("family_result") or {}).get("family"))
        or ((execution_data.get("classification") or {}).get("family"))
        or ((execution_data.get("classification") or {}).get("playbook_type"))
        or ((execution_data.get("playbook") or {}).get("playbook_id"))
    )


def get_target_scope(execution_data: Dict[str, Any], review_data: Dict[str, Any]) -> Dict[str, Any]:
    target = execution_data.get("target_scope", {}) or review_data.get("target_scope", {}) or {}
    if not isinstance(target, dict):
        return {}
    return target


def normalize_fact_item(name: str, value: Any, source: str = "evidence_summary") -> Dict[str, Any]:
    return {
        "name": safe_text(name),
        "value": value,
        "source": source,
    }


def build_facts(evidence_summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    facts: List[Dict[str, Any]] = []

    raw_facts = evidence_summary.get("facts", {}) or {}
    if isinstance(raw_facts, dict):
        for key, value in raw_facts.items():
            if value is None or value == "":
                continue
            facts.append(normalize_fact_item(key, value))

    for line in evidence_summary.get("key_findings", []) or []:
        line_text = safe_text(line)
        if not line_text:
            continue
        facts.append(
            {
                "name": "key_finding",
                "value": line_text,
                "source": "review_key_findings",
            }
        )

    return facts


def build_metrics(evidence_summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    prom = evidence_summary.get("prometheus", {}) or {}
    metrics: List[Dict[str, Any]] = []

    for item in prom.get("metrics", []) or []:
        if not isinstance(item, dict):
            continue

        metrics.append(
            {
                "name": safe_text(item.get("name")),
                "source": "prometheus",
                "query": safe_text(item.get("query")),
                "summary": item.get("summary", {}) or {},
                "classification": item.get("classification", {}) or {},
            }
        )

    return metrics


def build_logs(evidence_summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    logs: List[Dict[str, Any]] = []

    elastic = evidence_summary.get("elastic", {}) or {}
    if isinstance(elastic, dict):
        for item in elastic.get("logs", []) or []:
            if isinstance(item, dict):
                logs.append(item)

    return logs


def build_device_outputs(execution_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    outputs: List[Dict[str, Any]] = []

    for item in execution_data.get("command_results", []) or []:
        if not isinstance(item, dict):
            continue

        output_text = safe_text(item.get("output"))
        if len(output_text) > 1200:
            output_preview = output_text[:1200] + "...[truncated]"
        else:
            output_preview = output_text

        outputs.append(
            {
                "order": item.get("order"),
                "capability": safe_text(item.get("capability")),
                "command": safe_text(item.get("command")),
                "status": safe_text(item.get("dispatch_status") or item.get("final_status")),
                "judge": item.get("judge", {}) or {},
                "output_preview": output_preview,
            }
        )

    return outputs


def build_timeline(execution_data: Dict[str, Any], review_data: Dict[str, Any], evidence_summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    timeline: List[Dict[str, Any]] = []

    for key, label in [
        ("created_at", "request_created"),
        ("generated_at", "plan_generated"),
        ("confirmed_at", "plan_confirmed"),
        ("dispatch_started_at", "dispatch_started"),
        ("dispatch_finished_at", "dispatch_finished"),
        ("review_generated_at", "review_generated"),
    ]:
        value = safe_text(execution_data.get(key) or review_data.get(key) or evidence_summary.get(key))
        if value:
            timeline.append(
                {
                    "time": value,
                    "event": label,
                    "source": "runtime",
                }
            )

    prom = evidence_summary.get("prometheus", {}) or {}
    window = prom.get("time_window", {}) or {}
    if window:
        for key, label in [
            ("start", "prometheus_window_start"),
            ("event_time", "alert_event_time"),
            ("end", "prometheus_window_end"),
        ]:
            value = safe_text(window.get(key))
            if value:
                timeline.append(
                    {
                        "time": value,
                        "event": label,
                        "source": "prometheus",
                    }
                )

    if not timeline:
        timeline.append(
            {
                "time": now_utc(),
                "event": "evidence_bundle_generated",
                "source": "system",
            }
        )

    return timeline


def infer_hypotheses(evidence_summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    hypotheses: List[Dict[str, Any]] = []

    facts = evidence_summary.get("facts", {}) or {}
    conclusion = safe_text(evidence_summary.get("conclusion"))
    key_findings = " ".join([safe_text(x) for x in evidence_summary.get("key_findings", []) or []])
    combined = f"{conclusion} {key_findings}"

    output_rate = facts.get("output_rate_bps")
    output_total_drops = facts.get("output_total_drops") or facts.get("output_buffer_drops")
    oper_status = safe_text(facts.get("oper_status"))
    admin_status = safe_text(facts.get("admin_status"))

    prom = evidence_summary.get("prometheus", {}) or {}
    prom_status = ""
    for metric in prom.get("metrics", []) or []:
        classification = metric.get("classification", {}) or {}
        if classification.get("status"):
            prom_status = safe_text(classification.get("status"))
            break

    if prom_status in ("recovered_or_spike", "short_spike"):
        hypotheses.append(
            {
                "hypothesis": "告警可能由短时流量峰值触发，当前可能已恢复。",
                "confidence": "medium",
                "basis": "Prometheus窗口指标显示短时峰值或窗口末尾回落。",
            }
        )

    if isinstance(output_rate, int) and output_rate < 1000000:
        hypotheses.append(
            {
                "hypothesis": "取证时接口实时流量较低，告警可能已经恢复或属于瞬时峰值。",
                "confidence": "medium",
                "basis": f"设备侧取证 output_rate_bps={output_rate}。",
            }
        )

    if isinstance(output_total_drops, int) and output_total_drops > 0:
        hypotheses.append(
            {
                "hypothesis": "接口存在累计丢弃计数，需要进一步确认是否仍在持续增长。",
                "confidence": "medium",
                "basis": f"设备侧存在累计 output drops={output_total_drops}。",
            }
        )

    if oper_status.lower() == "up" and admin_status.lower() == "up":
        hypotheses.append(
            {
                "hypothesis": "本端接口当前物理/管理状态正常。",
                "confidence": "high",
                "basis": "接口 oper/admin 状态均为 up。",
            }
        )

    if "未观察到" in combined or "查询失败" in combined:
        hypotheses.append(
            {
                "hypothesis": "部分证据不足，需要人工复核指标、日志或对象映射。",
                "confidence": "low",
                "basis": "现有证据中存在无数据或查询失败信息。",
            }
        )

    if not hypotheses:
        hypotheses.append(
            {
                "hypothesis": "已完成只读取证，但当前证据不足以给出单一明确根因。",
                "confidence": "low",
                "basis": "未命中明确假设规则。",
            }
        )

    return hypotheses


def infer_confidence(evidence_summary: Dict[str, Any], execution_data: Dict[str, Any], hypotheses: List[Dict[str, Any]]) -> str:
    has_facts = bool(evidence_summary.get("has_facts"))
    command_results = execution_data.get("command_results", []) or []
    completed_count = 0
    failed_count = 0

    for item in command_results:
        status = safe_text(item.get("dispatch_status") or item.get("final_status")).lower()
        judge = item.get("judge", {}) or {}

        if judge.get("hard_error"):
            failed_count += 1
        elif status == "completed":
            completed_count += 1
        elif status == "failed":
            failed_count += 1

    has_metrics = bool((evidence_summary.get("prometheus", {}) or {}).get("has_metrics"))
    has_logs = bool((evidence_summary.get("elastic", {}) or {}).get("has_logs"))

    if has_facts and completed_count > 0 and failed_count == 0 and (has_metrics or has_logs):
        return "high"

    if has_facts and completed_count > 0 and failed_count == 0:
        return "medium"

    if has_facts and completed_count > 0:
        return "medium_low"

    return "low"


def build_evidence_bundle(
    request_id: str,
    execution_data: Dict[str, Any],
    review_data: Dict[str, Any],
    evidence_summary: Dict[str, Any],
) -> Dict[str, Any]:
    facts = build_facts(evidence_summary)
    metrics = build_metrics(evidence_summary)
    logs = build_logs(evidence_summary)
    device_outputs = build_device_outputs(execution_data)
    timeline = build_timeline(execution_data, review_data, evidence_summary)
    hypotheses = infer_hypotheses(evidence_summary)
    confidence = infer_confidence(evidence_summary, execution_data, hypotheses)

    return {
        "schema_version": "1.0",
        "request_id": request_id,
        "family": get_family(execution_data, review_data, evidence_summary),
        "target_scope": get_target_scope(execution_data, review_data),
        "generated_at": now_utc(),
        "facts": facts,
        "metrics": metrics,
        "logs": logs,
        "device_outputs": device_outputs,
        "timeline": timeline,
        "hypotheses": hypotheses,
        "confidence": confidence,
        "summary": {
            "fact_count": len(facts),
            "metric_count": len(metrics),
            "log_count": len(logs),
            "device_output_count": len(device_outputs),
            "timeline_count": len(timeline),
            "hypothesis_count": len(hypotheses),
        },
    }
