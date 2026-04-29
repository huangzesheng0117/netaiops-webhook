import json
import math
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


BASE_DIR = Path("/opt/netaiops-webhook")
CONFIG_FILE = BASE_DIR / "config.yaml"
DATA_DIR = BASE_DIR / "data"
NORMALIZED_DIR = DATA_DIR / "normalized"
ANALYSIS_DIR = DATA_DIR / "analysis"


INTERFACE_FAMILIES = {
    "interface_or_link_utilization_high",
    "interface_or_link_traffic_drop",
    "interface_packet_loss_or_discards_high",
    "interface_status_or_flap",
    "interface_flap",
}


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def load_config() -> Dict[str, Any]:
    if not CONFIG_FILE.exists():
        return {}
    try:
        return yaml.safe_load(CONFIG_FILE.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def prometheus_config() -> Dict[str, Any]:
    cfg = load_config()
    prom = cfg.get("prometheus", {}) or {}

    base_url = safe_text(prom.get("base_url"))
    if not base_url:
        base_url = safe_text(prom.get("url"))

    enabled = bool(prom.get("enabled", False))
    if base_url:
        enabled = bool(prom.get("enabled", True))

    return {
        "enabled": enabled,
        "base_url": base_url.rstrip("/"),
        "timeout": int(prom.get("timeout", 10)),
        "lookback_minutes": int(prom.get("lookback_minutes", 15)),
        "lookahead_minutes": int(prom.get("lookahead_minutes", 5)),
        "step": safe_text(prom.get("step", "60s")),
        "high_threshold_percent": float(prom.get("high_threshold_percent", 80)),
        "recovered_threshold_percent": float(prom.get("recovered_threshold_percent", 20)),
        "queries": prom.get("queries", {}) or {},
    }


def parse_datetime(value: Any) -> Optional[datetime]:
    text = safe_text(value)
    if not text:
        return None

    text = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def find_file_by_request_id(directory: Path, request_id: str, suffix: str) -> Optional[Path]:
    files = list(directory.glob(f"*_{request_id}.{suffix}"))
    if files:
        return files[0]
    return None


def load_event_context(request_id: str) -> Dict[str, Any]:
    normalized_file = find_file_by_request_id(NORMALIZED_DIR, request_id, "json")
    if normalized_file and normalized_file.exists():
        try:
            data = json.loads(normalized_file.read_text(encoding="utf-8"))
            events = data.get("events", []) or []
            if events:
                event = dict(events[0])
                event["_normalized_file"] = str(normalized_file)
                return event
        except Exception:
            pass

    analysis_file = find_file_by_request_id(ANALYSIS_DIR, request_id, "analysis.json")
    if analysis_file and analysis_file.exists():
        try:
            data = json.loads(analysis_file.read_text(encoding="utf-8"))
            event = dict((data.get("event") or {}))
            event["_analysis_file"] = str(analysis_file)
            return event
        except Exception:
            pass

    return {}


def guess_event_time(event: Dict[str, Any]) -> datetime:
    for key in ("timestamp", "startsAt", "starts_at", "created_at", "createdAt"):
        dt = parse_datetime(event.get(key))
        if dt:
            return dt

    return datetime.now(timezone.utc)


def render_query(template: str, context: Dict[str, Any]) -> str:
    try:
        return template.format(**context)
    except Exception:
        return template


def prom_query_range(
    base_url: str,
    query: str,
    start: datetime,
    end: datetime,
    step: str,
    timeout: int,
) -> Dict[str, Any]:
    params = urllib.parse.urlencode(
        {
            "query": query,
            "start": start.timestamp(),
            "end": end.timestamp(),
            "step": step,
        }
    )

    url = f"{base_url}/api/v1/query_range?{params}"

    with urllib.request.urlopen(url, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        return json.loads(body)


def extract_values(response: Dict[str, Any]) -> List[Tuple[float, float]]:
    values: List[Tuple[float, float]] = []

    if response.get("status") != "success":
        return values

    result = ((response.get("data") or {}).get("result")) or []
    for series in result:
        for item in series.get("values", []) or []:
            if len(item) < 2:
                continue
            try:
                ts = float(item[0])
                value = float(item[1])
                if math.isfinite(value):
                    values.append((ts, value))
            except Exception:
                continue

    values.sort(key=lambda x: x[0])
    return values


def summarize_values(values: List[Tuple[float, float]]) -> Dict[str, Any]:
    if not values:
        return {
            "has_data": False,
            "sample_count": 0,
        }

    nums = [v for _, v in values]
    return {
        "has_data": True,
        "sample_count": len(nums),
        "min": min(nums),
        "max": max(nums),
        "avg": sum(nums) / len(nums),
        "first": nums[0],
        "last": nums[-1],
        "first_ts": values[0][0],
        "last_ts": values[-1][0],
    }


def classify_utilization(summary: Dict[str, Any], high_threshold: float, recovered_threshold: float) -> Dict[str, Any]:
    if not summary.get("has_data"):
        return {
            "status": "no_data",
            "description": "Prometheus 查询未返回有效数据，无法判断告警窗口内利用率走势。",
        }

    max_v = float(summary.get("max", 0))
    avg_v = float(summary.get("avg", 0))
    last_v = float(summary.get("last", 0))

    if max_v >= high_threshold and last_v <= recovered_threshold:
        return {
            "status": "recovered_or_spike",
            "description": f"告警窗口内最大利用率 {max_v:.2f}%，当前窗口末尾约 {last_v:.2f}%，更像瞬时峰值或已恢复。",
        }

    if avg_v >= high_threshold * 0.8 and max_v >= high_threshold:
        return {
            "status": "sustained_high",
            "description": f"告警窗口内平均利用率 {avg_v:.2f}%，最大利用率 {max_v:.2f}%，更像持续高利用率。",
        }

    if max_v >= high_threshold:
        return {
            "status": "short_spike",
            "description": f"告警窗口内最大利用率 {max_v:.2f}%，但平均利用率 {avg_v:.2f}%，更像短时峰值。",
        }

    return {
        "status": "not_observed_high",
        "description": f"告警窗口内最大利用率 {max_v:.2f}%，未在 Prometheus 窗口内观察到超过阈值的高利用率。",
    }


def build_query_context(event: Dict[str, Any], execution_data: Dict[str, Any]) -> Dict[str, Any]:
    target_scope = execution_data.get("target_scope", {}) or {}

    return {
        "request_id": safe_text(execution_data.get("request_id")),
        "device_ip": safe_text(target_scope.get("device_ip") or event.get("device_ip")),
        "hostname": safe_text(target_scope.get("hostname") or event.get("hostname")),
        "interface": safe_text(target_scope.get("interface") or event.get("interface")),
        "if_alias": safe_text(event.get("if_alias") or event.get("ifAlias") or event.get("object_name")),
        "job": safe_text(event.get("job") or target_scope.get("job")),
        "instance": safe_text(event.get("instance") or target_scope.get("hostname")),
        "alarm_type": safe_text(event.get("alarm_type") or target_scope.get("alarm_type")),
    }


def should_query_prometheus(execution_data: Dict[str, Any]) -> bool:
    family = safe_text(
        ((execution_data.get("family_result") or {}).get("family"))
        or ((execution_data.get("classification") or {}).get("family"))
        or ((execution_data.get("classification") or {}).get("playbook_type"))
    )

    return family in INTERFACE_FAMILIES


def build_prometheus_evidence_summary(execution_data: Dict[str, Any]) -> Dict[str, Any]:
    cfg = prometheus_config()

    if not should_query_prometheus(execution_data):
        return {
            "enabled": False,
            "has_metrics": False,
            "reason": "family_not_supported",
            "metrics": [],
            "key_findings": [],
            "recommendations": [],
            "notify_lines": [],
            "conclusion_suffix": "",
        }

    if not cfg.get("enabled") or not cfg.get("base_url"):
        return {
            "enabled": False,
            "has_metrics": False,
            "reason": "prometheus_not_configured",
            "metrics": [],
            "key_findings": [],
            "recommendations": [],
            "notify_lines": [],
            "conclusion_suffix": "",
        }

    request_id = safe_text(execution_data.get("request_id"))
    event = load_event_context(request_id)
    event_time = guess_event_time(event)
    start = event_time - timedelta(minutes=int(cfg["lookback_minutes"]))
    end = event_time + timedelta(minutes=int(cfg["lookahead_minutes"]))

    context = build_query_context(event, execution_data)

    queries = cfg.get("queries", {}) or {}
    utilization_template = safe_text(
        queries.get("interface_output_utilization_percent")
        or queries.get("interface_out_utilization_percent")
        or queries.get("interface_utilization_percent")
    )

    output_bps_template = safe_text(
        queries.get("interface_output_bps")
        or queries.get("interface_out_bps")
    )

    metrics: List[Dict[str, Any]] = []
    key_findings: List[str] = []
    recommendations: List[str] = []
    notify_lines: List[str] = []

    if not utilization_template and not output_bps_template:
        return {
            "enabled": True,
            "has_metrics": False,
            "reason": "query_template_missing",
            "time_window": {
                "event_time": event_time.isoformat(),
                "start": start.isoformat(),
                "end": end.isoformat(),
            },
            "query_context": context,
            "metrics": [],
            "key_findings": [],
            "recommendations": [
                "Prometheus 已配置但未配置接口利用率查询模板，建议补充 prometheus.queries.interface_output_utilization_percent。",
            ],
            "notify_lines": [],
            "conclusion_suffix": "",
        }

    try:
        if utilization_template:
            query = render_query(utilization_template, context)
            response = prom_query_range(
                cfg["base_url"],
                query,
                start,
                end,
                cfg["step"],
                int(cfg["timeout"]),
            )
            values = extract_values(response)
            summary = summarize_values(values)
            classification = classify_utilization(
                summary,
                float(cfg["high_threshold_percent"]),
                float(cfg["recovered_threshold_percent"]),
            )

            metric_item = {
                "name": "interface_output_utilization_percent",
                "query": query,
                "summary": summary,
                "classification": classification,
            }
            metrics.append(metric_item)

            if summary.get("has_data"):
                line = (
                    f"Prometheus窗口利用率：max={summary['max']:.2f}%，"
                    f"avg={summary['avg']:.2f}%，last={summary['last']:.2f}%"
                )
                key_findings.append(line)
                notify_lines.append(line)
                key_findings.append(classification["description"])

                if classification["status"] in ("recovered_or_spike", "short_spike"):
                    recommendations.append("Prometheus 指标显示更像瞬时峰值或已恢复，建议结合业务流量峰值和告警持续时间判断是否需要继续跟进。")
                elif classification["status"] == "sustained_high":
                    recommendations.append("Prometheus 指标显示更像持续高利用率，建议继续定位流量来源、业务高峰、链路容量和上联聚合情况。")
                else:
                    recommendations.append("Prometheus 窗口未观察到明显高利用率，建议核对告警表达式、标签映射和采样时间窗口。")

        if output_bps_template:
            query = render_query(output_bps_template, context)
            response = prom_query_range(
                cfg["base_url"],
                query,
                start,
                end,
                cfg["step"],
                int(cfg["timeout"]),
            )
            values = extract_values(response)
            summary = summarize_values(values)

            metrics.append(
                {
                    "name": "interface_output_bps",
                    "query": query,
                    "summary": summary,
                }
            )

            if summary.get("has_data"):
                line = (
                    f"Prometheus窗口出向速率：max={summary['max']:.2f} bps，"
                    f"avg={summary['avg']:.2f} bps，last={summary['last']:.2f} bps"
                )
                key_findings.append(line)
                notify_lines.append(line)

    except Exception as e:
        return {
            "enabled": True,
            "has_metrics": False,
            "reason": "query_failed",
            "error": str(e),
            "time_window": {
                "event_time": event_time.isoformat(),
                "start": start.isoformat(),
                "end": end.isoformat(),
            },
            "query_context": context,
            "metrics": metrics,
            "key_findings": [],
            "recommendations": [
                f"Prometheus 查询失败：{e}",
            ],
            "notify_lines": [],
            "conclusion_suffix": "",
        }

    has_metrics = any((m.get("summary") or {}).get("has_data") for m in metrics)

    conclusion_suffix = ""
    if key_findings:
        conclusion_suffix = " Prometheus窗口证据：" + "；".join(key_findings[:2]) + "。"

    return {
        "enabled": True,
        "has_metrics": has_metrics,
        "reason": "ok" if has_metrics else "no_data",
        "time_window": {
            "event_time": event_time.isoformat(),
            "start": start.isoformat(),
            "end": end.isoformat(),
        },
        "query_context": context,
        "metrics": metrics,
        "key_findings": key_findings[:8],
        "recommendations": recommendations[:5],
        "notify_lines": notify_lines[:4],
        "conclusion_suffix": conclusion_suffix,
    }


def enrich_evidence_summary_with_prometheus(
    evidence_summary: Dict[str, Any],
    execution_data: Dict[str, Any],
) -> Dict[str, Any]:
    evidence_summary = dict(evidence_summary or {})
    prom = build_prometheus_evidence_summary(execution_data)

    evidence_summary["prometheus"] = prom

    if not prom.get("enabled"):
        return evidence_summary

    if prom.get("key_findings"):
        existing = list(evidence_summary.get("key_findings", []) or [])
        evidence_summary["key_findings"] = existing + prom.get("key_findings", [])

    if prom.get("recommendations"):
        existing = list(evidence_summary.get("recommendations", []) or [])
        evidence_summary["recommendations"] = existing + prom.get("recommendations", [])

    if prom.get("notify_lines"):
        existing = list(evidence_summary.get("notify_lines", []) or [])
        for line in prom.get("notify_lines", []):
            existing.append("指标窗口：" + line)
        evidence_summary["notify_lines"] = existing

    suffix = safe_text(prom.get("conclusion_suffix"))
    if suffix:
        base = safe_text(evidence_summary.get("conclusion"))
        evidence_summary["conclusion"] = (base + suffix).strip()

    return evidence_summary
