import json
import math
import urllib.parse
import urllib.request
import urllib.error
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

    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return json.loads(body)
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""

        raise RuntimeError(
            "prometheus_http_error "
            f"status={e.code} reason={e.reason} "
            f"query={query} "
            f"body={body[:2000]}"
        )


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

# ===== v5 prometheus directional metric window enhancement begin =====
# 增强 Prometheus 指标窗口证据：
# 1. 支持入向/出向利用率窗口。
# 2. 支持入向/出向 bps 窗口。
# 3. 支持从告警方向自动选择重点展示 input/output。
# 4. 支持通过 config.yaml 自定义 PromQL 模板。
# 5. 未配置 Prometheus 时保持安全跳过，不影响 MCP 只读取证闭环。

import re as _p5_re
import time as _p5_time
from typing import Any as _P5Any, Dict as _P5Dict, List as _P5List, Optional as _P5Optional


try:
    _p5_original_build_prometheus_evidence_summary = build_prometheus_evidence_summary
except NameError:
    _p5_original_build_prometheus_evidence_summary = None


def _p5_safe_text(value: _P5Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _p5_guess_direction(event: _P5Dict[str, _P5Any], execution_data: _P5Dict[str, _P5Any]) -> str:
    target_scope = execution_data.get("target_scope", {}) or {}

    blob = " ".join(
        [
            _p5_safe_text(target_scope.get("direction")),
            _p5_safe_text(target_scope.get("alarm_type")),
            _p5_safe_text(target_scope.get("raw_text")),
            _p5_safe_text(event.get("alarm_type")),
            _p5_safe_text(event.get("raw_text")),
            _p5_safe_text(event.get("summary")),
            _p5_safe_text(event.get("description")),
            _p5_safe_text(event.get("labels")),
            _p5_safe_text(event.get("annotations")),
        ]
    ).lower()

    if "入向" in blob or "入方向" in blob or "inbound" in blob or "input" in blob:
        return "in"

    if "出向" in blob or "出方向" in blob or "outbound" in blob or "output" in blob:
        return "out"

    return ""


def _p5_regex_alt(value: str) -> str:
    # PromQL 双引号字符串中不要生成 \- 这种转义，否则会触发
    # parse error: unknown escape sequence U+002D '-'
    # 这里仅处理会破坏正则含义的少数字符，保留 - 和 / 原样。
    value = _p5_safe_text(value)
    out = []
    for ch in value:
        if ch in ".+?^$()[]{}|":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def _p5_interface_regex(interface: str) -> str:
    value = _p5_safe_text(interface)
    if not value:
        return ""

    alts = {value}

    m = _p5_re.match(r"^Te(\d+/\d+/\d+)$", value, flags=_p5_re.IGNORECASE)
    if m:
        alts.add("TenGigabitEthernet" + m.group(1))

    m = _p5_re.match(r"^Gi(\d+/\d+/\d+)$", value, flags=_p5_re.IGNORECASE)
    if m:
        alts.add("GigabitEthernet" + m.group(1))

    m = _p5_re.match(r"^Eth(?:ernet)?(\d+/\d+)$", value, flags=_p5_re.IGNORECASE)
    if m:
        alts.add("Ethernet" + m.group(1))
        alts.add("Eth" + m.group(1))

    m = _p5_re.match(r"^(?:port-channel|Port-channel|Po)(\d+)$", value, flags=_p5_re.IGNORECASE)
    if m:
        alts.add("port-channel" + m.group(1))
        alts.add("Port-channel" + m.group(1))
        alts.add("Po" + m.group(1))

    return "|".join(sorted(_p5_regex_alt(x) for x in alts if x))


def _p5_build_query_context(event: _P5Dict[str, _P5Any], execution_data: _P5Dict[str, _P5Any]) -> _P5Dict[str, _P5Any]:
    target_scope = execution_data.get("target_scope", {}) or {}

    interface = _p5_safe_text(
        target_scope.get("interface")
        or event.get("interface")
        or event.get("ifName")
        or event.get("if_name")
        or event.get("object_name")
    )

    instance = _p5_safe_text(
        event.get("instance")
        or event.get("exporter_instance")
        or target_scope.get("instance")
        or target_scope.get("exporter_instance")
        or event.get("hostname")
        or target_scope.get("hostname")
    )

    raw_cfg = load_config().get("prometheus", {}) or {}
    label_names = raw_cfg.get("label_names", {}) or {}

    ip_label = _p5_safe_text(label_names.get("ip")) or "ip"
    instance_label = _p5_safe_text(label_names.get("instance")) or "instance"

    device_ip = _p5_safe_text(target_scope.get("device_ip") or event.get("device_ip"))
    hostname = _p5_safe_text(target_scope.get("hostname") or event.get("hostname"))

    selector_parts = []

    if device_ip:
        selector_parts.append(f'{ip_label}="{device_ip}"')

    if instance:
        selector_parts.append(f'{instance_label}="{instance}"')

    prom_selector_prefix = ""
    if selector_parts:
        prom_selector_prefix = ",".join(selector_parts) + ","

    return {
        "request_id": _p5_safe_text(execution_data.get("request_id")),
        "device_ip": device_ip,
        "hostname": hostname,
        "instance": instance,
        "job": _p5_safe_text(event.get("job") or target_scope.get("job")),
        "interface": interface,
        "interface_regex": _p5_interface_regex(interface),
        "if_name": interface,
        "if_alias": _p5_safe_text(event.get("if_alias") or event.get("ifAlias") or event.get("object_name")),
        "alarm_type": _p5_safe_text(event.get("alarm_type") or target_scope.get("alarm_type")),
        "prom_selector_prefix": prom_selector_prefix,
    }


def _p5_render_query(template: str, context: _P5Dict[str, _P5Any]) -> str:
    # 不能直接用 str.format(**context)，因为 PromQL 本身大量使用 {label="value"}。
    # str.format 会把 PromQL label selector 误认为格式化字段，导致渲染失败后返回原始模板。
    # 这里改为只替换明确的 {变量名} 占位符，保留 PromQL 自身的大括号。
    rendered = template or ""

    for key, value in (context or {}).items():
        rendered = rendered.replace("{" + str(key) + "}", str(value))

    return rendered


def _p5_default_query_templates(cfg: _P5Dict[str, _P5Any]) -> _P5Dict[str, str]:
    prom = prometheus_config()
    raw_cfg = load_config().get("prometheus", {}) or {}

    metric_names = raw_cfg.get("metric_names", {}) or {}
    label_names = raw_cfg.get("label_names", {}) or {}

    in_octets = _p5_safe_text(metric_names.get("if_in_octets")) or "ifHCInOctets"
    out_octets = _p5_safe_text(metric_names.get("if_out_octets")) or "ifHCOutOctets"
    speed = _p5_safe_text(metric_names.get("if_speed_mbps")) or "ifHighSpeed"

    instance_label = _p5_safe_text(label_names.get("instance")) or "instance"
    ifname_label = _p5_safe_text(label_names.get("if_name")) or "ifName"

    # 注意：
    # 多 target snmp_exporter 场景中，instance 往往是 exporter 地址，
    # 真实设备 IP 通常在 ip 标签里，所以默认 selector 使用 prom_selector_prefix。
    # prom_selector_prefix 会在运行时根据 device_ip / instance 动态生成。
    selector = f'{{prom_selector_prefix}}{ifname_label}=~"{{interface_regex}}"'

    rate_window = _p5_safe_text(raw_cfg.get("rate_window")) or "5m"

    return {
        "interface_input_bps": f'rate({in_octets}{{{selector}}}[{rate_window}]) * 8',
        "interface_output_bps": f'rate({out_octets}{{{selector}}}[{rate_window}]) * 8',
        "interface_input_utilization_percent": f'(rate({in_octets}{{{selector}}}[{rate_window}]) * 8) / ({speed}{{{selector}}} * 1000000) * 100',
        "interface_output_utilization_percent": f'(rate({out_octets}{{{selector}}}[{rate_window}]) * 8) / ({speed}{{{selector}}} * 1000000) * 100',
    }


def _p5_get_query_templates() -> _P5Dict[str, str]:
    raw_cfg = load_config().get("prometheus", {}) or {}
    configured = raw_cfg.get("queries", {}) or {}
    defaults = _p5_default_query_templates(raw_cfg)

    result = dict(defaults)
    for key, value in configured.items():
        if _p5_safe_text(value):
            result[key] = _p5_safe_text(value)

    return result


def _p5_query_metric(
    metric_name: str,
    query_template: str,
    context: _P5Dict[str, _P5Any],
    cfg: _P5Dict[str, _P5Any],
    start,
    end,
) -> _P5Dict[str, _P5Any]:
    query = _p5_render_query(query_template, context)

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

    item = {
        "name": metric_name,
        "query": query,
        "summary": summary,
    }

    if metric_name.endswith("_utilization_percent"):
        item["classification"] = classify_utilization(
            summary,
            float(cfg["high_threshold_percent"]),
            float(cfg["recovered_threshold_percent"]),
        )

    return item


def _p5_metric_line_chinese(metric: _P5Dict[str, _P5Any]) -> str:
    name = _p5_safe_text(metric.get("name"))
    summary = metric.get("summary", {}) or {}

    if not summary.get("has_data"):
        return ""

    direction = "入向" if "input" in name else "出向"

    if name.endswith("_utilization_percent"):
        return (
            f"Prometheus告警窗口{direction}利用率："
            f"max={summary.get('max', 0):.2f}%，"
            f"avg={summary.get('avg', 0):.2f}%，"
            f"last={summary.get('last', 0):.2f}%"
        )

    if name.endswith("_bps"):
        return (
            f"Prometheus告警窗口{direction}速率："
            f"max={summary.get('max', 0):.2f} bps，"
            f"avg={summary.get('avg', 0):.2f} bps，"
            f"last={summary.get('last', 0):.2f} bps"
        )

    return ""


def _p5_conclusion_for_direction(metrics: _P5List[_P5Dict[str, _P5Any]], direction: str) -> str:
    if direction == "in":
        prefer = "interface_input_utilization_percent"
    elif direction == "out":
        prefer = "interface_output_utilization_percent"
    else:
        prefer = ""

    selected = None

    for metric in metrics:
        if metric.get("name") == prefer:
            selected = metric
            break

    if selected is None:
        for metric in metrics:
            if _p5_safe_text(metric.get("name")).endswith("_utilization_percent"):
                selected = metric
                break

    if not selected:
        return ""

    classification = selected.get("classification", {}) or {}
    return _p5_safe_text(classification.get("description"))


def _p5_build_prometheus_evidence_summary(execution_data: _P5Dict[str, _P5Any]) -> _P5Dict[str, _P5Any]:
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

    request_id = _p5_safe_text(execution_data.get("request_id"))
    event = load_event_context(request_id)
    event_time = guess_event_time(event)
    start = event_time - timedelta(minutes=int(cfg["lookback_minutes"]))
    end = event_time + timedelta(minutes=int(cfg["lookahead_minutes"]))

    context = _p5_build_query_context(event, execution_data)
    direction = _p5_guess_direction(event, execution_data)

    if not context.get("instance") or not context.get("interface_regex"):
        return {
            "enabled": True,
            "has_metrics": False,
            "reason": "missing_instance_or_interface",
            "time_window": {
                "event_time": event_time.isoformat(),
                "start": start.isoformat(),
                "end": end.isoformat(),
            },
            "query_context": context,
            "metrics": [],
            "key_findings": [],
            "recommendations": [
                "Prometheus 查询缺少 instance 或 interface 标签，建议检查 Alertmanager payload 中是否包含 exporter instance 和 ifName。",
            ],
            "notify_lines": [],
            "conclusion_suffix": "",
        }

    templates = _p5_get_query_templates()

    metric_order = [
        "interface_input_utilization_percent",
        "interface_output_utilization_percent",
        "interface_input_bps",
        "interface_output_bps",
    ]

    metrics: _P5List[_P5Dict[str, _P5Any]] = []
    key_findings: _P5List[str] = []
    recommendations: _P5List[str] = []
    notify_lines: _P5List[str] = []

    try:
        for metric_name in metric_order:
            template = _p5_safe_text(templates.get(metric_name))
            if not template:
                continue

            metric = _p5_query_metric(metric_name, template, context, cfg, start, end)
            metrics.append(metric)

            line = _p5_metric_line_chinese(metric)
            if line:
                key_findings.append(line)
                notify_lines.append(line)

        has_metrics = any((m.get("summary") or {}).get("has_data") for m in metrics)

        direction_conclusion = _p5_conclusion_for_direction(metrics, direction)

        if direction_conclusion:
            key_findings.append(direction_conclusion)
            notify_lines.append("Prometheus窗口判断：" + direction_conclusion)

            if "持续高利用率" in direction_conclusion:
                recommendations.append("Prometheus 指标窗口显示更像持续高利用率，建议继续定位流量来源、业务高峰和链路容量。")
            elif "瞬时峰值" in direction_conclusion or "已恢复" in direction_conclusion:
                recommendations.append("Prometheus 指标窗口显示更像瞬时峰值或已恢复，建议结合告警持续时间和业务流量峰值判断是否继续跟进。")
            else:
                recommendations.append("Prometheus 指标窗口已返回数据，建议结合设备侧只读取证结果共同判断。")

        if not has_metrics:
            recommendations.append("Prometheus 查询成功但未返回有效序列，建议核对 instance、ifName、指标名和 exporter 标签。")

        suffix = ""
        if key_findings:
            suffix = " Prometheus窗口证据：" + "；".join(key_findings[:3]) + "。"

        return {
            "enabled": True,
            "has_metrics": has_metrics,
            "reason": "ok" if has_metrics else "no_data",
            "direction": direction,
            "time_window": {
                "event_time": event_time.isoformat(),
                "start": start.isoformat(),
                "end": end.isoformat(),
            },
            "query_context": context,
            "metrics": metrics,
            "key_findings": key_findings[:10],
            "recommendations": recommendations[:6],
            "notify_lines": notify_lines[:6],
            "conclusion_suffix": suffix,
        }

    except Exception as e:
        return {
            "enabled": True,
            "has_metrics": False,
            "reason": "query_failed",
            "error": str(e),
            "direction": direction,
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


def build_prometheus_evidence_summary(execution_data: _P5Dict[str, _P5Any]) -> _P5Dict[str, _P5Any]:
    return _p5_build_prometheus_evidence_summary(execution_data)
# ===== v5 prometheus directional metric window enhancement end =====
