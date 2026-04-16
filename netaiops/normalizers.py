import re
from datetime import datetime, timezone

from netaiops.context_catalog import enrich_event_from_catalog

def now_utc_str() -> str:
    return datetime.now(timezone.utc).isoformat()

def extract_ip(text: str) -> str:
    if not text:
        return ""
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(text))
    return match.group(0) if match else ""

def normalize_alertmanager(payload: dict) -> list:
    events = []

    alerts = payload.get("alerts", [])
    common_labels = payload.get("commonLabels", {}) or {}
    common_annotations = payload.get("commonAnnotations", {}) or {}

    for alert in alerts:
        labels = alert.get("labels", {}) or {}
        annotations = alert.get("annotations", {}) or {}

        merged_labels = {**common_labels, **labels}
        merged_annotations = {**common_annotations, **annotations}

        raw_text = " ".join(
            [
                str(merged_labels.get("alertname", "")),
                str(merged_annotations.get("summary", "")),
                str(merged_annotations.get("description", "")),
            ]
        ).strip()

        event = {
            "source": "alertmanager",
            "timestamp": alert.get("startsAt") or now_utc_str(),
            "alarm_type": merged_labels.get("alertname", ""),
            "severity": merged_labels.get("severity", ""),
            "status": alert.get("status", payload.get("status", "")),
            "hostname": merged_labels.get("instance", "") or merged_labels.get("hostname", ""),
            "device_ip": merged_labels.get("ip", "") or extract_ip(
                merged_labels.get("instance", "") or merged_annotations.get("description", "") or raw_text
            ),
            "vendor": merged_labels.get("vendor", ""),
            "object_type": merged_labels.get("job", "") or merged_labels.get("type", ""),
            "object_name": merged_labels.get("interface", "") or merged_labels.get("name", ""),
            "raw_text": raw_text,
            "labels": merged_labels,
            "annotations": merged_annotations,
            "generator_url": alert.get("generatorURL", ""),
            "expression": alert.get("expression", ""),
        }
        event = enrich_event_from_catalog(event)
        events.append(event)

    return events

def normalize_elastic(payload: dict) -> list:
    events = []

    hits = (((payload or {}).get("hits") or {}).get("hits") or [])
    if not hits and isinstance(payload, dict):
        src = payload.get("_source")
        if src:
            hits = [payload]

    for hit in hits:
        source_data = hit.get("_source", {}) if isinstance(hit, dict) else {}
        message = str(source_data.get("message", "") or source_data.get("log", "") or "")

        host_obj = source_data.get("host", {})
        if not isinstance(host_obj, dict):
            host_obj = {}

        agent_obj = source_data.get("agent", {})
        if not isinstance(agent_obj, dict):
            agent_obj = {}

        observer_obj = source_data.get("observer", {})
        if not isinstance(observer_obj, dict):
            observer_obj = {}

        event_obj = source_data.get("event", {})
        if not isinstance(event_obj, dict):
            event_obj = {}

        log_obj = source_data.get("log", {})
        if not isinstance(log_obj, dict):
            log_obj = {}

        rule_obj = source_data.get("rule", {})
        if not isinstance(rule_obj, dict):
            rule_obj = {}

        hostname = (
            host_obj.get("name", "")
            or source_data.get("host", "")
            or agent_obj.get("name", "")
        )

        vendor = (
            source_data.get("vendor", "")
            or observer_obj.get("vendor", "")
        )

        event = {
            "source": "elastic",
            "timestamp": source_data.get("@timestamp", now_utc_str()),
            "alarm_type": event_obj.get("kind", "") or rule_obj.get("name", ""),
            "severity": log_obj.get("level", ""),
            "status": event_obj.get("outcome", ""),
            "hostname": hostname,
            "device_ip": source_data.get("ip", "") or extract_ip(message),
            "vendor": vendor,
            "object_type": event_obj.get("category", ""),
            "object_name": rule_obj.get("name", ""),
            "raw_text": message,
            "labels": source_data,
            "annotations": {},
            "expression": "",
            "generator_url": "",
        }
        event = enrich_event_from_catalog(event)
        events.append(event)

    return events
