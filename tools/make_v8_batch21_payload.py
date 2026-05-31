#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

ts = os.environ.get("TS") or datetime.now().strftime("%Y%m%d_%H%M%S")
poc_dir = Path(os.environ.get("POC_DIR") or "/opt/netaiops-webhook/data/v8_prometheus_mcp_poc")
payload_file = Path(os.environ.get("PAYLOAD_FILE") or poc_dir / f"alertmanager_v8_batch21_{ts}.json")

device_ip = "10.187.251.107"
hostname = "SH16-G03-DCI-BN-ACC-SW01"
if_name = "Ethernet1/1"
alertname = "cisco_interface_or_link_traffic_drop"

now = datetime.now(timezone.utc)
starts_at = (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")

labels = {
    "alertname": alertname,
    "severity": "warning",
    "vendor": "cisco",
    "platform": "nxos",
    "job": "netaiops-v8-simulation",
    "instance": device_ip,
    "ip": device_ip,
    "device_ip": device_ip,
    "hostname": hostname,
    "sysName": hostname,
    "interface": if_name,
    "ifName": if_name,
    "if_name": if_name,
    "object_name": if_name,
    "alarm_type": "interface_traffic_drop",
    "event_type": "interface_traffic_drop",
    "source": "batch21_v8_simulation",
    "simulation": "true",
    "v8_prometheus_mcp_test": "true",
}

annotations = {
    "summary": f"[V8仿真-Batch21] {hostname} {if_name} 接口流量突降",
    "description": (
        f"这是 NetAIOps webhook v8 Prometheus MCP 对接仿真告警。"
        f"目标设备 {hostname}({device_ip})，接口 {if_name}。"
        f"本次用于验证 1min PromQL 精度、移除 oper_status 后的 Prometheus 窗口证据，以及咚咚通知展示。"
    ),
}

payload = {
    "receiver": "netaiops-webhook-v8-simulation",
    "status": "firing",
    "alerts": [
        {
            "status": "firing",
            "labels": labels,
            "annotations": annotations,
            "startsAt": starts_at,
            "endsAt": "0001-01-01T00:00:00Z",
            "generatorURL": "http://netaiops-webhook.local/simulation/batch21",
            "fingerprint": f"v8-batch21-sim-{int(now.timestamp())}",
        }
    ],
    "groupLabels": {
        "alertname": alertname,
        "device_ip": device_ip,
        "ifName": if_name,
    },
    "commonLabels": labels,
    "commonAnnotations": annotations,
    "externalURL": "http://netaiops-webhook.local/alertmanager-simulation",
    "version": "4",
    "groupKey": f"{{}}:{{alertname='{alertname}',device_ip='{device_ip}',ifName='{if_name}'}}",
    "truncatedAlerts": 0,
}

payload_file.parent.mkdir(parents=True, exist_ok=True)
payload_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
print(payload_file)
