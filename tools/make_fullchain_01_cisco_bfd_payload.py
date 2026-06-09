#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

ts = os.environ.get("TS") or datetime.now().strftime("%Y%m%d_%H%M%S")
out_file = Path(os.environ.get("PAYLOAD_FILE") or f"data/fullchain_simulation/fullchain_01_cisco_bfd_{ts}.json")

sim_device_ip = os.environ.get("SIM_DEVICE_IP", "10.187.251.107")
sim_hostname = os.environ.get("SIM_HOSTNAME", "SH16-G03-DCI-BN-ACC-SW01")
sim_peer_ip = os.environ.get("SIM_PEER_IP", "10.187.251.108")
sim_interface = os.environ.get("SIM_INTERFACE", "Ethernet1/1")
sim_vrf = os.environ.get("SIM_VRF", "default")

alertname = "BFD Neighbor Down"
now = datetime.now(timezone.utc)
starts_at = (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")

labels = {
    "alertname": alertname,
    "severity": "warning",
    "vendor": "cisco",
    "platform": "nxos",
    "job": "netaiops-fullchain-simulation",
    "instance": sim_device_ip,
    "ip": sim_device_ip,
    "device_ip": sim_device_ip,
    "hostname": sim_hostname,
    "sysName": sim_hostname,
    "protocol": "bfd",
    "peer_ip": sim_peer_ip,
    "neighbor_ip": sim_peer_ip,
    "neighbor_id": sim_peer_ip,
    "interface": sim_interface,
    "ifName": sim_interface,
    "if_name": sim_interface,
    "object_name": sim_peer_ip,
    "vrf": sim_vrf,
    "alarm_type": "routing_neighbor_down",
    "event_type": "bfd_neighbor_down",
    "playbook_id": "cisco_bfd_neighbor_down",
    "skill_name": "routing_neighbor_down",
    "simulation": "true",
    "fullchain_test": "true",
    "fullchain_index": "01",
}

annotations = {
    "summary": f"[全链路仿真-01] {sim_hostname} BFD邻居 {sim_peer_ip} Down",
    "description": (
        f"这是 NetAIOps webhook 全链路仿真告警，用于验证 playbook=cisco_bfd_neighbor_down "
        f"和 skill=routing_neighbor_down。目标设备 {sim_hostname}({sim_device_ip})，"
        f"BFD peer={sim_peer_ip}，interface={sim_interface}，vrf={sim_vrf}。"
        f"预期平台执行只读命令 show bfd neighbors / show bfd neighbors details / "
        f"show logging include BFD 相关关键字，并将分析结果发送到咚咚。"
    ),
    "runbook": "fullchain simulation 01 - cisco_bfd_neighbor_down",
}

payload = {
    "receiver": "netaiops-webhook-fullchain-simulation",
    "status": "firing",
    "alerts": [
        {
            "status": "firing",
            "labels": labels,
            "annotations": annotations,
            "startsAt": starts_at,
            "endsAt": "0001-01-01T00:00:00Z",
            "generatorURL": "http://netaiops-webhook.local/simulation/fullchain-01-cisco-bfd",
            "fingerprint": f"fullchain-01-cisco-bfd-{int(now.timestamp())}",
        }
    ],
    "groupLabels": {
        "alertname": alertname,
        "device_ip": sim_device_ip,
        "peer_ip": sim_peer_ip,
    },
    "commonLabels": labels,
    "commonAnnotations": annotations,
    "externalURL": "http://netaiops-webhook.local/alertmanager-fullchain-simulation",
    "version": "4",
    "groupKey": f"{{}}:{{alertname='{alertname}',device_ip='{sim_device_ip}',peer_ip='{sim_peer_ip}'}}",
    "truncatedAlerts": 0,
}

out_file.parent.mkdir(parents=True, exist_ok=True)
out_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
print(out_file)
