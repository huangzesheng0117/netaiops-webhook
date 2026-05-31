#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
给重点 playbook 增加 prometheus_evidence_first 元数据。

说明：
- 只追加 YAML 顶层元数据块，不修改已有 commands / policy / skill / readonly 字段。
- 如果文件中已经存在 prometheus_evidence_first，则跳过，避免重复。
- 当前 runtime 尚未识别该字段，因此本批不会触发 Prometheus 查询。
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import yaml


PATCHES: Dict[str, str] = {
    "playbooks/cisco_interface_or_link_traffic_drop.yaml": """
prometheus_evidence_first:
  enabled: true
  backend_preference: prometheus_mcp
  fallback: http_api
  evidence_profile: interface_traffic
  query_names:
    - in_bps
    - out_bps
    - oper_status
  lookback_minutes: 15
  compare_offset_minutes: 5
  step_seconds: 60
  required_labels:
    - device_ip
    - if_name
  stop_device_cli_if_not_confirmed: false
  unavailable_policy: continue_cli_evidence
  note: "v8 metadata only: runtime integration will be added in later batches."
""".strip(),

    "playbooks/cisco_interface_traffic_anomaly.yaml": """
prometheus_evidence_first:
  enabled: true
  backend_preference: prometheus_mcp
  fallback: http_api
  evidence_profile: interface_traffic
  query_names:
    - in_bps
    - out_bps
    - oper_status
  lookback_minutes: 15
  compare_offset_minutes: 5
  step_seconds: 60
  required_labels:
    - device_ip
    - if_name
  stop_device_cli_if_not_confirmed: false
  unavailable_policy: continue_cli_evidence
  note: "v8 metadata only: runtime integration will be added in later batches."
""".strip(),

    "playbooks/cisco_interface_or_link_utilization_high.yaml": """
prometheus_evidence_first:
  enabled: true
  backend_preference: prometheus_mcp
  fallback: http_api
  evidence_profile: interface_traffic
  query_names:
    - in_bps
    - out_bps
    - oper_status
  lookback_minutes: 15
  compare_offset_minutes: 5
  step_seconds: 60
  required_labels:
    - device_ip
    - if_name
  stop_device_cli_if_not_confirmed: false
  unavailable_policy: continue_cli_evidence
  note: "v8 metadata only: runtime integration will be added in later batches."
""".strip(),

    "playbooks/cisco_interface_packet_loss_or_discards_high.yaml": """
prometheus_evidence_first:
  enabled: true
  backend_preference: prometheus_mcp
  fallback: http_api
  evidence_profile: interface_errors
  query_names:
    - in_errors_delta
    - out_errors_delta
    - in_discards_delta
    - out_discards_delta
  lookback_minutes: 15
  compare_offset_minutes: 5
  step_seconds: 60
  required_labels:
    - device_ip
    - if_name
  stop_device_cli_if_not_confirmed: false
  unavailable_policy: continue_cli_evidence
  note: "v8 metadata only: runtime integration will be added in later batches."
""".strip(),
}


def ensure_yaml_valid(path: Path) -> None:
    with path.open("r", encoding="utf-8") as f:
        yaml.safe_load(f)


def append_metadata(path: Path, block: str) -> str:
    if not path.exists():
        return "missing"

    text = path.read_text(encoding="utf-8")

    if "prometheus_evidence_first:" in text:
        ensure_yaml_valid(path)
        return "already_exists"

    new_text = text.rstrip() + "\n\n# NetAIOps webhook v8 Prometheus MCP metadata\n" + block + "\n"
    path.write_text(new_text, encoding="utf-8")
    ensure_yaml_valid(path)
    return "patched"


def main() -> int:
    results: List[dict] = []

    for file_name, block in PATCHES.items():
        path = Path(file_name)
        status = append_metadata(path, block)
        results.append({
            "path": file_name,
            "status": status,
        })

    for item in results:
        print(f"[{item['status']}] {item['path']}")

    bad = [x for x in results if x["status"] == "missing"]
    if bad:
        print("[WARN] 存在缺失 playbook，请确认文件名。")
        return 2

    print("[OK] playbook prometheus_evidence_first metadata patch completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
