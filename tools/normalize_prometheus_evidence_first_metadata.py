#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
规范化重点 playbook 的 prometheus_evidence_first 顶层元数据。

修复目标：
1. 确保 4 个重点 playbook 都有顶层 prometheus_evidence_first。
2. 清理误插入到 device_evidence_after_prometheus 下的 max_candidates_per_query / sidecar_overall_timeout_seconds。
3. 将 sidecar_overall_timeout_seconds 从 45 调整到 30，避免无数据场景拖慢生产通知。
4. 保持原有 commands / execution / device_evidence_after_prometheus 不变。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml


TARGETS: Dict[str, Dict[str, Any]] = {
    "playbooks/cisco_interface_or_link_traffic_drop.yaml": {
        "evidence_profile": "interface_traffic",
        "query_names": ["in_bps", "out_bps", "oper_status"],
        "required_labels": ["device_ip", "if_name"],
    },
    "playbooks/cisco_interface_traffic_anomaly.yaml": {
        "evidence_profile": "interface_traffic",
        "query_names": ["in_bps", "out_bps", "oper_status"],
        "required_labels": ["device_ip", "if_name"],
    },
    "playbooks/cisco_interface_or_link_utilization_high.yaml": {
        "evidence_profile": "interface_traffic",
        "query_names": ["in_bps", "out_bps", "oper_status"],
        "required_labels": ["device_ip", "if_name"],
    },
    "playbooks/cisco_interface_packet_loss_or_discards_high.yaml": {
        "evidence_profile": "interface_errors",
        "query_names": ["in_errors_delta", "out_errors_delta", "in_discards_delta", "out_discards_delta"],
        "required_labels": ["device_ip", "if_name"],
    },
}


def build_metadata(profile: str, query_names: list[str], required_labels: list[str]) -> Dict[str, Any]:
    return {
        "enabled": True,
        "backend_preference": "prometheus_mcp",
        "fallback": "http_api",
        "evidence_profile": profile,
        "query_names": query_names,
        "lookback_minutes": 15,
        "compare_offset_minutes": 5,
        "step_seconds": 60,
        "max_candidates_per_query": 1,
        "sidecar_overall_timeout_seconds": 30,
        "required_labels": required_labels,
        "stop_device_cli_if_not_confirmed": False,
        "unavailable_policy": "continue_cli_evidence",
        "note": "v8 runtime metadata: Prometheus MCP sidecar enabled; failure must not block CLI evidence.",
    }


def remove_wrong_nested_perf_keys(obj: Any) -> Any:
    """
    只清理非 prometheus_evidence_first 里的误插入性能字段。
    """
    if isinstance(obj, dict):
        cleaned = {}
        for key, value in obj.items():
            if key in {"max_candidates_per_query", "sidecar_overall_timeout_seconds"}:
                # 顶层和非 prometheus_evidence_first 内的该字段都先清掉；
                # 后面会重新写入标准 prometheus_evidence_first。
                continue
            cleaned[key] = remove_wrong_nested_perf_keys(value)
        return cleaned

    if isinstance(obj, list):
        return [remove_wrong_nested_perf_keys(x) for x in obj]

    return obj


def normalize_file(path: Path, spec: Dict[str, Any]) -> str:
    if not path.exists():
        return "missing"

    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path} YAML root is not dict")

    # 先移除误插入到旧块下面的性能字段。
    cleaned = remove_wrong_nested_perf_keys(raw)

    # 重新写入标准顶层 prometheus_evidence_first。
    cleaned["prometheus_evidence_first"] = build_metadata(
        profile=spec["evidence_profile"],
        query_names=spec["query_names"],
        required_labels=spec["required_labels"],
    )

    # 用 safe_dump 重写 YAML。会改变字段顺序，但保留结构；当前更重要的是修正 YAML 结构。
    text = yaml.safe_dump(
        cleaned,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
        width=120,
    )
    path.write_text(text, encoding="utf-8")

    # 二次校验。
    verify = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    pef = verify.get("prometheus_evidence_first") or {}
    if not isinstance(pef, dict):
        raise ValueError(f"{path} prometheus_evidence_first not dict after normalize")
    if pef.get("max_candidates_per_query") != 1:
        raise ValueError(f"{path} max_candidates_per_query invalid")
    if pef.get("sidecar_overall_timeout_seconds") != 30:
        raise ValueError(f"{path} sidecar_overall_timeout_seconds invalid")

    return "normalized"


def main() -> int:
    failed = False

    for name, spec in TARGETS.items():
        path = Path(name)
        try:
            status = normalize_file(path, spec)
            print(f"[{status}] {name}")
            if status == "missing":
                failed = True
        except Exception as e:
            failed = True
            print(f"[ERROR] {name}: {type(e).__name__}: {e}")

    if failed:
        return 2

    print("[OK] all target playbooks normalized.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
