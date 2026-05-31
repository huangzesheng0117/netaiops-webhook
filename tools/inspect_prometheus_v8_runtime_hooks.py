#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NetAIOps webhook v8 Prometheus Evidence runtime hook inspector.

只读扫描：
1. 当前 playbooks 中哪些最适合接入 prometheus_evidence_first。
2. plan_builder / processor / review_builder / notification_payload 的函数结构。
3. 输出 JSON 报告，供下一批最小改造使用。

本脚本不修改任何生产业务代码。
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any, Dict, List

import yaml


ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = ROOT / "data" / "v8_prometheus_mcp_poc"

PROM_KEYWORDS = [
    "prometheus",
    "query_range",
    "traffic",
    "utilization",
    "bandwidth",
    "bps",
    "octets",
    "drop",
    "drops",
    "error",
    "errors",
    "discard",
    "discards",
    "crc",
    "loss",
    "packet",
    "latency",
    "delay",
    "session",
    "connection",
    "connections",
    "f5",
    "fortigate",
    "hillstone",
    "internet",
    "dci",
    "interface",
    "流量",
    "利用率",
    "突增",
    "突降",
    "错包",
    "丢包",
    "会话",
    "连接数",
    "延迟",
]


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except Exception:
        return str(path)


def get_defs(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    try:
        tree = ast.parse(read_text(path))
    except Exception as e:
        return [{"error": f"{type(e).__name__}: {e}"}]

    defs: List[Dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defs.append({
                "type": "class" if isinstance(node, ast.ClassDef) else "function",
                "name": node.name,
                "line": getattr(node, "lineno", None),
            })
    return sorted(defs, key=lambda x: x.get("line") or 0)


def grep_hits(path: Path, patterns: List[str], max_hits: int = 80) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    lines = read_text(path).splitlines()
    regexes = [re.compile(p, re.IGNORECASE) for p in patterns]
    hits = []

    for idx, line in enumerate(lines, 1):
        if any(r.search(line) for r in regexes):
            hits.append({
                "line": idx,
                "text": line.strip(),
            })
        if len(hits) >= max_hits:
            break
    return hits


def infer_profile(text: str) -> str:
    lower = text.lower()

    if any(x in lower for x in ["crc", "discard", "discards", "error", "errors", "packet", "loss", "错包", "丢包"]):
        return "interface_errors"

    if any(x in lower for x in ["traffic", "utilization", "bandwidth", "octets", "bps", "flow", "流量", "利用率", "突增", "突降"]):
        return "interface_traffic"

    if "f5" in lower or "sysstatclientcurconns" in lower:
        return "f5_connections"

    if any(x in lower for x in ["fortigate", "hillstone", "session", "connection", "connections", "会话", "连接数"]):
        return "firewall_sessions"

    if any(x in lower for x in ["latency", "delay", "sla", "延迟"]):
        return "latency_window"

    return "unknown"


def scan_playbooks() -> List[Dict[str, Any]]:
    playbook_dir = ROOT / "playbooks"
    result: List[Dict[str, Any]] = []

    if not playbook_dir.exists():
        return result

    for path in sorted(playbook_dir.rglob("*.yaml")):
        text = read_text(path)
        lower = text.lower()

        matched = sorted(set(k for k in PROM_KEYWORDS if k.lower() in lower))
        has_prom_marker = any(x in lower for x in [
            "prometheus_evidence_first",
            "prometheus_first",
            "prometheus-first",
            "query_range",
        ])

        if not matched and not has_prom_marker:
            continue

        try:
            data = yaml.safe_load(text) or {}
        except Exception as e:
            data = {"_yaml_error": f"{type(e).__name__}: {e}"}

        profile = infer_profile(text)

        score = 0
        if matched:
            score += 1
        if profile != "unknown":
            score += 2
        if has_prom_marker:
            score += 3

        result.append({
            "path": rel(path),
            "name": data.get("name") or data.get("alertname") or data.get("alert_name") or path.stem,
            "vendor": data.get("vendor") or data.get("platform") or data.get("family") or "-",
            "readonly_only": data.get("readonly_only", data.get("read_only")),
            "auto_execute_allowed": data.get("auto_execute_allowed", data.get("auto_confirm_allowed")),
            "has_prometheus_marker": has_prom_marker,
            "matched_keywords": matched,
            "recommended_profile": profile,
            "priority_score": score,
        })

    return sorted(result, key=lambda x: (-x["priority_score"], x["path"]))


def inspect_metric_mapping() -> Dict[str, Any]:
    path = ROOT / "config" / "prometheus_metrics.yaml"
    if not path.exists():
        return {"exists": False}

    try:
        data = yaml.safe_load(read_text(path)) or {}
    except Exception as e:
        return {"exists": True, "error": f"{type(e).__name__}: {e}"}

    profiles = data.get("profiles") or {}
    return {
        "exists": True,
        "defaults": data.get("defaults") or {},
        "profiles": {
            name: {
                "description": item.get("description"),
                "queries": sorted((item.get("queries") or {}).keys()),
            }
            for name, item in profiles.items()
            if isinstance(item, dict)
        },
    }


def inspect_core_files() -> Dict[str, Any]:
    files = [
        "netaiops/plan_builder.py",
        "netaiops/processor.py",
        "netaiops/review_builder.py",
        "netaiops/notification_payload.py",
        "netaiops/notifier.py",
        "netaiops/playbook_loader.py",
        "netaiops/policy_engine.py",
        "agent_runner/runner.py",
        "agent_runner/mcp_bridge_netmiko.py",
    ]

    patterns = [
        r"playbook",
        r"plan",
        r"review",
        r"notification",
        r"notify",
        r"evidence",
        r"facts",
        r"execution",
        r"dispatch",
        r"auto_execute",
        r"auto_dispatch",
        r"prometheus",
    ]

    result: Dict[str, Any] = {}
    for f in files:
        path = ROOT / f
        result[f] = {
            "exists": path.exists(),
            "defs": get_defs(path),
            "hits": grep_hits(path, patterns),
        }
    return result


def build_recommendations(playbooks: List[Dict[str, Any]], core: Dict[str, Any]) -> List[str]:
    recs = []

    if playbooks:
        recs.append("下一批建议先只给命中的 playbook 增加 prometheus_evidence_first 元数据，不立即接入执行逻辑。")
        recs.append("优先选择 interface_traffic 与 interface_errors 两类，因为它们最需要 Prometheus query_range 历史窗口。")
        recs.append("F5/FortiGate/Hillstone 会话类可作为第二阶段，避免一次性扩大主链路改造范围。")
    else:
        recs.append("未扫描到明显候选 playbook，下一批应先人工确认 playbook 命名和告警类别。")

    if core.get("netaiops/plan_builder.py", {}).get("exists"):
        recs.append("plan_builder.py 存在，后续可识别 playbook.prometheus_evidence_first 并写入 plan metadata。")

    if core.get("netaiops/processor.py", {}).get("exists"):
        recs.append("processor.py 存在，后续可在 plan 之后、设备 CLI dispatch 之前插入 Prometheus evidence sidecar 调用。")

    if core.get("netaiops/review_builder.py", {}).get("exists"):
        recs.append("review_builder.py 存在，后续可在 review 构建完成后附加 Prometheus section。")

    if core.get("netaiops/notification_payload.py", {}).get("exists"):
        recs.append("notification_payload.py 存在，后续可在通知文本末尾追加 Prometheus窗口证据。")

    recs.append("Prometheus 查询失败时只能标记 evidence unavailable，不得阻断原有 CLI 取证和咚咚通知。")
    return recs


def main() -> int:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    metric_mapping = inspect_metric_mapping()
    playbooks = scan_playbooks()
    core = inspect_core_files()
    recommendations = build_recommendations(playbooks, core)

    report = {
        "project_root": str(ROOT),
        "metric_mapping": metric_mapping,
        "playbook_prometheus_candidates": playbooks,
        "core_files": core,
        "recommendations": recommendations,
    }

    out_file = REPORT_DIR / "prometheus_v8_runtime_hook_inspection.json"
    out_file.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print("========== Metric Mapping ==========")
    print(json.dumps(metric_mapping, ensure_ascii=False, indent=2))

    print("\n========== Playbook Prometheus Candidates Top 40 ==========")
    for item in playbooks[:40]:
        print(
            f"- score={item.get('priority_score')} "
            f"profile={item.get('recommended_profile')} "
            f"prom_marker={item.get('has_prometheus_marker')} "
            f"path={item.get('path')} "
            f"name={item.get('name')}"
        )
        kws = item.get("matched_keywords") or []
        if kws:
            print("  keywords=" + ", ".join(kws[:24]))

    print("\n========== Core File Function/Class Summary ==========")
    for path, info in core.items():
        print(f"\n--- {path} exists={info.get('exists')} ---")
        for d in (info.get("defs") or [])[:35]:
            if "error" in d:
                print("  parse_error:", d["error"])
            else:
                print(f"  L{d.get('line')}: {d.get('type')} {d.get('name')}")
        print(f"  keyword_hits={len(info.get('hits') or [])}")

    print("\n========== Recommendations ==========")
    for idx, rec in enumerate(recommendations, 1):
        print(f"{idx}. {rec}")

    print("\n========== Report ==========")
    print(out_file)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
