#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict


BASE_DIR = Path("/opt/netaiops-webhook")
sys.path.insert(0, str(BASE_DIR))

from netaiops.prometheus_evidence import build_prometheus_evidence_summary


DATA_DIR = BASE_DIR / "data"


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def find_file_by_rid(directory: Path, rid: str, suffix: str):
    matches = list(directory.glob(f"*_{rid}.{suffix}"))
    if matches:
        return matches[0]
    matches = list(directory.glob(f"*{rid}*{suffix}"))
    if matches:
        return matches[0]
    return None


def build_execution_from_existing(rid: str) -> Dict[str, Any]:
    execution_file = find_file_by_rid(DATA_DIR / "execution", rid, "execution.json")
    if execution_file:
        data = load_json(execution_file)
        if data:
            return data

    plan_file = find_file_by_rid(DATA_DIR / "plans", rid, "plan.json")
    if plan_file:
        data = load_json(plan_file)
        if data:
            return data

    return {
        "request_id": rid,
        "family_result": {
            "family": "interface_or_link_utilization_high",
        },
        "target_scope": {},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rid", required=True)
    args = parser.parse_args()

    execution_data = build_execution_from_existing(args.rid)
    execution_data["request_id"] = args.rid

    summary = build_prometheus_evidence_summary(execution_data)

    print("PROMETHEUS_WINDOW_DEBUG")
    print("request_id =", args.rid)
    print("enabled =", summary.get("enabled"))
    print("reason =", summary.get("reason"))
    print("has_metrics =", summary.get("has_metrics"))
    print("direction =", summary.get("direction"))
    print("query_context =", json.dumps(summary.get("query_context", {}), ensure_ascii=False, indent=2))
    print("time_window =", json.dumps(summary.get("time_window", {}), ensure_ascii=False, indent=2))

    for metric in summary.get("metrics", []) or []:
        print("----- metric -----")
        print("name =", metric.get("name"))
        print("query =", metric.get("query"))
        print("summary =", json.dumps(metric.get("summary", {}), ensure_ascii=False, indent=2))
        print("classification =", json.dumps(metric.get("classification", {}), ensure_ascii=False, indent=2))

    print("key_findings =", json.dumps(summary.get("key_findings", []), ensure_ascii=False, indent=2))
    print("recommendations =", json.dumps(summary.get("recommendations", []), ensure_ascii=False, indent=2))
    print("notify_lines =", json.dumps(summary.get("notify_lines", []), ensure_ascii=False, indent=2))

    if summary.get("reason") == "query_failed":
        raise SystemExit("ERROR: prometheus query failed")

    print("PROMETHEUS_WINDOW_DEBUG_CHECK=PASS")


if __name__ == "__main__":
    main()
