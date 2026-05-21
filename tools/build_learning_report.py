#!/usr/bin/env python3
"""Build v7.6 Learning Report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netaiops.learning_report import (
    build_learning_report,
    list_learning_reports,
    validate_report_safety,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build v7.6 learning report")
    parser.add_argument("--base-dir", default="/opt/netaiops-webhook")
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--summary", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--validate-safety", action="store_true")
    args = parser.parse_args()

    base_dir = Path(args.base_dir)

    if args.list:
        rows = list_learning_reports(base_dir=base_dir, limit=args.limit)
        print("report_id\tcreated_at\tmemory\trelations\tclusters\tproposals\treviews\tdrafts")
        for item in rows:
            counts = item.get("lifecycle_counts") or {}
            print(
                f"{item.get('report_id')}\t"
                f"{item.get('created_at')}\t"
                f"{counts.get('incident_memory_count')}\t"
                f"{counts.get('relation_count')}\t"
                f"{counts.get('cluster_count')}\t"
                f"{counts.get('proposal_count')}\t"
                f"{counts.get('review_count')}\t"
                f"{counts.get('draft_count')}"
            )
        return 0

    report = build_learning_report(base_dir=base_dir, write=not args.no_write)
    safety = validate_report_safety(report)

    if args.summary:
        counts = report.get("lifecycle_counts") or {}
        print("stage:", report.get("stage"))
        print("report_id:", report.get("report_id"))
        print("incident_memory_count:", counts.get("incident_memory_count"))
        print("relation_count:", counts.get("relation_count"))
        print("cluster_count:", counts.get("cluster_count"))
        print("proposal_count:", counts.get("proposal_count"))
        print("review_count:", counts.get("review_count"))
        print("draft_count:", counts.get("draft_count"))
        if args.validate_safety:
            print("safety.ok:", safety.get("ok"))
            print("safety.findings:", safety.get("findings"))
        return 0 if safety.get("ok") else 2

    result = {
        "ok": safety.get("ok"),
        "stage": "v7.6_learning_report",
        "safety_check": safety,
        "report": report,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
