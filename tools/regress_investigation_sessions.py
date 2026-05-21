#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netaiops.investigation_policy import evaluate_request_id


RID_RE = re.compile(r"(\d{8}_\d{6}_\d{6}_[0-9a-fA-F]+)")


def collect_request_ids(base_dir: Path, limit: int) -> list[str]:
    candidates = []

    search_dirs = [
        base_dir / "data" / "reviews",
        base_dir / "data" / "execution",
        base_dir / "data" / "plans",
        base_dir / "data" / "analysis",
        base_dir / "data" / "callback",
    ]

    for d in search_dirs:
        if not d.exists():
            continue
        for p in d.rglob("*.json"):
            m = RID_RE.search(p.name)
            if not m:
                continue
            candidates.append((p.stat().st_mtime, m.group(1), p))

    candidates.sort(reverse=True, key=lambda x: x[0])

    seen = set()
    result = []
    for _, rid, _ in candidates:
        if rid in seen:
            continue
        seen.add(rid)
        result.append(rid)
        if len(result) >= limit:
            break

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Regress NetAIOps v6.1 investigation sessions.")
    parser.add_argument("--base-dir", default=str(ROOT), help="Project base directory")
    parser.add_argument("--limit", type=int, default=10, help="Max request_ids to evaluate")
    parser.add_argument("--rid", action="append", default=[], help="Specific request_id to evaluate; can be repeated")
    parser.add_argument("--skip-in-progress", action="store_true", help="Skip sessions whose session_status is in_progress")
    parser.add_argument("--json", action="store_true", help="Print full JSON result")
    args = parser.parse_args()

    base_dir = Path(args.base_dir)
    request_ids = args.rid or collect_request_ids(base_dir, args.limit)

    if not request_ids:
        print("NO_REQUEST_IDS_FOUND")
        return 1

    results = []
    failed = 0

    for rid in request_ids:
        result = evaluate_request_id(rid, base_dir)
        results.append(result)

        verdict = result.get("verdict")
        summary = result.get("summary") or {}
        warnings = result.get("warnings") or []
        violations = result.get("violations") or []

        print("=" * 100)
        print("request_id:", rid)
        print("verdict:", verdict)
        print("session_status:", summary.get("session_status"))
        print("timeline_count:", summary.get("timeline_count"))
        print("stages:", ",".join(summary.get("stages") or []))
        print("session_file:", result.get("session_file"))

        if warnings:
            print("warnings:")
            for item in warnings:
                print("  -", item)

        if violations:
            print("violations:")
            for item in violations:
                print("  -", item)

        if args.skip_in_progress and summary.get("session_status") == "in_progress":
            print("skip_reason: session_status is in_progress")
            continue

        if verdict != "pass":
            failed += 1

    counted_results = [
        item for item in results
        if not (
            args.skip_in_progress
            and (item.get("summary") or {}).get("session_status") == "in_progress"
        )
    ]

    print("=" * 100)
    print("TOTAL:", len(results))
    print("COUNTED:", len(counted_results))
    print("SKIPPED_IN_PROGRESS:", len(results) - len(counted_results))
    print("PASS:", len(counted_results) - failed)
    print("FAIL:", failed)

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
