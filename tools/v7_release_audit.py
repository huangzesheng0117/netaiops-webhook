#!/usr/bin/env python3
"""Run v7.7 release audit."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netaiops.v7_release_audit import audit_v7_release


def main() -> int:
    parser = argparse.ArgumentParser(description="v7.7 release audit")
    parser.add_argument("--base-dir", default="/opt/netaiops-webhook")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    report = audit_v7_release(
        base_dir=Path(args.base_dir),
        write=args.write,
    )

    if args.summary:
        print("stage:", report.get("stage"))
        print("verdict:", report.get("verdict"))
        print("violation_count:", len(report.get("violations") or []))
        print("warning_count:", len(report.get("warnings") or []))
        print("missing_required_files:", len((report.get("required_path_status") or {}).get("missing") or []))
        print("missing_api_routes:", len((report.get("api_route_status") or {}).get("missing") or []))
        print("non_executable_tools:", len((report.get("executable_status") or {}).get("not_executable") or []))
        print("tracked_runtime_count:", (report.get("runtime_git_status") or {}).get("tracked_runtime_count"))
        print("snapshot_file:", report.get("snapshot_file", ""))
        if report.get("violations"):
            print("violations:")
            for item in report.get("violations")[:10]:
                print("  -", item)
        if report.get("warnings"):
            print("warnings:")
            for item in report.get("warnings")[:10]:
                print("  -", item)
        return 0 if report.get("verdict") == "pass" else 2

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report.get("verdict") == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
