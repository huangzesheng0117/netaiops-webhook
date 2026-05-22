#!/usr/bin/env python3
"""Run v7.9 interface error counter delta recheck."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netaiops.interface_error_delta import (
    list_delta_results,
    read_delta_result,
    run_delta_check,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="v7.9 interface error delta recheck")
    parser.add_argument("--base-dir", default="/opt/netaiops-webhook")
    parser.add_argument("--rid", "--request-id", dest="request_id", default="")
    parser.add_argument("--delay", type=int, default=0)
    parser.add_argument("--no-execute", action="store_true")
    parser.add_argument("--latest-output-file", default="")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--read", action="store_true")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    base_dir = Path(args.base_dir)

    if args.list:
        rows = list_delta_results(base_dir=base_dir, limit=args.limit)
        print("request_id\tstatus\tinterface\tdeltas")
        for item in rows:
            compare = item.get("compare") or {}
            print(
                f"{item.get('request_id')}\t"
                f"{compare.get('status')}\t"
                f"{item.get('interface')}\t"
                f"{compare.get('deltas')}"
            )
        return 0

    if not args.request_id:
        parser.error("--rid is required unless --list is used")

    if args.read:
        data = read_delta_result(args.request_id, base_dir=base_dir)
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0

    latest_output = ""
    if args.latest_output_file:
        latest_output = Path(args.latest_output_file).read_text(encoding="utf-8", errors="ignore")

    result = run_delta_check(
        request_id=args.request_id,
        base_dir=base_dir,
        delay_seconds=args.delay,
        execute=not args.no_execute,
        latest_output_override=latest_output,
    )

    if args.summary:
        compare = result.get("compare") or {}
        print("stage:", result.get("stage"))
        print("request_id:", result.get("request_id"))
        print("ok:", result.get("ok"))
        print("interface:", result.get("interface"))
        print("status:", compare.get("status"))
        print("deltas:", compare.get("deltas"))
        print("result_file:", result.get("result_file"))
        return 0 if result.get("ok") else 2

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
