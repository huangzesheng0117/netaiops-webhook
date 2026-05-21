#!/usr/bin/env python3
"""Build v7.1 incident memory from existing request_id artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netaiops.memory_store import (
    build_memory_for_request_id,
    build_memory_from_existing_files,
    validate_no_raw_sensitive_values,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build v7.1 incident memory")
    parser.add_argument("--base-dir", default="/opt/netaiops-webhook")
    parser.add_argument("--rid", "--request-id", dest="request_id", default="")
    parser.add_argument("--all", action="store_true", help="build memory for all review files")
    parser.add_argument("--limit", type=int, default=0, help="limit newest review files when using --all")
    parser.add_argument("--write", action="store_true", help="persist memory to data/memory/incidents.jsonl")
    parser.add_argument("--no-safety-check", action="store_true")
    args = parser.parse_args()

    base_dir = Path(args.base_dir)

    if args.all:
        result = build_memory_from_existing_files(
            base_dir=base_dir,
            limit=args.limit,
            write=args.write,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("ok") else 2

    if not args.request_id:
        parser.error("either --rid or --all is required")

    record = build_memory_for_request_id(
        request_id=args.request_id,
        base_dir=base_dir,
        write=args.write,
    )

    result = {
        "ok": True,
        "stage": "v7.1_incident_memory_build",
        "request_id": args.request_id,
        "written": args.write,
        "memory_file": record.get("memory_file", ""),
        "record": record,
    }

    if not args.no_safety_check:
        result["safety_check"] = validate_no_raw_sensitive_values(record)
        if not result["safety_check"].get("ok"):
            result["ok"] = False

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
