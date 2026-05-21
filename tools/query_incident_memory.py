#!/usr/bin/env python3
"""Query v7.1 incident memory."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netaiops.memory_store import query_incident_memories, read_incident_memories


def main() -> int:
    parser = argparse.ArgumentParser(description="Query v7.1 incident memory")
    parser.add_argument("--base-dir", default="/opt/netaiops-webhook")
    parser.add_argument("--family", default="")
    parser.add_argument("--hostname", default="")
    parser.add_argument("--interface", default="")
    parser.add_argument("--q", default="")
    parser.add_argument("--days", type=int, default=0)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    base_dir = Path(args.base_dir)

    records = query_incident_memories(
        base_dir=base_dir,
        family=args.family,
        hostname=args.hostname,
        interface=args.interface,
        q=args.q,
        days=args.days,
        limit=args.limit,
    )

    if args.summary:
        print("request_id\tevent_time\tfamily\thostname\tinterfaces\tcircuit_alias\tdirection")
        for item in records:
            print(
                f"{item.get('request_id','')}\t"
                f"{item.get('event_time','')}\t"
                f"{item.get('family','')}\t"
                f"{item.get('hostname','')}\t"
                f"{','.join(item.get('interfaces') or [])}\t"
                f"{item.get('circuit_alias','')}\t"
                f"{item.get('direction','')}"
            )
        return 0

    print(json.dumps(
        {
            "ok": True,
            "stage": "v7.1_incident_memory_query",
            "total_memory_records": len(read_incident_memories(base_dir)),
            "record_count": len(records),
            "records": records,
        },
        ensure_ascii=False,
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
