#!/usr/bin/env python3
"""Build v7.2 incident relation graph from v7.1 incident memory."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netaiops.relation_engine import build_relation_graph


def main() -> int:
    parser = argparse.ArgumentParser(description="Build v7.2 incident relation graph")
    parser.add_argument("--base-dir", default="/opt/netaiops-webhook")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    graph = build_relation_graph(
        base_dir=Path(args.base_dir),
        limit=args.limit,
        write=not args.no_write,
    )

    if args.summary:
        print("stage:", graph.get("stage"))
        print("record_count:", graph.get("record_count"))
        print("relation_count:", graph.get("relation_count"))
        print("cluster_count:", graph.get("cluster_count"))
        print("relation_file:", graph.get("relation_file", ""))
        return 0

    print(json.dumps(graph, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
