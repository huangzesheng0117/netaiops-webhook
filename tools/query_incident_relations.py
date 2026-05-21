#!/usr/bin/env python3
"""Query v7.2 incident relation graph."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netaiops.relation_engine import find_relations_for_request_id, query_relation_graph


def main() -> int:
    parser = argparse.ArgumentParser(description="Query v7.2 incident relation graph")
    parser.add_argument("--base-dir", default="/opt/netaiops-webhook")
    parser.add_argument("--rid", "--request-id", dest="request_id", default="")
    parser.add_argument("--family", default="")
    parser.add_argument("--hostname", default="")
    parser.add_argument("--interface", default="")
    parser.add_argument("--relation-type", default="")
    parser.add_argument("--min-score", type=int, default=0)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--rebuild", action="store_true")
    parser.add_argument("--rebuild-limit", type=int, default=0)
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    base_dir = Path(args.base_dir)

    if args.request_id:
        result = find_relations_for_request_id(
            request_id=args.request_id,
            base_dir=base_dir,
            rebuild=args.rebuild,
            limit=args.rebuild_limit,
        )
    else:
        result = query_relation_graph(
            base_dir=base_dir,
            family=args.family,
            hostname=args.hostname,
            interface=args.interface,
            relation_type=args.relation_type,
            min_score=args.min_score,
            limit=args.limit,
            rebuild=args.rebuild,
            rebuild_limit=args.rebuild_limit,
        )

    if args.summary:
        print("stage:", result.get("stage"))
        print("relation_count:", result.get("relation_count"))
        print("cluster_count:", result.get("cluster_count"))
        for rel in result.get("relations", [])[:args.limit]:
            print(
                f"{rel.get('score')}\t"
                f"{rel.get('relation_type')}\t"
                f"{rel.get('source_request_id')}\t"
                f"{rel.get('target_request_id')}\t"
                f"{','.join(rel.get('reasons') or [])}"
            )
        return 0

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
