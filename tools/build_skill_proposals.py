#!/usr/bin/env python3
"""Build v7.3 Skill Proposals."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netaiops.skill_proposal_builder import build_skill_proposals, validate_proposal_safety


def main() -> int:
    parser = argparse.ArgumentParser(description="Build v7.3 skill proposals")
    parser.add_argument("--base-dir", default="/opt/netaiops-webhook")
    parser.add_argument("--limit-clusters", type=int, default=0)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--rebuild-relations", action="store_true")
    parser.add_argument("--summary", action="store_true")
    parser.add_argument("--validate-safety", action="store_true")
    args = parser.parse_args()

    result = build_skill_proposals(
        base_dir=Path(args.base_dir),
        limit_clusters=args.limit_clusters,
        write=not args.no_write,
        rebuild_relations=args.rebuild_relations,
    )

    if args.validate_safety:
        bad = []
        for item in result.get("proposals") or []:
            check = validate_proposal_safety(item)
            if not check.get("ok"):
                bad.append({
                    "proposal_id": item.get("proposal_id"),
                    "findings": check.get("findings"),
                })
        result["safety_validation"] = {
            "ok": not bad,
            "bad_count": len(bad),
            "bad": bad[:10],
        }
        if bad:
            result["ok"] = False

    if args.summary:
        print("stage:", result.get("stage"))
        print("memory_record_count:", result.get("memory_record_count"))
        print("cluster_count:", result.get("cluster_count"))
        print("proposal_count:", result.get("proposal_count"))
        print("skipped_count:", result.get("skipped_count"))
        for item in result.get("proposals", [])[:10]:
            reuse = item.get("reuse_value") or {}
            print(
                f"{item.get('proposal_id')}\t"
                f"{reuse.get('total_score')}\t"
                f"{reuse.get('verdict')}\t"
                f"{item.get('proposal_type')}\t"
                f"{item.get('candidate_skill_name')}"
            )

        sv = result.get("safety_validation") or {}
        if sv:
            print("safety_validation.ok:", sv.get("ok"))
            print("safety_validation.bad_count:", sv.get("bad_count"))
            for bad in sv.get("bad", [])[:10]:
                print("safety_bad:", bad)

        return 0 if result.get("ok") else 2

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
