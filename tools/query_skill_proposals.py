#!/usr/bin/env python3
"""Query v7.3 Skill Proposals."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netaiops.skill_proposal_builder import (
    get_skill_proposal,
    query_skill_proposals,
    read_skill_proposals,
    validate_proposal_safety,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Query v7.3 skill proposals")
    parser.add_argument("--base-dir", default="/opt/netaiops-webhook")
    parser.add_argument("--proposal-id", default="")
    parser.add_argument("--family", default="")
    parser.add_argument("--proposal-type", default="")
    parser.add_argument("--verdict", default="")
    parser.add_argument("--min-score", type=int, default=0)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--summary", action="store_true")
    parser.add_argument("--validate-safety", action="store_true")
    args = parser.parse_args()

    base_dir = Path(args.base_dir)

    if args.proposal_id:
        item = get_skill_proposal(args.proposal_id, base_dir=base_dir)
        if not item:
            print(json.dumps({"ok": False, "error": "proposal not found", "proposal_id": args.proposal_id}, ensure_ascii=False, indent=2))
            return 2
        result = {
            "ok": True,
            "stage": "v7.3_skill_proposal_detail",
            "proposal": item,
        }
        if args.validate_safety:
            result["safety_check"] = validate_proposal_safety(item)
            if not result["safety_check"].get("ok"):
                result["ok"] = False

        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("ok") else 2

    rows = query_skill_proposals(
        base_dir=base_dir,
        family=args.family,
        proposal_type=args.proposal_type,
        verdict=args.verdict,
        min_score=args.min_score,
        limit=args.limit,
    )

    if args.summary:
        print("proposal_id\tscore\tverdict\ttype\tstatus\tcandidate_skill_name")
        for item in rows:
            reuse = item.get("reuse_value") or {}
            print(
                f"{item.get('proposal_id')}\t"
                f"{reuse.get('total_score')}\t"
                f"{reuse.get('verdict')}\t"
                f"{item.get('proposal_type')}\t"
                f"{item.get('proposal_status')}\t"
                f"{item.get('candidate_skill_name')}"
            )
        return 0

    print(json.dumps(
        {
            "ok": True,
            "stage": "v7.3_skill_proposal_query",
            "total_proposal_count": len(read_skill_proposals(base_dir)),
            "proposal_count": len(rows),
            "proposals": rows,
        },
        ensure_ascii=False,
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
