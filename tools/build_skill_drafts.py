#!/usr/bin/env python3
"""Build v7.5 draft skill packages from approved proposal reviews."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netaiops.skill_draft_builder import (
    build_skill_drafts,
    query_skill_drafts,
    validate_draft_safety,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build v7.5 skill drafts")
    parser.add_argument("--base-dir", default="/opt/netaiops-webhook")
    parser.add_argument("--proposal-id", default="")
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--summary", action="store_true")
    parser.add_argument("--validate-safety", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()

    base_dir = Path(args.base_dir)

    if args.list:
        rows = query_skill_drafts(base_dir=base_dir, proposal_id=args.proposal_id, limit=args.limit)
        print("draft_id\tstatus\tproposal_id\tcandidate_skill_name")
        for item in rows:
            print(
                f"{item.get('draft_id')}\t"
                f"{item.get('draft_status')}\t"
                f"{item.get('proposal_id')}\t"
                f"{item.get('candidate_skill_name')}"
            )
        return 0

    result = build_skill_drafts(
        base_dir=base_dir,
        proposal_id=args.proposal_id,
        write=not args.no_write,
    )

    if args.validate_safety:
        bad = []
        for item in result.get("drafts") or []:
            check = validate_draft_safety(item, base_dir=base_dir)
            if not check.get("ok"):
                bad.append({
                    "draft_id": item.get("draft_id"),
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
        print("approved_review_count:", result.get("approved_review_count"))
        print("draft_count:", result.get("draft_count"))
        print("error_count:", result.get("error_count"))
        sv = result.get("safety_validation") or {}
        if sv:
            print("safety_validation.ok:", sv.get("ok"))
            print("safety_validation.bad_count:", sv.get("bad_count"))
        for item in result.get("drafts", [])[:10]:
            print(
                f"{item.get('draft_id')}\t"
                f"{item.get('draft_status')}\t"
                f"{item.get('proposal_id')}\t"
                f"{item.get('candidate_skill_name')}"
            )
        return 0 if result.get("ok") else 2

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
