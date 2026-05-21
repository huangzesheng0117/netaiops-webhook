#!/usr/bin/env python3
"""Review v7.3 skill proposal in v7.4 review gate."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netaiops.skill_proposal_review import (
    ALLOWED_DECISIONS,
    create_skill_proposal_review,
    list_pending_proposals,
    proposal_review_status,
    query_skill_proposal_reviews,
    review_summary,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="v7.4 skill proposal review gate")
    parser.add_argument("--base-dir", default="/opt/netaiops-webhook")
    parser.add_argument("--proposal-id", default="")
    parser.add_argument("--decision", default="")
    parser.add_argument("--reviewer", default="manual_reviewer")
    parser.add_argument("--comment", default="")
    parser.add_argument("--next-action", default="")
    parser.add_argument("--pending", action="store_true")
    parser.add_argument("--reviews", action="store_true")
    parser.add_argument("--summary", action="store_true")
    parser.add_argument("--min-score", type=int, default=0)
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()

    base_dir = Path(args.base_dir)

    try:
        if args.summary:
            print(json.dumps(review_summary(base_dir=base_dir), ensure_ascii=False, indent=2))
            return 0

        if args.pending:
            rows = list_pending_proposals(
                base_dir=base_dir,
                min_score=args.min_score,
                limit=args.limit,
            )
            print("proposal_id\tscore\tstatus\tcandidate_skill_name")
            for item in rows:
                reuse = item.get("reuse_value") or {}
                print(
                    f"{item.get('proposal_id')}\t"
                    f"{reuse.get('total_score')}\t"
                    f"{item.get('review_status')}\t"
                    f"{item.get('candidate_skill_name')}"
                )
            return 0

        if args.reviews:
            rows = query_skill_proposal_reviews(
                base_dir=base_dir,
                proposal_id=args.proposal_id,
                limit=args.limit,
            )
            print("review_id\tproposal_id\tdecision\treviewer\tcreated_at")
            for item in rows:
                print(
                    f"{item.get('review_id')}\t"
                    f"{item.get('proposal_id')}\t"
                    f"{item.get('decision')}\t"
                    f"{item.get('reviewer')}\t"
                    f"{item.get('created_at')}"
                )
            return 0

        if args.proposal_id and args.decision:
            if args.decision not in ALLOWED_DECISIONS:
                raise SystemExit(f"invalid decision={args.decision}, allowed={sorted(ALLOWED_DECISIONS)}")

            review = create_skill_proposal_review(
                proposal_id=args.proposal_id,
                decision=args.decision,
                reviewer=args.reviewer,
                comment=args.comment,
                next_action=args.next_action,
                base_dir=base_dir,
            )
            print(json.dumps(
                {
                    "ok": True,
                    "stage": "v7.4_skill_proposal_review_gate",
                    "review_id": review.get("review_id"),
                    "proposal_id": review.get("proposal_id"),
                    "decision": review.get("decision"),
                    "reviewer": review.get("reviewer"),
                    "review_file": review.get("review_file"),
                },
                ensure_ascii=False,
                indent=2,
            ))
            return 0

        if args.proposal_id:
            print(json.dumps(
                proposal_review_status(args.proposal_id, base_dir=base_dir),
                ensure_ascii=False,
                indent=2,
            ))
            return 0

        parser.error("use --summary, --pending, --reviews, --proposal-id, or --proposal-id with --decision")
        return 2

    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
