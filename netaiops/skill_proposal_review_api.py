"""v7.4 Skill Proposal Review API helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from netaiops.skill_proposal_review import (
    create_skill_proposal_review,
    list_pending_proposals,
    proposal_review_status,
    query_skill_proposal_reviews,
    review_summary,
)


def review_summary_response(base_dir: Path) -> Dict[str, Any]:
    return {
        "status": "ok",
        **review_summary(base_dir=base_dir),
    }


def pending_reviews_response(
    base_dir: Path,
    min_score: int = 0,
    limit: int = 20,
) -> Dict[str, Any]:
    rows = list_pending_proposals(
        base_dir=base_dir,
        min_score=min_score,
        limit=limit,
    )
    return {
        "status": "ok",
        "stage": "v7.4_skill_proposal_review_gate",
        "pending_count": len(rows),
        "records": rows,
    }


def query_reviews_response(
    base_dir: Path,
    proposal_id: str = "",
    decision: str = "",
    reviewer: str = "",
    family: str = "",
    limit: int = 20,
) -> Dict[str, Any]:
    rows = query_skill_proposal_reviews(
        base_dir=base_dir,
        proposal_id=proposal_id,
        decision=decision,
        reviewer=reviewer,
        family=family,
        limit=limit,
    )
    return {
        "status": "ok",
        "stage": "v7.4_skill_proposal_review_gate",
        "review_count": len(rows),
        "reviews": rows,
    }


def proposal_review_status_response(
    proposal_id: str,
    base_dir: Path,
) -> Dict[str, Any]:
    return {
        "status": "ok",
        "stage": "v7.4_skill_proposal_review_gate",
        "data": proposal_review_status(
            proposal_id=proposal_id,
            base_dir=base_dir,
        ),
    }


def create_review_response(
    proposal_id: str,
    decision: str,
    reviewer: str,
    comment: str,
    next_action: str,
    base_dir: Path,
) -> Dict[str, Any]:
    review = create_skill_proposal_review(
        proposal_id=proposal_id,
        decision=decision,
        reviewer=reviewer,
        comment=comment,
        next_action=next_action,
        base_dir=base_dir,
    )
    return {
        "status": "ok",
        "stage": "v7.4_skill_proposal_review_gate",
        "review": review,
    }
