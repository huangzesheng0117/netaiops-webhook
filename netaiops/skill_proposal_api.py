"""v7.3 Skill Proposal API helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from netaiops.skill_proposal_builder import (
    build_skill_proposals,
    get_skill_proposal,
    query_skill_proposals,
    read_skill_proposals,
    validate_proposal_safety,
)


def build_skill_proposals_response(
    base_dir: Path,
    limit_clusters: int = 0,
    rebuild_relations: bool = False,
) -> Dict[str, Any]:
    return build_skill_proposals(
        base_dir=base_dir,
        limit_clusters=limit_clusters,
        write=True,
        rebuild_relations=rebuild_relations,
    )


def query_skill_proposals_response(
    base_dir: Path,
    family: str = "",
    proposal_type: str = "",
    verdict: str = "",
    min_score: int = 0,
    limit: int = 20,
    rebuild: bool = False,
    limit_clusters: int = 0,
) -> Dict[str, Any]:
    rebuild_result = None
    if rebuild:
        rebuild_result = build_skill_proposals(
            base_dir=base_dir,
            limit_clusters=limit_clusters,
            write=True,
            rebuild_relations=False,
        )

    rows = query_skill_proposals(
        base_dir=base_dir,
        family=family,
        proposal_type=proposal_type,
        verdict=verdict,
        min_score=min_score,
        limit=limit,
    )

    return {
        "status": "ok",
        "stage": "v7.3_skill_proposal_builder",
        "filters": {
            "family": family,
            "proposal_type": proposal_type,
            "verdict": verdict,
            "min_score": min_score,
            "limit": limit,
        },
        "rebuild_result": rebuild_result,
        "total_proposal_count": len(read_skill_proposals(base_dir)),
        "proposal_count": len(rows),
        "proposals": rows,
    }


def skill_proposal_detail_response(
    proposal_id: str,
    base_dir: Path,
) -> Dict[str, Any]:
    proposal = get_skill_proposal(proposal_id, base_dir=base_dir)
    if not proposal:
        raise FileNotFoundError(f"skill proposal not found: {proposal_id}")

    return {
        "status": "ok",
        "stage": "v7.3_skill_proposal_detail",
        "proposal_id": proposal_id,
        "safety_check": validate_proposal_safety(proposal),
        "proposal": proposal,
    }
