"""v7.5 Skill Draft API helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from netaiops.skill_draft_builder import (
    build_skill_drafts,
    get_skill_draft,
    query_skill_drafts,
    read_drafts,
    validate_draft_safety,
)


def build_skill_drafts_response(
    base_dir: Path,
    proposal_id: str = "",
) -> Dict[str, Any]:
    return build_skill_drafts(
        base_dir=base_dir,
        proposal_id=proposal_id,
        write=True,
    )


def query_skill_drafts_response(
    base_dir: Path,
    family: str = "",
    proposal_id: str = "",
    limit: int = 20,
) -> Dict[str, Any]:
    rows = query_skill_drafts(
        base_dir=base_dir,
        family=family,
        proposal_id=proposal_id,
        limit=limit,
    )
    return {
        "status": "ok",
        "stage": "v7.5_skill_draft_builder",
        "total_draft_count": len(read_drafts(base_dir)),
        "draft_count": len(rows),
        "drafts": rows,
    }


def skill_draft_detail_response(
    draft_id: str,
    base_dir: Path,
) -> Dict[str, Any]:
    draft = get_skill_draft(draft_id, base_dir=base_dir)
    if not draft:
        raise FileNotFoundError(f"skill draft not found: {draft_id}")

    return {
        "status": "ok",
        "stage": "v7.5_skill_draft_detail",
        "draft_id": draft_id,
        "safety_check": validate_draft_safety(draft, base_dir=base_dir),
        "draft": draft,
    }
