"""v7.4 Skill Proposal Review Gate.

为 v7.3 生成的 Skill Proposal 增加人工复核门控。

安全边界：
- 只读取 data/skill_proposals。
- 只写入 data/skill_proposal_reviews。
- 不修改 skills/ 正式目录。
- 不自动 approve、不自动 merge、不执行任何设备命令。
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from netaiops.memory_store import DEFAULT_BASE_DIR, safe_text
from netaiops.skill_proposal_builder import get_skill_proposal, query_skill_proposals

SCHEMA_VERSION = "v7.4.skill_proposal_review.v1"
REVIEW_DIR_REL = Path("data/skill_proposal_reviews")
REVIEW_INDEX_REL = Path("data/skill_proposal_reviews/reviews.jsonl")

ALLOWED_DECISIONS = {
    "approve",
    "reject",
    "defer",
    "needs_more_evidence",
}

TERMINAL_DECISIONS = {
    "approve",
    "reject",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def review_dir(base_dir: Path = DEFAULT_BASE_DIR) -> Path:
    return Path(base_dir) / REVIEW_DIR_REL


def review_index_file(base_dir: Path = DEFAULT_BASE_DIR) -> Path:
    return Path(base_dir) / REVIEW_INDEX_REL


def make_review_id(proposal_id: str, decision: str, reviewer: str, created_at: str) -> str:
    text = "|".join([proposal_id, decision, reviewer, created_at])
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    return f"review_{digest}"


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []

    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except Exception:
                continue
            if isinstance(item, dict):
                rows.append(item)
    return rows


def read_reviews(base_dir: Path = DEFAULT_BASE_DIR) -> List[Dict[str, Any]]:
    return read_jsonl(review_index_file(base_dir))


def write_reviews(reviews: List[Dict[str, Any]], base_dir: Path = DEFAULT_BASE_DIR) -> Path:
    root = review_dir(base_dir)
    root.mkdir(parents=True, exist_ok=True)

    index = review_index_file(base_dir)
    with index.open("w", encoding="utf-8") as f:
        for item in reviews:
            f.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")

    return index


def append_review(review: Dict[str, Any], base_dir: Path = DEFAULT_BASE_DIR) -> Dict[str, Any]:
    root = review_dir(base_dir)
    root.mkdir(parents=True, exist_ok=True)

    detail_file = root / f"{review['review_id']}.review.json"
    review["review_file"] = str(detail_file)

    detail_file.write_text(
        json.dumps(review, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    rows = read_reviews(base_dir)
    rows.append(review)
    write_reviews(rows, base_dir)

    return review


def latest_review_for_proposal(proposal_id: str, base_dir: Path = DEFAULT_BASE_DIR) -> Optional[Dict[str, Any]]:
    rows = [
        item for item in read_reviews(base_dir)
        if item.get("proposal_id") == proposal_id
    ]

    if not rows:
        return None

    rows.sort(key=lambda x: safe_text(x.get("created_at")), reverse=True)
    return rows[0]


def proposal_review_status(proposal_id: str, base_dir: Path = DEFAULT_BASE_DIR) -> Dict[str, Any]:
    proposal = get_skill_proposal(proposal_id, base_dir=base_dir)
    if not proposal:
        raise FileNotFoundError(f"skill proposal not found: {proposal_id}")

    latest = latest_review_for_proposal(proposal_id, base_dir=base_dir)

    if not latest:
        status = "pending_review"
    else:
        decision = latest.get("decision")
        if decision == "approve":
            status = "approved_for_skill_draft"
        elif decision == "reject":
            status = "rejected"
        elif decision == "needs_more_evidence":
            status = "needs_more_evidence"
        else:
            status = "deferred"

    return {
        "proposal_id": proposal_id,
        "review_status": status,
        "latest_review": latest,
        "proposal_status": proposal.get("proposal_status"),
        "candidate_skill_name": proposal.get("candidate_skill_name"),
        "family": proposal.get("family"),
        "manual_review_required": proposal.get("manual_review_required"),
        "auto_merge_enabled": proposal.get("auto_merge_enabled"),
    }


def create_skill_proposal_review(
    proposal_id: str,
    decision: str,
    reviewer: str = "",
    comment: str = "",
    next_action: str = "",
    base_dir: Path = DEFAULT_BASE_DIR,
) -> Dict[str, Any]:
    proposal = get_skill_proposal(proposal_id, base_dir=base_dir)
    if not proposal:
        raise FileNotFoundError(f"skill proposal not found: {proposal_id}")

    decision = safe_text(decision).lower()
    if decision not in ALLOWED_DECISIONS:
        raise ValueError(f"invalid decision={decision}; allowed={sorted(ALLOWED_DECISIONS)}")

    reviewer = safe_text(reviewer, "manual_reviewer")
    comment = safe_text(comment)
    next_action = safe_text(next_action)

    created_at = utc_now()
    review_id = make_review_id(proposal_id, decision, reviewer, created_at)

    review = {
        "schema_version": SCHEMA_VERSION,
        "review_id": review_id,
        "proposal_id": proposal_id,
        "decision": decision,
        "reviewer": reviewer,
        "comment": comment,
        "next_action": next_action,
        "created_at": created_at,
        "candidate_skill_name": proposal.get("candidate_skill_name"),
        "proposal_type": proposal.get("proposal_type"),
        "family": proposal.get("family"),
        "reuse_value": proposal.get("reuse_value"),
        "source_cluster": proposal.get("source_cluster"),
        "manual_review_required": True,
        "auto_merge_enabled": False,
        "writes_formal_skill": False,
        "safety": {
            "review_gate_only": True,
            "writes_formal_skill": False,
            "auto_merge_enabled": False,
            "readonly_sidecar_only": True,
        },
    }

    return append_review(review, base_dir=base_dir)


def query_skill_proposal_reviews(
    base_dir: Path = DEFAULT_BASE_DIR,
    proposal_id: str = "",
    decision: str = "",
    reviewer: str = "",
    family: str = "",
    limit: int = 20,
) -> List[Dict[str, Any]]:
    rows = read_reviews(base_dir)

    proposal_id_l = safe_text(proposal_id).lower()
    decision_l = safe_text(decision).lower()
    reviewer_l = safe_text(reviewer).lower()
    family_l = safe_text(family).lower()

    result = []
    for item in rows:
        if proposal_id_l and proposal_id_l != safe_text(item.get("proposal_id")).lower():
            continue
        if decision_l and decision_l != safe_text(item.get("decision")).lower():
            continue
        if reviewer_l and reviewer_l not in safe_text(item.get("reviewer")).lower():
            continue
        if family_l and family_l not in safe_text(item.get("family")).lower():
            continue
        result.append(item)

    result.sort(key=lambda x: safe_text(x.get("created_at")), reverse=True)

    if limit and limit > 0:
        result = result[:limit]

    return result


def list_pending_proposals(
    base_dir: Path = DEFAULT_BASE_DIR,
    min_score: int = 0,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    proposals = query_skill_proposals(
        base_dir=base_dir,
        min_score=min_score,
        limit=0,
    )

    pending = []
    for item in proposals:
        proposal_id = item.get("proposal_id")
        if not proposal_id:
            continue

        latest = latest_review_for_proposal(proposal_id, base_dir=base_dir)
        if latest and latest.get("decision") in TERMINAL_DECISIONS:
            continue

        status = proposal_review_status(proposal_id, base_dir=base_dir)
        pending.append({
            "proposal_id": proposal_id,
            "candidate_skill_name": item.get("candidate_skill_name"),
            "family": item.get("family"),
            "proposal_type": item.get("proposal_type"),
            "reuse_value": item.get("reuse_value"),
            "review_status": status.get("review_status"),
            "latest_review": latest,
        })

    pending.sort(
        key=lambda x: (x.get("reuse_value") or {}).get("total_score", 0),
        reverse=True,
    )

    if limit and limit > 0:
        pending = pending[:limit]

    return pending


def review_summary(base_dir: Path = DEFAULT_BASE_DIR) -> Dict[str, Any]:
    rows = read_reviews(base_dir)
    counters: Dict[str, int] = {}

    for item in rows:
        decision = safe_text(item.get("decision"), "unknown")
        counters[decision] = counters.get(decision, 0) + 1

    pending = list_pending_proposals(base_dir=base_dir, min_score=0, limit=100000)

    return {
        "stage": "v7.4_skill_proposal_review_gate",
        "review_count": len(rows),
        "decision_counts": counters,
        "pending_count": len(pending),
        "safety": {
            "auto_merge_enabled": False,
            "writes_formal_skill": False,
            "manual_review_required": True,
        },
    }
