"""v7.5 Skill Draft Builder.

Build draft skill packages from approved v7.4 proposal reviews.

Safety:
- read v7.3 proposals and v7.4 reviews only
- write draft packages only under data/skill_drafts/
- never write formal skills/
- never auto merge
- never execute device commands
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from netaiops.memory_store import DEFAULT_BASE_DIR, safe_text
from netaiops.skill_proposal_builder import get_skill_proposal
from netaiops.skill_proposal_review import read_reviews

SCHEMA_VERSION = "v7.5.skill_draft.v1"
DRAFT_DIR_REL = Path("data/skill_drafts")
DRAFT_INDEX_REL = Path("data/skill_drafts/drafts.jsonl")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def draft_root(base_dir: Path = DEFAULT_BASE_DIR) -> Path:
    return Path(base_dir) / DRAFT_DIR_REL


def draft_index_file(base_dir: Path = DEFAULT_BASE_DIR) -> Path:
    return Path(base_dir) / DRAFT_INDEX_REL


def safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def safe_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def slugify(value: Any, max_len: int = 90) -> str:
    text = safe_text(value).lower()
    text = re.sub(r"[^a-z0-9_\-\u4e00-\u9fff]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text[:max_len] or "skill_draft"


def stable_id(*parts: Any, prefix: str = "skilldraft") -> str:
    text = "|".join(safe_text(x) for x in parts)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{digest}"


def redact_ipv4_text(text: str) -> str:
    def repl(match):
        ip = match.group(0)
        digest = hashlib.sha256(ip.encode("utf-8")).hexdigest()[:10]
        return f"<ip_hash_{digest}>"

    return re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", repl, text)


def sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(v) for v in value]
    if isinstance(value, str):
        return redact_ipv4_text(value)
    return value


def approved_reviews(base_dir: Path = DEFAULT_BASE_DIR, proposal_id: str = "") -> List[Dict[str, Any]]:
    rows = []
    for item in read_reviews(base_dir):
        if item.get("decision") != "approve":
            continue
        if proposal_id and item.get("proposal_id") != proposal_id:
            continue
        rows.append(item)

    rows.sort(key=lambda x: safe_text(x.get("created_at")), reverse=True)
    return rows


def render_skill_md(proposal: Dict[str, Any], review: Dict[str, Any]) -> str:
    reuse = safe_dict(proposal.get("reuse_value"))
    source_cluster = safe_dict(proposal.get("source_cluster"))
    evidence = safe_list(proposal.get("evidence_requirements"))
    guardrails = safe_list(proposal.get("risks_and_guardrails"))
    acceptance = safe_list(proposal.get("acceptance_criteria"))

    lines = [
        f"# Draft Skill: {proposal.get('candidate_skill_name')}",
        "",
        "This is a v7.5 draft skill generated from an approved v7.4 proposal review.",
        "It is not a formal production skill and must not be copied into skills/ without manual review.",
        "",
        "## Source",
        f"- proposal_id: {proposal.get('proposal_id')}",
        f"- review_id: {review.get('review_id')}",
        f"- family: {proposal.get('family')}",
        f"- proposal_type: {proposal.get('proposal_type')}",
        f"- reuse_score: {reuse.get('total_score')}",
        f"- reuse_verdict: {reuse.get('verdict')}",
        f"- source_cluster_id: {source_cluster.get('cluster_id')}",
        f"- source_cluster_size: {source_cluster.get('size')}",
        "",
        "## Draft Instructions",
        safe_text(proposal.get("proposed_instruction_summary")),
        "",
        "## Evidence Requirements",
    ]

    for item in evidence:
        lines.append(f"- {item}")

    lines += [
        "",
        "## Guardrails",
        "- readonly only",
        "- no config change",
        "- no automatic merge",
        "- no production skill overwrite",
    ]

    for item in guardrails:
        lines.append(f"- {item}")

    lines += [
        "",
        "## Acceptance Criteria",
    ]

    for item in acceptance:
        lines.append(f"- {item}")

    lines += [
        "",
        "## Manual Review Note",
        safe_text(review.get("comment")),
        "",
    ]

    return "\n".join(lines)


def render_commands_yaml(proposal: Dict[str, Any]) -> str:
    family = safe_text(proposal.get("family"))
    trigger = safe_dict(proposal.get("trigger_template"))
    direction = safe_text(trigger.get("direction"))

    if "utilization" in family.lower():
        commands = [
            {
                "capability": "show_interface_detail",
                "command_template": "show interfaces {interface}",
                "readonly": True,
                "required": True,
            },
            {
                "capability": "show_interface_error_counters",
                "command_template": "show interfaces {interface} counters errors",
                "readonly": True,
                "required": True,
            },
            {
                "capability": "show_portchannel_summary",
                "command_template": "show etherchannel summary",
                "readonly": True,
                "required": False,
            },
        ]
    else:
        commands = [
            {
                "capability": "generic_readonly_show",
                "command_template": "show {object}",
                "readonly": True,
                "required": False,
            },
        ]

    lines = [
        "schema_version: v7.5.draft.commands.v1",
        f"family: {family}",
        f"direction: {direction}",
        "readonly_only: true",
        "commands:",
    ]

    for item in commands:
        lines.append(f"  - capability: {item['capability']}")
        lines.append(f"    command_template: \"{item['command_template']}\"")
        lines.append(f"    readonly: {str(item['readonly']).lower()}")
        lines.append(f"    required: {str(item['required']).lower()}")

    return "\n".join(lines) + "\n"


def render_evidence_rules_yaml(proposal: Dict[str, Any]) -> str:
    trigger = safe_dict(proposal.get("trigger_template"))
    requirements = safe_list(proposal.get("evidence_requirements"))

    lines = [
        "schema_version: v7.5.draft.evidence_rules.v1",
        f"family: {proposal.get('family')}",
        f"match_strategy: \"{trigger.get('match_strategy')}\"",
        "required_facts:",
    ]

    if requirements:
        for item in requirements:
            lines.append(f"  - \"{safe_text(item)}\"")
    else:
        lines.append("  - \"basic evidence facts\"")

    lines += [
        "consistency_rules:",
        "  - \"notify_lines, key_findings, recommendations and conclusion must use the same scope\"",
        "  - \"multi-interface alerts must not be reduced to the first interface\"",
        "  - \"business bandwidth and physical bandwidth must be displayed separately when both exist\"",
    ]

    return "\n".join(lines) + "\n"


def render_output_schema(proposal: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_version": "v7.5.draft.output_schema.v1",
        "family": proposal.get("family"),
        "required_output_sections": [
            "summary",
            "evidence_facts",
            "key_findings",
            "recommendations",
            "conclusion",
        ],
        "required_fact_fields": [
            "oper_status",
            "admin_status",
            "input_rate_bps",
            "output_rate_bps",
            "business_bandwidth_bps",
            "alarm_direction",
        ],
        "optional_fact_fields": [
            "multi_interfaces",
            "aggregate_input_rate_bps",
            "aggregate_output_rate_bps",
            "aggregate_input_utilization_percent_business_estimated",
            "aggregate_output_utilization_percent_business_estimated",
            "crc",
            "input_errors",
            "output_errors",
            "output_drops",
        ],
    }


def build_draft_from_review(review: Dict[str, Any], base_dir: Path = DEFAULT_BASE_DIR, write: bool = True) -> Optional[Dict[str, Any]]:
    if review.get("decision") != "approve":
        return None

    proposal_id = safe_text(review.get("proposal_id"))
    proposal = get_skill_proposal(proposal_id, base_dir=base_dir)
    if not proposal:
        raise FileNotFoundError(f"skill proposal not found: {proposal_id}")

    candidate = safe_text(proposal.get("candidate_skill_name"), "skill_draft")
    draft_id = stable_id(proposal_id, review.get("review_id"), candidate)
    folder_name = f"{draft_id}_{slugify(candidate)}"
    folder_rel = DRAFT_DIR_REL / folder_name
    folder = Path(base_dir) / folder_rel

    metadata = {
        "schema_version": SCHEMA_VERSION,
        "draft_id": draft_id,
        "draft_status": "draft_generated_review_required",
        "created_at": utc_now(),
        "candidate_skill_name": candidate,
        "family": proposal.get("family"),
        "proposal_id": proposal_id,
        "review_id": review.get("review_id"),
        "proposal_type": proposal.get("proposal_type"),
        "reuse_value": proposal.get("reuse_value"),
        "source_cluster": proposal.get("source_cluster"),
        "draft_dir": str(folder),
        "draft_files": {
            "SKILL.md": str(folder / "SKILL.md"),
            "commands.yaml": str(folder / "commands.yaml"),
            "evidence_rules.yaml": str(folder / "evidence_rules.yaml"),
            "output_schema.json": str(folder / "output_schema.json"),
            "proposal_snapshot.json": str(folder / "proposal_snapshot.json"),
            "DRAFT_STATUS.md": str(folder / "DRAFT_STATUS.md"),
        },
        "manual_review_required": True,
        "auto_merge_enabled": False,
        "writes_formal_skill": False,
        "safety": {
            "draft_only": True,
            "writes_formal_skill": False,
            "formal_skill_dir": "",
            "readonly_sidecar_only": True,
        },
    }

    metadata = sanitize(metadata)
    proposal_clean = sanitize(proposal)
    review_clean = sanitize(review)

    if write:
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "SKILL.md").write_text(render_skill_md(proposal_clean, review_clean), encoding="utf-8")
        (folder / "commands.yaml").write_text(render_commands_yaml(proposal_clean), encoding="utf-8")
        (folder / "evidence_rules.yaml").write_text(render_evidence_rules_yaml(proposal_clean), encoding="utf-8")
        (folder / "output_schema.json").write_text(
            json.dumps(render_output_schema(proposal_clean), ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        (folder / "proposal_snapshot.json").write_text(
            json.dumps({"proposal": proposal_clean, "review": review_clean}, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        (folder / "DRAFT_STATUS.md").write_text(
            "\n".join([
                "# Draft Status",
                "",
                "status: draft_generated_review_required",
                "auto_merge_enabled: false",
                "writes_formal_skill: false",
                "",
                "This draft package is generated under data/skill_drafts only.",
                "Manual review is required before any formal Skill lifecycle action.",
                "",
            ]),
            encoding="utf-8",
        )

    return metadata


def read_drafts(base_dir: Path = DEFAULT_BASE_DIR) -> List[Dict[str, Any]]:
    path = draft_index_file(base_dir)
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


def write_draft_index(drafts: List[Dict[str, Any]], base_dir: Path = DEFAULT_BASE_DIR) -> Path:
    root = draft_root(base_dir)
    root.mkdir(parents=True, exist_ok=True)
    path = draft_index_file(base_dir)
    with path.open("w", encoding="utf-8") as f:
        for item in drafts:
            f.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
    return path


def build_skill_drafts(base_dir: Path = DEFAULT_BASE_DIR, proposal_id: str = "", write: bool = True) -> Dict[str, Any]:
    reviews = approved_reviews(base_dir=base_dir, proposal_id=proposal_id)

    drafts = []
    errors = []

    for review in reviews:
        try:
            draft = build_draft_from_review(review, base_dir=base_dir, write=write)
            if draft:
                drafts.append(draft)
        except Exception as exc:
            errors.append({
                "proposal_id": review.get("proposal_id"),
                "review_id": review.get("review_id"),
                "error": str(exc),
            })

    if write:
        write_draft_index(drafts, base_dir=base_dir)

    return {
        "ok": len(errors) == 0,
        "stage": "v7.5_skill_draft_builder",
        "approved_review_count": len(reviews),
        "draft_count": len(drafts),
        "error_count": len(errors),
        "errors": errors,
        "drafts": drafts,
        "safety": {
            "auto_merge_enabled": False,
            "writes_formal_skill": False,
            "draft_only": True,
        },
    }


def get_skill_draft(draft_id: str, base_dir: Path = DEFAULT_BASE_DIR) -> Optional[Dict[str, Any]]:
    for item in read_drafts(base_dir):
        if item.get("draft_id") == draft_id:
            return item
    return None


def query_skill_drafts(
    base_dir: Path = DEFAULT_BASE_DIR,
    family: str = "",
    proposal_id: str = "",
    limit: int = 20,
) -> List[Dict[str, Any]]:
    rows = read_drafts(base_dir)

    family_l = safe_text(family).lower()
    proposal_id_l = safe_text(proposal_id).lower()

    result = []
    for item in rows:
        if family_l and family_l not in safe_text(item.get("family")).lower():
            continue
        if proposal_id_l and proposal_id_l != safe_text(item.get("proposal_id")).lower():
            continue
        result.append(item)

    result.sort(key=lambda x: safe_text(x.get("created_at")), reverse=True)

    if limit and limit > 0:
        result = result[:limit]

    return result


def validate_draft_safety(draft: Dict[str, Any], base_dir: Path = DEFAULT_BASE_DIR) -> Dict[str, Any]:
    findings = []

    text = json.dumps(draft, ensure_ascii=False)
    ip_hits = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    if ip_hits:
        findings.append({"type": "raw_ipv4_in_metadata", "samples": ip_hits[:3]})

    if draft.get("auto_merge_enabled") is not False:
        findings.append({"type": "auto_merge_not_false"})

    if draft.get("writes_formal_skill") is not False:
        findings.append({"type": "writes_formal_skill_not_false"})

    draft_dir = safe_text(draft.get("draft_dir"))
    if "/data/skill_drafts/" not in draft_dir:
        findings.append({"type": "draft_dir_not_under_data_skill_drafts", "draft_dir": draft_dir})

    for _, fpath in safe_dict(draft.get("draft_files")).items():
        p = Path(fpath)
        if not p.exists():
            findings.append({"type": "missing_draft_file", "file": fpath})
            continue
        content = p.read_text(encoding="utf-8", errors="ignore")
        ip_hits = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)
        if ip_hits:
            findings.append({"type": "raw_ipv4_in_file", "file": fpath, "samples": ip_hits[:3]})

    return {
        "ok": not findings,
        "findings": findings,
    }
