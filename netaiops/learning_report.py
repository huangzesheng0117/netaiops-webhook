"""v7.6 Learning Report / Lifecycle Audit.

Summarize v7.1-v7.5 Hermes-style learning loop:

incident_memory -> relation_engine -> skill_proposal -> review_gate -> skill_draft

Safety:
- read existing v7 data only
- write report files only under data/learning_reports/
- never write formal skills/
- never execute MCP or device commands
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from netaiops.memory_store import DEFAULT_BASE_DIR, read_incident_memories, safe_text
from netaiops.relation_engine import read_relation_graph
from netaiops.skill_proposal_builder import read_skill_proposals
from netaiops.skill_proposal_review import read_reviews
from netaiops.skill_draft_builder import read_drafts

SCHEMA_VERSION = "v7.6.learning_report.v1"
REPORT_DIR_REL = Path("data/learning_reports")
REPORT_INDEX_REL = Path("data/learning_reports/reports.jsonl")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def report_dir(base_dir: Path = DEFAULT_BASE_DIR) -> Path:
    return Path(base_dir) / REPORT_DIR_REL


def report_index_file(base_dir: Path = DEFAULT_BASE_DIR) -> Path:
    return Path(base_dir) / REPORT_INDEX_REL


def stable_id(*parts: Any, prefix: str = "learnreport") -> str:
    text = "|".join(safe_text(x) for x in parts)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{digest}"


def safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def safe_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def redact_ipv4_text(text: str) -> str:
    """Replace raw IPv4 strings with stable non-reversible hash tokens."""
    def repl(match):
        ip = match.group(0)
        digest = hashlib.sha256(ip.encode("utf-8")).hexdigest()[:10]
        return f"<ip_hash_{digest}>"

    return re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", repl, text)


def sanitize_report_payload(value: Any) -> Any:
    """Recursively sanitize report payload before writing, rendering or validating."""
    if isinstance(value, dict):
        return {k: sanitize_report_payload(v) for k, v in value.items()}

    if isinstance(value, list):
        return [sanitize_report_payload(v) for v in value]

    if isinstance(value, str):
        return redact_ipv4_text(value)

    return value


def count_by(rows: List[Dict[str, Any]], key: str, limit: int = 10) -> List[Dict[str, Any]]:
    c = Counter()
    for row in rows:
        value = safe_text(row.get(key), "unknown")
        c[value] += 1
    return [{"name": k, "count": v} for k, v in c.most_common(limit)]


def count_nested(rows: List[Dict[str, Any]], path: List[str], limit: int = 10) -> List[Dict[str, Any]]:
    c = Counter()

    for row in rows:
        cur: Any = row
        for key in path:
            if not isinstance(cur, dict):
                cur = None
                break
            cur = cur.get(key)

        value = safe_text(cur, "unknown")
        c[value] += 1

    return [{"name": k, "count": v} for k, v in c.most_common(limit)]


def load_existing_reports(base_dir: Path = DEFAULT_BASE_DIR) -> List[Dict[str, Any]]:
    path = report_index_file(base_dir)
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


def write_report_index(rows: List[Dict[str, Any]], base_dir: Path = DEFAULT_BASE_DIR) -> Path:
    root = report_dir(base_dir)
    root.mkdir(parents=True, exist_ok=True)

    path = report_index_file(base_dir)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    return path


def latest_report(base_dir: Path = DEFAULT_BASE_DIR) -> Optional[Dict[str, Any]]:
    rows = load_existing_reports(base_dir)
    if not rows:
        return None

    rows.sort(key=lambda x: safe_text(x.get("created_at")), reverse=True)
    return rows[0]


def get_report(report_id: str, base_dir: Path = DEFAULT_BASE_DIR) -> Optional[Dict[str, Any]]:
    path = report_dir(base_dir) / f"{report_id}.report.json"
    if path.exists():
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(item, dict):
                return item
        except Exception:
            pass

    for item in load_existing_reports(base_dir):
        if item.get("report_id") == report_id:
            return item

    return None


def top_clusters(graph: Dict[str, Any], limit: int = 10) -> List[Dict[str, Any]]:
    clusters = safe_list(graph.get("clusters"))
    clusters.sort(key=lambda x: int(safe_dict(x).get("size") or 0), reverse=True)

    result = []
    for c in clusters[:limit]:
        if not isinstance(c, dict):
            continue

        result.append({
            "cluster_id": c.get("cluster_id"),
            "size": c.get("size"),
            "family": c.get("family"),
            "hostname": c.get("hostname"),
            "interfaces": c.get("interfaces"),
            "circuit_alias": c.get("circuit_alias"),
            "direction": c.get("direction"),
            "last_event_time": c.get("last_event_time"),
            "avg_dominant_utilization": c.get("avg_dominant_utilization"),
            "max_dominant_utilization": c.get("max_dominant_utilization"),
        })

    return result


def proposal_summary(proposals: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "total": len(proposals),
        "by_type": count_by(proposals, "proposal_type"),
        "by_status": count_by(proposals, "proposal_status"),
        "by_verdict": count_nested(proposals, ["reuse_value", "verdict"]),
        "top_scores": [
            {
                "proposal_id": p.get("proposal_id"),
                "candidate_skill_name": p.get("candidate_skill_name"),
                "family": p.get("family"),
                "score": safe_dict(p.get("reuse_value")).get("total_score"),
                "verdict": safe_dict(p.get("reuse_value")).get("verdict"),
                "manual_review_required": p.get("manual_review_required"),
                "auto_merge_enabled": p.get("auto_merge_enabled"),
            }
            for p in sorted(
                proposals,
                key=lambda x: int(safe_dict(x.get("reuse_value")).get("total_score") or 0),
                reverse=True,
            )[:10]
        ],
    }


def review_summary(reviews: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "total": len(reviews),
        "by_decision": count_by(reviews, "decision"),
        "latest_reviews": [
            {
                "review_id": r.get("review_id"),
                "proposal_id": r.get("proposal_id"),
                "decision": r.get("decision"),
                "reviewer": r.get("reviewer"),
                "created_at": r.get("created_at"),
                "candidate_skill_name": r.get("candidate_skill_name"),
            }
            for r in sorted(reviews, key=lambda x: safe_text(x.get("created_at")), reverse=True)[:10]
        ],
    }


def draft_summary(drafts: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "total": len(drafts),
        "by_status": count_by(drafts, "draft_status"),
        "drafts": [
            {
                "draft_id": d.get("draft_id"),
                "draft_status": d.get("draft_status"),
                "proposal_id": d.get("proposal_id"),
                "review_id": d.get("review_id"),
                "candidate_skill_name": d.get("candidate_skill_name"),
                "family": d.get("family"),
                "auto_merge_enabled": d.get("auto_merge_enabled"),
                "writes_formal_skill": d.get("writes_formal_skill"),
            }
            for d in drafts[:10]
        ],
    }


def build_health_findings(
    memories: List[Dict[str, Any]],
    graph: Dict[str, Any],
    proposals: List[Dict[str, Any]],
    reviews: List[Dict[str, Any]],
    drafts: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    findings = []

    if not memories:
        findings.append({
            "level": "warning",
            "code": "no_incident_memory",
            "message": "尚未生成 incident_memory，v7 学习闭环缺少基础样本。",
        })

    if memories and int(graph.get("relation_count") or 0) == 0:
        findings.append({
            "level": "warning",
            "code": "no_relations",
            "message": "已有 incident_memory，但 relation_engine 未形成有效关联关系。",
        })

    if int(graph.get("cluster_count") or 0) > 0 and not proposals:
        findings.append({
            "level": "warning",
            "code": "no_skill_proposals",
            "message": "已有重复告警簇，但尚未生成 Skill Proposal。",
        })

    pending = [
        p for p in proposals
        if p.get("manual_review_required") is True and p.get("auto_merge_enabled") is False
    ]

    if pending:
        findings.append({
            "level": "info",
            "code": "proposal_pending_manual_review",
            "message": f"当前有 {len(pending)} 条 proposal 等待人工复核。",
        })

    approved = [r for r in reviews if r.get("decision") == "approve"]

    if approved and not drafts:
        findings.append({
            "level": "warning",
            "code": "approved_without_draft",
            "message": "已有 approve 的 proposal review，但尚未生成 draft skill。",
        })

    unsafe_drafts = [
        d for d in drafts
        if d.get("auto_merge_enabled") is not False or d.get("writes_formal_skill") is not False
    ]

    if unsafe_drafts:
        findings.append({
            "level": "critical",
            "code": "unsafe_draft_flags",
            "message": "存在 draft 的 auto_merge 或 writes_formal_skill 安全标记异常。",
        })

    if not findings:
        findings.append({
            "level": "info",
            "code": "learning_loop_healthy",
            "message": "v7 学习闭环旁路状态正常，未发现阻塞性问题。",
        })

    return findings


def recommended_next_actions(
    proposals: List[Dict[str, Any]],
    reviews: List[Dict[str, Any]],
    drafts: List[Dict[str, Any]],
) -> List[str]:
    actions = []

    reviewed_proposal_ids = {safe_text(r.get("proposal_id")) for r in reviews}
    high_value_unreviewed = []

    for p in proposals:
        reuse = safe_dict(p.get("reuse_value"))
        score = int(reuse.get("total_score") or 0)
        if score >= 65 and safe_text(p.get("proposal_id")) not in reviewed_proposal_ids:
            high_value_unreviewed.append(p)

    if high_value_unreviewed:
        actions.append(f"优先人工复核 {len(high_value_unreviewed)} 条中高价值 Skill Proposal。")

    approved_ids = {safe_text(r.get("proposal_id")) for r in reviews if r.get("decision") == "approve"}
    drafted_ids = {safe_text(d.get("proposal_id")) for d in drafts}
    approved_without_draft = approved_ids - drafted_ids

    if approved_without_draft:
        actions.append(f"为 {len(approved_without_draft)} 条已 approve proposal 生成 v7.5 draft skill。")

    if drafts:
        actions.append("人工检查 data/skill_drafts 下的草稿包，确认是否进入正式 Skill 生命周期。")
    else:
        actions.append("当前没有 draft skill；如果需要验证 v7.5，可先人工 approve 一条低风险 proposal。")

    actions.append("继续保持 v7 旁路运行，不自动写入正式 skills/，不改变生产主链路。")
    actions.append("Git 收尾前执行 v7_all、v6_all 和敏感信息审计。")

    return actions


def render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        f"# NetAIOps webhook v7.6 Learning Report",
        "",
        f"- report_id: {report.get('report_id')}",
        f"- created_at: {report.get('created_at')}",
        f"- stage: {report.get('stage')}",
        "",
        "## Lifecycle Counts",
    ]

    counts = report.get("lifecycle_counts") or {}
    for key in [
        "incident_memory_count",
        "relation_count",
        "cluster_count",
        "proposal_count",
        "review_count",
        "draft_count",
    ]:
        lines.append(f"- {key}: {counts.get(key)}")

    lines += ["", "## Top Families"]
    for item in safe_list(report.get("incident_memory_summary", {}).get("top_families")):
        lines.append(f"- {item.get('name')}: {item.get('count')}")

    lines += ["", "## Top Clusters"]
    for item in safe_list(report.get("relation_summary", {}).get("top_clusters")):
        lines.append(
            f"- {item.get('cluster_id')} size={item.get('size')} "
            f"family={item.get('family')} circuit={item.get('circuit_alias')}"
        )

    lines += ["", "## Proposal Summary"]
    ps = report.get("proposal_summary") or {}
    lines.append(f"- total: {ps.get('total')}")
    for item in safe_list(ps.get("by_verdict")):
        lines.append(f"- verdict {item.get('name')}: {item.get('count')}")

    lines += ["", "## Findings"]
    for item in safe_list(report.get("findings")):
        lines.append(f"- [{item.get('level')}] {item.get('code')}: {item.get('message')}")

    lines += ["", "## Recommended Next Actions"]
    for item in safe_list(report.get("recommended_next_actions")):
        lines.append(f"- {item}")

    lines += ["", "## Safety"]
    for k, v in safe_dict(report.get("safety")).items():
        lines.append(f"- {k}: {v}")

    return "\n".join(lines) + "\n"


def validate_report_safety(report: Dict[str, Any]) -> Dict[str, Any]:
    text = json.dumps(report, ensure_ascii=False)
    findings = []

    ip_hits = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    if ip_hits:
        findings.append({"type": "raw_ipv4", "count": len(ip_hits), "samples": ip_hits[:3]})

    safety = safe_dict(report.get("safety"))
    if safety.get("writes_formal_skill") is not False:
        findings.append({"type": "writes_formal_skill_not_false"})
    if safety.get("auto_merge_enabled") is not False:
        findings.append({"type": "auto_merge_enabled_not_false"})
    if safety.get("executes_device_commands") is not False:
        findings.append({"type": "executes_device_commands_not_false"})

    return {
        "ok": not findings,
        "findings": findings,
    }


def build_learning_report(base_dir: Path = DEFAULT_BASE_DIR, write: bool = True) -> Dict[str, Any]:
    base_dir = Path(base_dir)

    memories = read_incident_memories(base_dir)
    graph = read_relation_graph(base_dir)
    proposals = read_skill_proposals(base_dir)
    reviews = read_reviews(base_dir)
    drafts = read_drafts(base_dir)

    created_at = utc_now()
    report_id = stable_id(created_at, len(memories), len(proposals), len(reviews), len(drafts))

    report = {
        "schema_version": SCHEMA_VERSION,
        "stage": "v7.6_learning_report",
        "report_id": report_id,
        "created_at": created_at,
        "lifecycle_counts": {
            "incident_memory_count": len(memories),
            "relation_count": int(graph.get("relation_count") or 0),
            "cluster_count": int(graph.get("cluster_count") or 0),
            "proposal_count": len(proposals),
            "review_count": len(reviews),
            "draft_count": len(drafts),
        },
        "incident_memory_summary": {
            "top_families": count_by(memories, "family"),
            "top_hosts": count_by(memories, "hostname"),
            "top_directions": count_by(memories, "direction"),
        },
        "relation_summary": {
            "generated_at": graph.get("generated_at"),
            "record_count": graph.get("record_count", 0),
            "relation_count": graph.get("relation_count", 0),
            "cluster_count": graph.get("cluster_count", 0),
            "top_clusters": top_clusters(graph),
        },
        "proposal_summary": proposal_summary(proposals),
        "review_summary": review_summary(reviews),
        "draft_summary": draft_summary(drafts),
        "findings": build_health_findings(memories, graph, proposals, reviews, drafts),
        "recommended_next_actions": recommended_next_actions(proposals, reviews, drafts),
        "safety": {
            "source": "v7_sidecar_files_only",
            "readonly_sidecar_only": True,
            "executes_device_commands": False,
            "writes_formal_skill": False,
            "auto_merge_enabled": False,
            "contains_raw_device_ip": False,
        },
    }

    report = sanitize_report_payload(report)

    if write:
        root = report_dir(base_dir)
        root.mkdir(parents=True, exist_ok=True)

        json_file = root / f"{report_id}.report.json"
        md_file = root / f"{report_id}.report.md"

        report["report_files"] = {
            "json": str(json_file),
            "markdown": str(md_file),
        }

        report = sanitize_report_payload(report)

        json_file.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        md_file.write_text(render_markdown(report), encoding="utf-8")

        rows = load_existing_reports(base_dir)
        rows.append({
            "report_id": report_id,
            "created_at": created_at,
            "stage": report.get("stage"),
            "lifecycle_counts": report.get("lifecycle_counts"),
            "report_files": report.get("report_files"),
            "safety": report.get("safety"),
        })
        write_report_index(rows, base_dir)

    return report


def list_learning_reports(base_dir: Path = DEFAULT_BASE_DIR, limit: int = 20) -> List[Dict[str, Any]]:
    rows = load_existing_reports(base_dir)
    rows.sort(key=lambda x: safe_text(x.get("created_at")), reverse=True)

    if limit and limit > 0:
        return rows[:limit]

    return rows
