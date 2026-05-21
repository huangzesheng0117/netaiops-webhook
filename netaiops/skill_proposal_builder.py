"""v7.3 Skill Proposal Builder.

Hermes-style Learning Ops 第三阶段：
基于 v7.1 incident_memory 与 v7.2 relation_engine，识别哪些重复告警/经验具备沉淀为 Skill 的价值。

安全边界：
- 只读取 data/memory/incidents.jsonl 与 data/memory/incident_relations.json。
- 不访问设备，不执行 MCP/Netmiko 命令。
- 不自动写入 skills/ 正式目录。
- 只生成 data/skill_proposals 下的候选 proposal，必须人工复核后才能进入后续 Skill 生命周期。
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from netaiops.memory_store import DEFAULT_BASE_DIR, read_incident_memories, safe_text
from netaiops.relation_engine import build_relation_graph, read_relation_graph

SCHEMA_VERSION = "v7.3.skill_proposal.v1"
PROPOSAL_DIR_REL = Path("data/skill_proposals")
PROPOSAL_INDEX_REL = Path("data/skill_proposals/proposals.jsonl")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def proposal_dir(base_dir: Path = DEFAULT_BASE_DIR) -> Path:
    return Path(base_dir) / PROPOSAL_DIR_REL


def proposal_index_file(base_dir: Path = DEFAULT_BASE_DIR) -> Path:
    return Path(base_dir) / PROPOSAL_INDEX_REL


def slugify(value: Any, max_len: int = 80) -> str:
    text = safe_text(value).lower()
    text = re.sub(r"[^a-z0-9_\-\u4e00-\u9fff]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text[:max_len] or "unknown"


def stable_id(*parts: Any, prefix: str = "skillprop") -> str:
    text = "|".join(safe_text(x) for x in parts)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{digest}"


def redact_ipv4_text(text: str) -> str:
    """Replace raw IPv4 strings with stable non-reversible hash tokens."""
    def repl(match):
        ip = match.group(0)
        digest = hashlib.sha256(ip.encode("utf-8")).hexdigest()[:10]
        return f"<ip_hash_{digest}>"

    return re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", repl, text)


def redact_sensitive_values(value: Any) -> Any:
    """Recursively sanitize proposal payload before writing or validating."""
    if isinstance(value, dict):
        return {k: redact_sensitive_values(v) for k, v in value.items()}

    if isinstance(value, list):
        return [redact_sensitive_values(v) for v in value]

    if isinstance(value, str):
        return redact_ipv4_text(value)

    return value


def safe_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def safe_float(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        text = safe_text(value)
        if not text:
            return None
        return float(text)
    except Exception:
        return None


def records_by_request_id(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {safe_text(item.get("request_id")): item for item in records if item.get("request_id")}


def get_fact(record: Dict[str, Any], key: str, default: Any = None) -> Any:
    facts = safe_dict(record.get("evidence_facts"))
    return facts.get(key, default)


def dominant_util(record: Dict[str, Any]) -> Optional[float]:
    direction = safe_text(record.get("direction")).lower()
    facts = safe_dict(record.get("evidence_facts"))

    ordered = []
    if direction == "out":
        ordered += [
            facts.get("aggregate_output_utilization_percent_business_estimated"),
            facts.get("output_utilization_percent_business_estimated"),
            facts.get("output_utilization_percent_estimated"),
        ]
    elif direction == "in":
        ordered += [
            facts.get("aggregate_input_utilization_percent_business_estimated"),
            facts.get("input_utilization_percent_business_estimated"),
            facts.get("input_utilization_percent_estimated"),
        ]

    ordered += [
        facts.get("aggregate_output_utilization_percent_business_estimated"),
        facts.get("aggregate_input_utilization_percent_business_estimated"),
        facts.get("output_utilization_percent_business_estimated"),
        facts.get("input_utilization_percent_business_estimated"),
        facts.get("output_utilization_percent_estimated"),
        facts.get("input_utilization_percent_estimated"),
    ]

    for item in ordered:
        val = safe_float(item)
        if val is not None:
            return val

    return None


def existing_skill_index(base_dir: Path = DEFAULT_BASE_DIR) -> Dict[str, Dict[str, Any]]:
    root = Path(base_dir) / "skills"
    result: Dict[str, Dict[str, Any]] = {}

    if not root.exists():
        return result

    for path in root.iterdir():
        if not path.is_dir():
            continue

        text_parts = []
        for name in ("SKILL.md", "commands.yaml", "evidence_rules.yaml", "output_schema.json"):
            fp = path / name
            if fp.exists():
                try:
                    text_parts.append(fp.read_text(encoding="utf-8", errors="ignore"))
                except Exception:
                    pass

        blob = "\n".join(text_parts)
        result[path.name] = {
            "skill_name": path.name,
            "path": str(path.relative_to(base_dir)),
            "content_preview": blob[:2000],
        }

    return result


def find_existing_skill_for_family(family: str, base_dir: Path = DEFAULT_BASE_DIR) -> Dict[str, Any]:
    family_l = safe_text(family).lower()
    if not family_l:
        return {}

    for skill_name, item in existing_skill_index(base_dir).items():
        blob = (skill_name + "\n" + safe_text(item.get("content_preview"))).lower()
        if family_l in blob:
            return item

        if "interface_utilization" in skill_name and "utilization" in family_l:
            return item

    return {}


def cluster_records(cluster: Dict[str, Any], memory_index: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    result = []
    for rid in safe_list(cluster.get("request_ids")):
        rec = memory_index.get(safe_text(rid))
        if rec:
            result.append(rec)
    return result


def score_reuse_value(cluster: Dict[str, Any], records: List[Dict[str, Any]], base_dir: Path = DEFAULT_BASE_DIR) -> Dict[str, Any]:
    reasons: List[str] = []
    scores: Dict[str, int] = {}

    size = int(cluster.get("size") or len(records) or 0)
    if size >= 5:
        scores["recurrence"] = 35
        reasons.append("同一签名重复出现次数较多，具备沉淀为可复用经验的价值")
    elif size >= 3:
        scores["recurrence"] = 25
        reasons.append("同一签名出现多次，可考虑沉淀为增强规则")
    elif size >= 2:
        scores["recurrence"] = 15
        reasons.append("同一签名至少出现两次，可作为候选观察项")
    else:
        scores["recurrence"] = 0

    completed = 0
    total_commands = 0
    hard_error = 0
    parsed_enabled = 0
    fact_rich = 0

    for rec in records:
        cmd = safe_dict(rec.get("command_summary"))
        total_commands += int(cmd.get("total_commands") or 0)
        completed += int(cmd.get("completed_commands") or 0)
        hard_error += int(cmd.get("hard_error_count") or 0)

        parser = safe_dict(rec.get("parser_summary"))
        if parser.get("parsed_facts_enabled"):
            parsed_enabled += 1

        facts = safe_dict(rec.get("evidence_facts"))
        if len(facts) >= 5:
            fact_rich += 1

    if total_commands and completed >= total_commands and hard_error == 0:
        scores["execution_quality"] = 20
        reasons.append("历史样例取证命令完成度高，且无 hard_error")
    elif completed > 0:
        scores["execution_quality"] = 10
        reasons.append("历史样例存在可用取证结果，但完成度需要继续观察")
    else:
        scores["execution_quality"] = 0

    if records and parsed_enabled >= max(1, len(records) // 2):
        scores["parser_coverage"] = 15
        reasons.append("多数样例已具备 parsed facts，可支撑结构化 Skill 规则")
    elif fact_rich:
        scores["parser_coverage"] = 8
        reasons.append("样例中存在较丰富 evidence facts，可作为 raw fallback 经验来源")
    else:
        scores["parser_coverage"] = 0

    utils = [dominant_util(x) for x in records]
    utils = [x for x in utils if x is not None]
    if utils and max(utils) >= 80:
        scores["business_signal"] = 15
        reasons.append("历史样例出现高于阈值的业务口径利用率，具备业务告警意义")
    elif utils:
        scores["business_signal"] = 8
        reasons.append("历史样例存在明确利用率指标，但业务严重度偏弱")
    else:
        scores["business_signal"] = 0

    specificity = 0
    if safe_text(cluster.get("family")):
        specificity += 5
    if safe_text(cluster.get("hostname")):
        specificity += 5
    if safe_list(cluster.get("interfaces")):
        specificity += 5
    if safe_text(cluster.get("circuit_alias")):
        specificity += 5

    scores["specificity"] = min(specificity, 20)
    if specificity >= 15:
        reasons.append("family、设备、接口或线路信息较完整，便于形成稳定触发条件")

    existing = find_existing_skill_for_family(safe_text(cluster.get("family")), base_dir=base_dir)
    if existing:
        scores["novelty"] = 5
        reasons.append(f"已存在相关 Skill：{existing.get('skill_name')}，更适合生成增强型 Proposal")
    else:
        scores["novelty"] = 15
        reasons.append("当前未发现明确匹配的既有 Skill，可作为新增 Skill 候选")

    total = sum(scores.values())
    if total >= 80:
        verdict = "high_reuse_value"
    elif total >= 65:
        verdict = "medium_reuse_value"
    elif total >= 50:
        verdict = "low_reuse_value_observe"
    else:
        verdict = "not_recommended"

    return {
        "total_score": total,
        "verdict": verdict,
        "scores": scores,
        "reasons": reasons,
        "existing_skill": existing,
    }


def infer_proposal_type(score_result: Dict[str, Any]) -> str:
    existing = safe_dict(score_result.get("existing_skill"))
    if existing:
        return "enhance_existing_skill"
    return "new_skill_candidate"


def build_candidate_skill_name(cluster: Dict[str, Any], score_result: Dict[str, Any]) -> str:
    existing = safe_dict(score_result.get("existing_skill"))
    family = slugify(cluster.get("family"), max_len=50)
    circuit = slugify(cluster.get("circuit_alias"), max_len=40)
    direction = slugify(cluster.get("direction"), max_len=20)

    if existing:
        base = safe_text(existing.get("skill_name"), "existing_skill")
        if circuit:
            return f"{base}_enhance_{circuit}_{direction}".strip("_")
        return f"{base}_enhance_{family}_{direction}".strip("_")

    if circuit:
        return f"{family}_{circuit}_{direction}".strip("_")

    return f"{family}_{direction}".strip("_")


def extract_observed_commands(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # incident_memory 默认不保存完整 command_results；这里从 source_files 指向的 execution 只取命令元数据，
    # 不复制完整设备输出。
    result: List[Dict[str, Any]] = []
    seen = set()

    for rec in records:
        command_summary = safe_dict(rec.get("command_summary"))
        if int(command_summary.get("total_commands") or 0) <= 0:
            continue

        item = {
            "request_id": rec.get("request_id"),
            "execution_status": command_summary.get("execution_status"),
            "total_commands": command_summary.get("total_commands"),
            "completed_commands": command_summary.get("completed_commands"),
            "failed_commands": command_summary.get("failed_commands"),
            "hard_error_count": command_summary.get("hard_error_count"),
        }

        key = json.dumps(item, ensure_ascii=False, sort_keys=True)
        if key not in seen:
            seen.add(key)
            result.append(item)

    return result[:10]


def extract_observed_facts(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    keys = [
        "business_bandwidth_text",
        "business_bandwidth_bps",
        "multi_interfaces",
        "aggregate_input_rate_bps",
        "aggregate_output_rate_bps",
        "aggregate_input_utilization_percent_business_estimated",
        "aggregate_output_utilization_percent_business_estimated",
        "input_utilization_percent_business_estimated",
        "output_utilization_percent_business_estimated",
        "crc",
        "input_errors",
        "output_errors",
        "output_drops",
        "parsed_facts_enabled",
        "parsed_fact_sources",
    ]

    result: Dict[str, Any] = {}

    for key in keys:
        values = []
        seen = set()
        for rec in records:
            facts = safe_dict(rec.get("evidence_facts"))
            if key not in facts:
                continue
            val = facts.get(key)
            stable = json.dumps(val, ensure_ascii=False, sort_keys=True)
            if stable in seen:
                continue
            seen.add(stable)
            values.append(val)
        if values:
            result[key] = values[:5]

    return result


def build_trigger_template(cluster: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "family": cluster.get("family"),
        "direction": cluster.get("direction"),
        "circuit_alias": cluster.get("circuit_alias"),
        "interfaces": cluster.get("interfaces") or [],
        "match_strategy": "family + optional circuit_alias/interface/direction",
        "notes": "该模板仅用于人工复核，不会自动写入正式 Skill。",
    }


def build_evidence_requirements(cluster: Dict[str, Any]) -> List[str]:
    family = safe_text(cluster.get("family"))
    direction = safe_text(cluster.get("direction"))

    req = [
        "接口 oper/admin 状态",
        "接口 input/output 速率",
        "接口错误/丢弃计数",
        "告警口径带宽与设备物理带宽区分",
    ]

    if "utilization" in family or "utilization" in family.lower():
        req.append("按告警方向计算业务口径利用率")
        req.append("多接口场景需要汇总所有成员接口速率")

    if direction:
        req.append(f"重点判断 {direction} 方向是否仍超过阈值")

    return req


def build_acceptance_criteria(score_result: Dict[str, Any], cluster: Dict[str, Any]) -> List[str]:
    return [
        "必须保持 readonly，只允许 show/display/get/diagnose 等只读命令",
        "不得因为 proposal 自动创建或覆盖正式 skills/ 内容",
        "同一告警样例重新生成 review 后，结论不得从多接口降级为单接口",
        "如果涉及多接口线路，notify_lines、key_findings、recommendations、conclusion 必须保持多接口汇总口径一致",
        "新增或增强 Skill 前，必须补充至少一个 regression 样例",
        f"本 proposal 复用价值评分为 {score_result.get('total_score')}，人工复核时应重点确认评分原因是否成立",
    ]


def build_risks_and_guardrails(score_result: Dict[str, Any]) -> List[str]:
    risks = [
        "相似告警不一定代表同一根因，不能只根据 family 直接复用处理结论",
        "多接口线路需要避免只分析第一个接口",
        "不能把单次瞬时峰值误沉淀为固定故障模式",
        "候选 Skill 不能绕过 safety_policy",
    ]

    existing = safe_dict(score_result.get("existing_skill"))
    if existing:
        risks.append("已有相关 Skill，本 proposal 更适合做增强项，避免重复建设平行 Skill")

    return risks


def build_proposal_from_cluster(
    cluster: Dict[str, Any],
    records: List[Dict[str, Any]],
    base_dir: Path = DEFAULT_BASE_DIR,
) -> Optional[Dict[str, Any]]:
    if len(records) < 2:
        return None

    score_result = score_reuse_value(cluster, records, base_dir=base_dir)
    if score_result.get("verdict") == "not_recommended":
        return None

    proposal_type = infer_proposal_type(score_result)
    candidate_skill_name = build_candidate_skill_name(cluster, score_result)
    proposal_id = stable_id(
        cluster.get("signature"),
        candidate_skill_name,
        proposal_type,
        prefix="skillprop",
    )

    sample_request_ids = [x.get("request_id") for x in records if x.get("request_id")][:10]

    proposal = {
        "schema_version": SCHEMA_VERSION,
        "proposal_id": proposal_id,
        "proposal_type": proposal_type,
        "proposal_status": "draft_review_required",
        "manual_review_required": True,
        "auto_merge_enabled": False,
        "created_at": utc_now(),
        "candidate_skill_name": candidate_skill_name,
        "family": cluster.get("family"),
        "source_cluster": {
            "cluster_id": cluster.get("cluster_id"),
            "signature": cluster.get("signature"),
            "size": cluster.get("size"),
            "first_event_time": cluster.get("first_event_time"),
            "last_event_time": cluster.get("last_event_time"),
            "request_ids": cluster.get("request_ids") or [],
        },
        "sample_request_ids": sample_request_ids,
        "reuse_value": score_result,
        "trigger_template": build_trigger_template(cluster),
        "evidence_requirements": build_evidence_requirements(cluster),
        "observed_facts": extract_observed_facts(records),
        "observed_command_summary": extract_observed_commands(records),
        "proposed_instruction_summary": (
            "针对重复出现的告警模式，建议沉淀为可复核 Skill 逻辑："
            "先识别告警 family 和对象范围，再按只读命令获取结构化证据，"
            "最后按业务口径和设备口径分别输出结论。"
        ),
        "acceptance_criteria": build_acceptance_criteria(score_result, cluster),
        "risks_and_guardrails": build_risks_and_guardrails(score_result),
        "next_actions": [
            "人工复核 proposal 是否确有复用价值",
            "确认是否增强既有 Skill 或创建新 Skill",
            "补充 Skill 示例输入、期望 evidence facts 与回归样例",
            "通过 validate_skills、validate_skill_compliance 和 v7 回归后再进入正式 Skill 生命周期",
        ],
        "safety": {
            "source": "incident_memory_and_relation_graph_only",
            "contains_raw_device_ip": False,
            "contains_secret_material": False,
            "readonly_sidecar_only": True,
            "writes_formal_skill": False,
        },
    }

    return redact_sensitive_values(proposal)


def write_proposals(proposals: List[Dict[str, Any]], base_dir: Path = DEFAULT_BASE_DIR) -> Dict[str, Any]:
    root = proposal_dir(base_dir)
    root.mkdir(parents=True, exist_ok=True)

    index = proposal_index_file(base_dir)

    with index.open("w", encoding="utf-8") as f:
        for proposal in proposals:
            proposal_id = safe_text(proposal.get("proposal_id"))
            if not proposal_id:
                continue

            detail_file = root / f"{proposal_id}.proposal.json"
            proposal["proposal_file"] = str(detail_file)
            detail_file.write_text(
                json.dumps(proposal, ensure_ascii=False, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            f.write(json.dumps(proposal, ensure_ascii=False, sort_keys=True) + "\n")

    return {
        "proposal_index_file": str(index),
        "proposal_dir": str(root),
    }


def read_skill_proposals(base_dir: Path = DEFAULT_BASE_DIR) -> List[Dict[str, Any]]:
    path = proposal_index_file(base_dir)
    if not path.exists():
        return []

    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except Exception:
                continue
            if isinstance(data, dict):
                rows.append(data)

    return rows


def get_skill_proposal(proposal_id: str, base_dir: Path = DEFAULT_BASE_DIR) -> Optional[Dict[str, Any]]:
    path = proposal_dir(base_dir) / f"{proposal_id}.proposal.json"
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass

    for item in read_skill_proposals(base_dir):
        if item.get("proposal_id") == proposal_id:
            return item

    return None


def build_skill_proposals(
    base_dir: Path = DEFAULT_BASE_DIR,
    limit_clusters: int = 0,
    write: bool = True,
    rebuild_relations: bool = False,
) -> Dict[str, Any]:
    base_dir = Path(base_dir)

    memories = read_incident_memories(base_dir)
    memory_index = records_by_request_id(memories)

    graph = build_relation_graph(base_dir=base_dir, limit=0, write=True) if rebuild_relations else read_relation_graph(base_dir)
    if not graph:
        graph = build_relation_graph(base_dir=base_dir, limit=0, write=True)

    clusters = safe_list(graph.get("clusters"))
    if limit_clusters and limit_clusters > 0:
        clusters = clusters[:limit_clusters]

    proposals: List[Dict[str, Any]] = []
    skipped = []

    for cluster in clusters:
        if not isinstance(cluster, dict):
            continue

        records = cluster_records(cluster, memory_index)
        proposal = build_proposal_from_cluster(cluster, records, base_dir=base_dir)

        if proposal:
            proposals.append(proposal)
        else:
            skipped.append({
                "cluster_id": cluster.get("cluster_id"),
                "signature": cluster.get("signature"),
                "reason": "not_enough_reuse_value_or_records",
            })

    proposals.sort(
        key=lambda x: (
            safe_dict(x.get("reuse_value")).get("total_score", 0),
            safe_dict(x.get("source_cluster")).get("size", 0),
        ),
        reverse=True,
    )

    write_result = {}
    if write:
        write_result = write_proposals(proposals, base_dir)

    return {
        "ok": True,
        "stage": "v7.3_skill_proposal_builder",
        "schema_version": SCHEMA_VERSION,
        "memory_record_count": len(memories),
        "cluster_count": len(clusters),
        "proposal_count": len(proposals),
        "skipped_count": len(skipped),
        "write_result": write_result,
        "proposals": proposals,
        "skipped": skipped[:20],
        "safety": {
            "auto_merge_enabled": False,
            "manual_review_required": True,
            "writes_formal_skill": False,
        },
    }


def query_skill_proposals(
    base_dir: Path = DEFAULT_BASE_DIR,
    family: str = "",
    proposal_type: str = "",
    verdict: str = "",
    min_score: int = 0,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    rows = read_skill_proposals(base_dir)

    family_l = safe_text(family).lower()
    type_l = safe_text(proposal_type).lower()
    verdict_l = safe_text(verdict).lower()

    result = []

    for item in rows:
        if family_l and family_l not in safe_text(item.get("family")).lower():
            continue

        if type_l and type_l != safe_text(item.get("proposal_type")).lower():
            continue

        reuse = safe_dict(item.get("reuse_value"))
        if verdict_l and verdict_l != safe_text(reuse.get("verdict")).lower():
            continue

        if min_score and int(reuse.get("total_score") or 0) < min_score:
            continue

        result.append(item)

    result.sort(key=lambda x: safe_dict(x.get("reuse_value")).get("total_score", 0), reverse=True)

    if limit and limit > 0:
        result = result[:limit]

    return result


def validate_proposal_safety(proposal: Dict[str, Any]) -> Dict[str, Any]:
    """Validate proposal safety.

    只检查 proposal 自身是否泄露明文 IP 或明显敏感字段。
    注意：不把普通单词 token 的任意出现都视为敏感，避免误判文档描述。
    """
    text = json.dumps(proposal, ensure_ascii=False)
    lower = text.lower()
    findings = []

    ip_hits = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    if ip_hits:
        findings.append({"type": "raw_ipv4", "count": len(ip_hits), "samples": ip_hits[:3]})

    secret_patterns = [
        r"password\s*[:=]",
        r"passwd\s*[:=]",
        r"api[_-]?key\s*[:=]",
        r"access[_-]?token\s*[:=]",
        r"secret[_-]?token\s*[:=]",
        r"webhook[_-]?secret\s*[:=]",
        r"mcp[_-]?server[_-]?url\s*[:=]",
    ]

    for pattern in secret_patterns:
        if re.search(pattern, lower):
            findings.append({"type": "secret_pattern", "pattern": pattern})

    if proposal.get("auto_merge_enabled") is not False:
        findings.append({"type": "auto_merge_not_false"})

    if proposal.get("manual_review_required") is not True:
        findings.append({"type": "manual_review_not_required"})

    safety = safe_dict(proposal.get("safety"))
    if safety.get("writes_formal_skill") is not False:
        findings.append({"type": "writes_formal_skill_not_false"})

    return {
        "ok": not findings,
        "findings": findings,
    }
