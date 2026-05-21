"""v7.2 Incident Relation Engine.

基于 v7.1 incident_memory 构建跨 request_id 的关系图。

设计边界：
- 只读取 data/memory/incidents.jsonl，不访问设备，不执行命令。
- 只使用已脱敏字段，例如 device_ip_hash。
- 输出到 data/memory/incident_relations.json。
- 用于后续 v7.3 skill proposal 和 v7.x learning report。
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from netaiops.memory_store import (
    DEFAULT_BASE_DIR,
    normalize_interface_name,
    read_incident_memories,
    safe_text,
)

RELATION_SCHEMA_VERSION = "v7.2.incident_relations.v1"
RELATION_REL_PATH = Path("data/memory/incident_relations.json")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def relation_file(base_dir: Path = DEFAULT_BASE_DIR) -> Path:
    return Path(base_dir) / RELATION_REL_PATH


def safe_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def as_lower_set(items: Iterable[Any]) -> set[str]:
    result = set()
    for item in items:
        text = safe_text(item).lower()
        if text:
            result.add(text)
    return result


def normalized_interfaces(record: Dict[str, Any]) -> List[str]:
    result = []
    seen = set()

    for iface in safe_list(record.get("interfaces")):
        name = normalize_interface_name(iface)
        key = name.lower()
        if name and key not in seen:
            seen.add(key)
            result.append(name)

    return result


def get_fact(record: Dict[str, Any], key: str, default: Any = None) -> Any:
    facts = record.get("evidence_facts")
    if isinstance(facts, dict):
        return facts.get(key, default)
    return default


def parse_time(value: Any) -> Optional[datetime]:
    text = safe_text(value)
    if not text:
        return None

    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def age_hours(a: Dict[str, Any], b: Dict[str, Any]) -> Optional[float]:
    ta = parse_time(a.get("event_time") or a.get("created_at"))
    tb = parse_time(b.get("event_time") or b.get("created_at"))
    if not ta or not tb:
        return None
    return round(abs((ta - tb).total_seconds()) / 3600.0, 2)


def overlap_count(a: Iterable[Any], b: Iterable[Any]) -> int:
    return len(as_lower_set(a) & as_lower_set(b))


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


def dominant_util(record: Dict[str, Any]) -> Optional[float]:
    direction = safe_text(record.get("direction")).lower()
    facts = record.get("evidence_facts") if isinstance(record.get("evidence_facts"), dict) else {}

    candidates = []
    if direction == "out":
        candidates.extend([
            facts.get("aggregate_output_utilization_percent_business_estimated"),
            facts.get("output_utilization_percent_business_estimated"),
            facts.get("output_utilization_percent_estimated"),
        ])
    elif direction == "in":
        candidates.extend([
            facts.get("aggregate_input_utilization_percent_business_estimated"),
            facts.get("input_utilization_percent_business_estimated"),
            facts.get("input_utilization_percent_estimated"),
        ])

    candidates.extend([
        facts.get("aggregate_output_utilization_percent_business_estimated"),
        facts.get("aggregate_input_utilization_percent_business_estimated"),
        facts.get("output_utilization_percent_business_estimated"),
        facts.get("input_utilization_percent_business_estimated"),
        facts.get("output_utilization_percent_estimated"),
        facts.get("input_utilization_percent_estimated"),
    ])

    for item in candidates:
        val = safe_float(item)
        if val is not None:
            return val

    return None


def relation_score(a: Dict[str, Any], b: Dict[str, Any]) -> Tuple[int, List[str], Dict[str, Any]]:
    score = 0
    reasons: List[str] = []
    detail: Dict[str, Any] = {}

    if safe_text(a.get("family")) and safe_text(a.get("family")) == safe_text(b.get("family")):
        score += 30
        reasons.append("same_family")

    if safe_text(a.get("hostname")) and safe_text(a.get("hostname")) == safe_text(b.get("hostname")):
        score += 25
        reasons.append("same_hostname")

    if safe_text(a.get("device_ip_hash")) and safe_text(a.get("device_ip_hash")) == safe_text(b.get("device_ip_hash")):
        score += 20
        reasons.append("same_device_hash")

    iface_overlap = overlap_count(normalized_interfaces(a), normalized_interfaces(b))
    if iface_overlap:
        score += min(30, iface_overlap * 15)
        reasons.append("same_interface")
        detail["interface_overlap_count"] = iface_overlap

    ca = safe_text(a.get("circuit_alias"))
    cb = safe_text(b.get("circuit_alias"))
    if ca and cb and ca == cb:
        score += 20
        reasons.append("same_circuit_alias")

    if safe_text(a.get("direction")) and safe_text(a.get("direction")) == safe_text(b.get("direction")):
        score += 8
        reasons.append("same_direction")

    if safe_text(a.get("alarm_type")) and safe_text(a.get("alarm_type")) == safe_text(b.get("alarm_type")):
        score += 10
        reasons.append("same_alarm_type")

    bw_a = a.get("alarm_bandwidth_mbps")
    bw_b = b.get("alarm_bandwidth_mbps")
    try:
        if bw_a is not None and bw_b is not None and float(bw_a) == float(bw_b):
            score += 5
            reasons.append("same_alarm_bandwidth")
    except Exception:
        pass

    h = age_hours(a, b)
    if h is not None:
        detail["time_distance_hours"] = h
        if h <= 2:
            score += 12
            reasons.append("near_time_2h")
        elif h <= 24:
            score += 8
            reasons.append("near_time_24h")
        elif h <= 7 * 24:
            score += 4
            reasons.append("near_time_7d")

    ua = dominant_util(a)
    ub = dominant_util(b)
    if ua is not None and ub is not None:
        detail["dominant_util_a"] = ua
        detail["dominant_util_b"] = ub
        if abs(ua - ub) <= 10:
            score += 5
            reasons.append("similar_utilization")

    return min(score, 100), reasons, detail


def classify_relation(score: int, reasons: List[str]) -> str:
    reason_set = set(reasons)

    if score >= 75 and ("same_interface" in reason_set or "same_circuit_alias" in reason_set):
        return "strong_recurrence"

    if score >= 60:
        return "related"

    if score >= 45:
        return "weak_related"

    return "unrelated"


def build_pair_relation(a: Dict[str, Any], b: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not a.get("request_id") or not b.get("request_id"):
        return None

    if a.get("request_id") == b.get("request_id"):
        return None

    score, reasons, detail = relation_score(a, b)
    relation_type = classify_relation(score, reasons)

    if relation_type == "unrelated":
        return None

    return {
        "source_request_id": a.get("request_id"),
        "target_request_id": b.get("request_id"),
        "score": score,
        "relation_type": relation_type,
        "reasons": reasons,
        "detail": detail,
        "source_event_time": a.get("event_time"),
        "target_event_time": b.get("event_time"),
        "family": a.get("family") or b.get("family"),
        "hostname": a.get("hostname") if a.get("hostname") == b.get("hostname") else "",
        "interfaces": sorted(list(set(normalized_interfaces(a)) | set(normalized_interfaces(b)))),
        "circuit_alias": a.get("circuit_alias") if a.get("circuit_alias") == b.get("circuit_alias") else "",
        "direction": a.get("direction") if a.get("direction") == b.get("direction") else "",
    }


def build_relations(records: List[Dict[str, Any]], max_pairs: int = 20000) -> List[Dict[str, Any]]:
    relations = []
    n = len(records)
    pair_count = 0

    for i in range(n):
        for j in range(i + 1, n):
            pair_count += 1
            if max_pairs and pair_count > max_pairs:
                break

            rel = build_pair_relation(records[i], records[j])
            if rel:
                relations.append(rel)

        if max_pairs and pair_count > max_pairs:
            break

    relations.sort(key=lambda x: (x.get("score", 0), x.get("source_event_time") or ""), reverse=True)
    return relations


def relation_signature(record: Dict[str, Any]) -> str:
    parts = [
        safe_text(record.get("family")),
        safe_text(record.get("hostname")),
        safe_text(record.get("circuit_alias")),
        safe_text(record.get("direction")),
        ",".join(normalized_interfaces(record)),
    ]
    return "|".join(parts)


def build_clusters(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for item in records:
        sig = relation_signature(item)
        if sig.strip("|"):
            grouped[sig].append(item)

    clusters = []

    for sig, items in grouped.items():
        if len(items) < 2:
            continue

        items_sorted = sorted(
            items,
            key=lambda x: safe_text(x.get("event_time") or x.get("created_at")),
            reverse=True,
        )

        sample = items_sorted[0]
        utils = [dominant_util(x) for x in items_sorted]
        utils = [x for x in utils if x is not None]

        clusters.append({
            "cluster_id": f"cluster_{abs(hash(sig)) % 100000000:08d}",
            "signature": sig,
            "size": len(items_sorted),
            "family": sample.get("family"),
            "hostname": sample.get("hostname"),
            "interfaces": normalized_interfaces(sample),
            "circuit_alias": sample.get("circuit_alias"),
            "direction": sample.get("direction"),
            "first_event_time": safe_text(items_sorted[-1].get("event_time") or items_sorted[-1].get("created_at")),
            "last_event_time": safe_text(items_sorted[0].get("event_time") or items_sorted[0].get("created_at")),
            "request_ids": [x.get("request_id") for x in items_sorted],
            "avg_dominant_utilization": round(sum(utils) / len(utils), 2) if utils else None,
            "max_dominant_utilization": round(max(utils), 2) if utils else None,
        })

    clusters.sort(key=lambda x: (x.get("size", 0), x.get("last_event_time") or ""), reverse=True)
    return clusters


def build_relation_graph(
    base_dir: Path = DEFAULT_BASE_DIR,
    limit: int = 0,
    write: bool = True,
) -> Dict[str, Any]:
    records = read_incident_memories(base_dir)

    records.sort(key=lambda x: safe_text(x.get("event_time") or x.get("created_at")), reverse=True)

    if limit and limit > 0:
        records = records[:limit]

    relations = build_relations(records)
    clusters = build_clusters(records)

    graph = {
        "schema_version": RELATION_SCHEMA_VERSION,
        "stage": "v7.2_relation_engine",
        "generated_at": utc_now(),
        "record_count": len(records),
        "relation_count": len(relations),
        "cluster_count": len(clusters),
        "relations": relations,
        "clusters": clusters,
        "safety": {
            "source": "incident_memory_only",
            "contains_raw_device_ip": False,
            "readonly_sidecar_only": True,
        },
    }

    if write:
        path = relation_file(base_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(graph, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        graph["relation_file"] = str(path)

    return graph


def read_relation_graph(base_dir: Path = DEFAULT_BASE_DIR) -> Dict[str, Any]:
    path = relation_file(base_dir)
    if not path.exists():
        return {}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def find_relations_for_request_id(
    request_id: str,
    base_dir: Path = DEFAULT_BASE_DIR,
    rebuild: bool = False,
    limit: int = 0,
) -> Dict[str, Any]:
    graph = build_relation_graph(base_dir=base_dir, limit=limit, write=True) if rebuild else read_relation_graph(base_dir)

    if not graph:
        graph = build_relation_graph(base_dir=base_dir, limit=limit, write=True)

    relations = []
    for rel in graph.get("relations") or []:
        if rel.get("source_request_id") == request_id or rel.get("target_request_id") == request_id:
            relations.append(rel)

    relations.sort(key=lambda x: x.get("score", 0), reverse=True)

    clusters = []
    for cluster in graph.get("clusters") or []:
        if request_id in (cluster.get("request_ids") or []):
            clusters.append(cluster)

    return {
        "status": "ok",
        "stage": "v7.2_relation_engine_detail",
        "request_id": request_id,
        "relation_count": len(relations),
        "cluster_count": len(clusters),
        "relations": relations,
        "clusters": clusters,
    }


def query_relation_graph(
    base_dir: Path = DEFAULT_BASE_DIR,
    family: str = "",
    hostname: str = "",
    interface: str = "",
    relation_type: str = "",
    min_score: int = 0,
    limit: int = 20,
    rebuild: bool = False,
    rebuild_limit: int = 0,
) -> Dict[str, Any]:
    graph = build_relation_graph(base_dir=base_dir, limit=rebuild_limit, write=True) if rebuild else read_relation_graph(base_dir)

    if not graph:
        graph = build_relation_graph(base_dir=base_dir, limit=rebuild_limit, write=True)

    family_l = family.lower().strip()
    hostname_l = hostname.lower().strip()
    iface_l = normalize_interface_name(interface).lower().strip() if interface else ""
    relation_type_l = relation_type.lower().strip()

    rows = []
    for rel in graph.get("relations") or []:
        if family_l and family_l not in safe_text(rel.get("family")).lower():
            continue

        if hostname_l and hostname_l not in safe_text(rel.get("hostname")).lower():
            continue

        if iface_l:
            rel_ifaces = [normalize_interface_name(x).lower() for x in rel.get("interfaces") or []]
            if iface_l not in rel_ifaces:
                continue

        if relation_type_l and relation_type_l != safe_text(rel.get("relation_type")).lower():
            continue

        if min_score and int(rel.get("score") or 0) < min_score:
            continue

        rows.append(rel)

    rows.sort(key=lambda x: x.get("score", 0), reverse=True)

    if limit and limit > 0:
        rows = rows[:limit]

    return {
        "status": "ok",
        "stage": "v7.2_relation_engine",
        "schema_version": graph.get("schema_version"),
        "generated_at": graph.get("generated_at"),
        "filters": {
            "family": family,
            "hostname": hostname,
            "interface": interface,
            "relation_type": relation_type,
            "min_score": min_score,
            "limit": limit,
        },
        "total_relation_count": graph.get("relation_count", 0),
        "total_cluster_count": graph.get("cluster_count", 0),
        "record_count": graph.get("record_count", 0),
        "relation_count": len(rows),
        "relations": rows,
        "top_clusters": (graph.get("clusters") or [])[:10],
    }
