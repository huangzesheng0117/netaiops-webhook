"""v7.1 Incident Memory store.

Hermes-style Learning Ops 第一阶段：
从既有 request_id 的 normalized / execution / review / investigation / adaptive plan 中抽取长期 incident_memory。

安全边界：
- 不影响 v5/v6 生产主链路。
- 不执行任何设备命令。
- 不保存明文设备 IP、密码、Token、Webhook Secret、MCP Server URL 或完整 inventory。
- 设备 IP 只保存 hash。
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

SCHEMA_VERSION = "v7.1.incident_memory.v1"
DEFAULT_BASE_DIR = Path("/opt/netaiops-webhook")
MEMORY_REL_PATH = Path("data/memory/incidents.jsonl")

_INTERFACE_RE = re.compile(
    r"\b(?:TenGigabitEthernet|GigabitEthernet|FastEthernet|Ethernet|Port-channel|Po|Te|Gi|Fa|Eth)\s*\d+(?:[/.:]\d+)*\b",
    re.I,
)
_REQ_ID_RE = re.compile(r"(\d{8}_\d{6}_\d{6}_[0-9a-fA-F]{8})")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


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


def safe_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    try:
        text = safe_text(value)
        if not text:
            return None
        return int(float(text))
    except Exception:
        return None


def read_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


def request_id_from_path(path: Path) -> str:
    match = _REQ_ID_RE.search(path.name)
    return match.group(1) if match else ""


def find_one_by_request_id(base_dir: Path, subdir: str, request_id: str, suffix: str = "") -> Optional[Path]:
    root = base_dir / "data" / subdir
    if not root.exists():
        return None

    pattern = f"*{request_id}*{suffix}" if suffix else f"*{request_id}*"
    files = [p for p in root.glob(pattern) if p.is_file()]
    if not files:
        return None

    return sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)[0]


def load_request_artifacts(request_id: str, base_dir: Path = DEFAULT_BASE_DIR) -> Dict[str, Any]:
    base_dir = Path(base_dir)

    specs = {
        "normalized": ("normalized", ".json"),
        "analysis": ("analysis", ".analysis.json"),
        "plan": ("plans", ".plan.json"),
        "execution": ("execution", ".execution.json"),
        "review": ("reviews", ".review.json"),
        "investigation": ("investigation", ".investigation.session.json"),
        "adaptive_plan": ("adaptive_plans", ".adaptive.plan.json"),
    }

    result: Dict[str, Any] = {
        "request_id": request_id,
        "files": {},
        "data": {},
    }

    for name, (subdir, suffix) in specs.items():
        path = find_one_by_request_id(base_dir, subdir, request_id, suffix)
        if not path:
            continue

        try:
            result["files"][name] = str(path.relative_to(base_dir))
        except Exception:
            result["files"][name] = str(path)

        try:
            result["data"][name] = read_json(path)
        except Exception as exc:
            result["data"][name] = {"_load_error": str(exc)}

    return result


def first_event(normalized_data: Dict[str, Any]) -> Dict[str, Any]:
    events = normalized_data.get("events")
    if isinstance(events, list) and events and isinstance(events[0], dict):
        return events[0]
    return normalized_data if isinstance(normalized_data, dict) else {}


def hash_identifier(value: Any) -> str:
    text = safe_text(value)
    if not text:
        return ""
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
    return f"hash_{digest}"


def normalize_interface_name(value: Any) -> str:
    text = safe_text(value).replace(" ", "")
    if not text:
        return ""

    lowered = text.lower()
    replacements = [
        ("tengigabitethernet", "TenGigabitEthernet"),
        ("gigabitethernet", "GigabitEthernet"),
        ("fastethernet", "FastEthernet"),
        ("ethernet", "Ethernet"),
        ("port-channel", "Port-channel"),
        ("po", "Port-channel"),
        ("te", "TenGigabitEthernet"),
        ("gi", "GigabitEthernet"),
        ("fa", "FastEthernet"),
        ("eth", "Ethernet"),
    ]

    for prefix, full in replacements:
        if lowered.startswith(prefix):
            return full + text[len(prefix):]

    return text


def add_unique(items: List[str], value: Any, normalize: bool = False) -> None:
    text = normalize_interface_name(value) if normalize else safe_text(value)
    if text and text not in items:
        items.append(text)


def extract_interfaces(*objects: Any) -> List[str]:
    result: List[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ("interface", "counter_interface", "command_interface", "object_name"):
                    add_unique(result, item, normalize=True)
                elif key in ("interfaces", "multi_interfaces") and isinstance(item, list):
                    for iface in item:
                        add_unique(result, iface, normalize=True)
                elif key in ("command", "output_preview"):
                    for match in _INTERFACE_RE.findall(safe_text(item)):
                        add_unique(result, match, normalize=True)
                elif key in (
                    "device_outputs",
                    "command_results",
                    "target_scope",
                    "facts",
                    "evidence_summary",
                    "capability_plan",
                    "selected_capabilities",
                ):
                    walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    for obj in objects:
        walk(obj)

    return result


def extract_target_scope(*objects: Any) -> Dict[str, Any]:
    for obj in objects:
        if not isinstance(obj, dict):
            continue

        scope = obj.get("target_scope")
        if isinstance(scope, dict) and scope:
            return scope

        data = obj.get("data")
        if isinstance(data, dict):
            scope = data.get("target_scope")
            if isinstance(scope, dict) and scope:
                return scope

    return {}


def get_nested(data: Dict[str, Any], path: Iterable[str], default: Any = None) -> Any:
    cur: Any = data
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
    return cur if cur is not None else default


def extract_capability_arguments(plan_or_review: Dict[str, Any]) -> List[Dict[str, Any]]:
    selected = get_nested(plan_or_review, ["capability_plan", "selected_capabilities"], [])
    if not isinstance(selected, list):
        selected = []

    args = []
    for item in selected:
        if isinstance(item, dict) and isinstance(item.get("arguments"), dict):
            args.append(item["arguments"])

    return args


def extract_circuit_alias(*objects: Any) -> str:
    for obj in objects:
        if not isinstance(obj, dict):
            continue

        candidates = [
            obj.get("circuit_alias"),
            obj.get("link_name"),
            obj.get("if_alias"),
            obj.get("description"),
            obj.get("alarm_type"),
            obj.get("object_name"),
        ]

        for c in candidates:
            text = safe_text(c)
            if not text:
                continue

            m = re.search(r"([A-Za-z0-9]+互联网线路[_\-][^_\s]+[_\-]\d+(?:M|G))", text, flags=re.I)
            if m:
                return m.group(1)

            if "互联网线路" in text and ("M" in text or "G" in text):
                return text[:80]

    return ""


def extract_direction(*objects: Any) -> str:
    for obj in objects:
        if not isinstance(obj, dict):
            continue

        text = " ".join(
            safe_text(x)
            for x in [
                obj.get("alarm_direction"),
                obj.get("direction"),
                obj.get("alarm_type"),
                obj.get("description"),
                obj.get("object_name"),
            ]
            if x is not None
        ).lower()

        if "出向" in text or "out" in text or "output" in text:
            return "out"
        if "入向" in text or "in" in text or "input" in text:
            return "in"

    return ""


def extract_bandwidth_mbps(*objects: Any) -> Optional[float]:
    for obj in objects:
        if not isinstance(obj, dict):
            continue

        val = safe_float(obj.get("business_bandwidth_bps"))
        if val is not None:
            return round(val / 1000000, 2)

        val = safe_float(obj.get("alarm_bandwidth_mbps"))
        if val is not None:
            return val

        text = " ".join(safe_text(v) for v in obj.values() if isinstance(v, (str, int, float)))
        m = re.search(r"(\d+(?:\.\d+)?)\s*([MG])", text, flags=re.I)
        if m:
            num = float(m.group(1))
            unit = m.group(2).upper()
            return num * 1000 if unit == "G" else num

    return None


def compact_facts(facts: Dict[str, Any]) -> Dict[str, Any]:
    allow = [
        "interface",
        "multi_interfaces",
        "oper_status",
        "admin_status",
        "oper_detail",
        "input_rate_bps",
        "output_rate_bps",
        "aggregate_input_rate_bps",
        "aggregate_output_rate_bps",
        "input_utilization_percent_estimated",
        "output_utilization_percent_estimated",
        "input_utilization_percent_business_estimated",
        "output_utilization_percent_business_estimated",
        "aggregate_input_utilization_percent_business_estimated",
        "aggregate_output_utilization_percent_business_estimated",
        "business_bandwidth_bps",
        "business_bandwidth_text",
        "physical_bandwidth_bps",
        "crc",
        "input_errors",
        "output_errors",
        "output_drops",
        "out_discards",
        "etherchannel_member_count",
        "etherchannel_bundled_member_count",
        "etherchannel_down_member_count",
        "channel_group_count",
        "aggregator_count",
        "port_channel_count",
        "parsed_facts_enabled",
        "facts_source_preference",
        "parsed_fact_sources",
    ]

    result: Dict[str, Any] = {}
    for key in allow:
        if key in facts:
            result[key] = facts.get(key)

    return result


def build_command_summary(review_data: Dict[str, Any], execution_data: Dict[str, Any]) -> Dict[str, Any]:
    stats = review_data.get("stats") if isinstance(review_data.get("stats"), dict) else {}
    command_results = execution_data.get("command_results") if isinstance(execution_data.get("command_results"), list) else []

    if stats:
        return {
            "execution_status": safe_text(stats.get("execution_status")),
            "total_commands": safe_int(stats.get("total_commands") or stats.get("command_total")) or 0,
            "completed_commands": safe_int(stats.get("completed_commands") or stats.get("command_completed")) or 0,
            "failed_commands": safe_int(stats.get("failed_commands") or stats.get("command_failed")) or 0,
            "partial_commands": safe_int(stats.get("partial_commands") or stats.get("command_partial")) or 0,
            "hard_error_count": safe_int(stats.get("hard_error_count")) or 0,
        }

    total = len(command_results)
    completed = 0
    failed = 0
    partial = 0
    hard = 0

    for item in command_results:
        if not isinstance(item, dict):
            continue

        status = safe_text(item.get("dispatch_status") or item.get("status")).lower()

        if status == "completed":
            completed += 1
        elif status == "partial":
            partial += 1
        elif status:
            failed += 1

        judge = item.get("judge") if isinstance(item.get("judge"), dict) else {}
        if judge.get("hard_error"):
            hard += 1

    return {
        "execution_status": safe_text(execution_data.get("execution_status")),
        "total_commands": total,
        "completed_commands": completed,
        "failed_commands": failed,
        "partial_commands": partial,
        "hard_error_count": hard,
    }


def build_parser_summary(facts: Dict[str, Any], execution_data: Dict[str, Any]) -> Dict[str, Any]:
    command_results = execution_data.get("command_results") if isinstance(execution_data.get("command_results"), list) else []
    counts: Dict[str, int] = {}

    for item in command_results:
        if not isinstance(item, dict):
            continue

        parsed = item.get("parsed")
        if isinstance(parsed, dict):
            status = safe_text(parsed.get("parse_status") or parsed.get("status"), "unknown")
            counts[status] = counts.get(status, 0) + 1

    return {
        "parsed_facts_enabled": bool(facts.get("parsed_facts_enabled")),
        "parsed_fact_sources": facts.get("parsed_fact_sources") or [],
        "parse_status_counts": counts,
    }


def build_incident_memory(request_id: str, base_dir: Path = DEFAULT_BASE_DIR) -> Dict[str, Any]:
    base_dir = Path(base_dir)
    artifacts = load_request_artifacts(request_id=request_id, base_dir=base_dir)
    data = artifacts.get("data", {})

    normalized = data.get("normalized", {})
    event = first_event(normalized)
    review = data.get("review", {})
    execution = data.get("execution", {})
    plan = data.get("plan", {})
    investigation = data.get("investigation", {})
    adaptive_plan = data.get("adaptive_plan", {})

    evidence_summary = review.get("evidence_summary") if isinstance(review.get("evidence_summary"), dict) else {}
    facts = evidence_summary.get("facts") if isinstance(evidence_summary.get("facts"), dict) else {}
    target_scope = extract_target_scope(review, execution, plan, event)
    capability_args = extract_capability_arguments(review) + extract_capability_arguments(plan)

    hostname = safe_text(
        target_scope.get("hostname") or event.get("hostname") or review.get("hostname") or execution.get("hostname")
    )
    device_ip = safe_text(target_scope.get("device_ip") or event.get("device_ip"))

    family = safe_text(
        review.get("family")
        or evidence_summary.get("family")
        or get_nested(review, ["family_result", "family"])
        or get_nested(plan, ["family_result", "family"])
        or event.get("family")
    )

    alarm_type = safe_text(
        target_scope.get("alarm_type")
        or event.get("alarm_type")
        or get_nested(review, ["classification", "alarm_type"])
    )

    severity = safe_text(event.get("severity") or get_nested(review, ["classification", "severity"]))
    source = safe_text(normalized.get("source") or event.get("source") or get_nested(review, ["classification", "source"]))

    interfaces = extract_interfaces(target_scope, facts, review, execution, plan)
    circuit_alias = extract_circuit_alias(target_scope, facts, event, review, *(capability_args or []))
    direction = extract_direction(facts, target_scope, event, review)
    alarm_bandwidth_mbps = extract_bandwidth_mbps(facts, target_scope, event, review)

    generated_at = safe_text(review.get("generated_at") or evidence_summary.get("generated_at") or normalized.get("created_at"))
    if not generated_at:
        generated_at = utc_now()

    record = {
        "schema_version": SCHEMA_VERSION,
        "memory_type": "incident_memory",
        "request_id": request_id,
        "created_at": utc_now(),
        "event_time": generated_at,
        "source": source,
        "family": family,
        "severity": severity,
        "hostname": hostname,
        "device_ip_hash": hash_identifier(device_ip),
        "interfaces": interfaces,
        "circuit_alias": circuit_alias,
        "direction": direction,
        "alarm_type": alarm_type,
        "alarm_bandwidth_mbps": alarm_bandwidth_mbps,
        "skill_name": safe_text(get_nested(investigation, ["skill_runtime_context", "primary_skill", "skill_name"])),
        "evidence_facts": compact_facts(facts),
        "command_summary": build_command_summary(review, execution),
        "parser_summary": build_parser_summary(facts, execution),
        "adaptive_summary": {
            "dry_run_only": bool(get_nested(adaptive_plan, ["policy", "dry_run_only"], False)),
            "dispatch_enabled": bool(get_nested(adaptive_plan, ["policy", "dispatch_enabled"], False)),
            "candidate_count": len(adaptive_plan.get("candidates") or []) if isinstance(adaptive_plan, dict) else 0,
        },
        "judgement": safe_text(review.get("conclusion") or evidence_summary.get("conclusion")),
        "source_files": artifacts.get("files", {}),
        "safety": {
            "contains_raw_device_ip": False,
            "contains_secret_material": False,
            "readonly_sidecar_only": True,
        },
    }

    return record


def memory_file(base_dir: Path = DEFAULT_BASE_DIR) -> Path:
    return Path(base_dir) / MEMORY_REL_PATH


def read_incident_memories(base_dir: Path = DEFAULT_BASE_DIR) -> List[Dict[str, Any]]:
    path = memory_file(base_dir)
    if not path.exists():
        return []

    records = []
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
                records.append(data)

    return records


def write_incident_memories(records: List[Dict[str, Any]], base_dir: Path = DEFAULT_BASE_DIR) -> Path:
    path = memory_file(base_dir)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    return path


def upsert_incident_memory(record: Dict[str, Any], base_dir: Path = DEFAULT_BASE_DIR) -> Path:
    records = read_incident_memories(base_dir)
    rid = record.get("request_id")

    replaced = False
    result = []

    for item in records:
        if item.get("request_id") == rid:
            result.append(record)
            replaced = True
        else:
            result.append(item)

    if not replaced:
        result.append(record)

    return write_incident_memories(result, base_dir)


def iter_request_ids_from_reviews(base_dir: Path = DEFAULT_BASE_DIR) -> List[str]:
    review_dir = Path(base_dir) / "data" / "reviews"
    if not review_dir.exists():
        return []

    items = []

    for path in review_dir.glob("*.review.json"):
        rid = request_id_from_path(path)
        if rid:
            items.append((path.stat().st_mtime, rid))

    return [rid for _, rid in sorted(items, reverse=True)]


def build_memory_for_request_id(request_id: str, base_dir: Path = DEFAULT_BASE_DIR, write: bool = False) -> Dict[str, Any]:
    record = build_incident_memory(request_id=request_id, base_dir=base_dir)

    if write:
        path = upsert_incident_memory(record, base_dir)
        record["memory_file"] = str(path)

    return record


def build_memory_from_existing_files(base_dir: Path = DEFAULT_BASE_DIR, limit: int = 0, write: bool = True) -> Dict[str, Any]:
    rids = iter_request_ids_from_reviews(base_dir)

    if limit and limit > 0:
        rids = rids[:limit]

    records = []
    errors = []

    for rid in rids:
        try:
            records.append(build_incident_memory(rid, base_dir))
        except Exception as exc:
            errors.append({"request_id": rid, "error": str(exc)})

    path = ""
    if write:
        path = str(write_incident_memories(records, base_dir))

    return {
        "ok": len(errors) == 0,
        "stage": "v7.1_incident_memory_build",
        "memory_file": path,
        "record_count": len(records),
        "error_count": len(errors),
        "errors": errors[:20],
    }


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


def query_incident_memories(
    base_dir: Path = DEFAULT_BASE_DIR,
    family: str = "",
    hostname: str = "",
    interface: str = "",
    q: str = "",
    days: int = 0,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    records = read_incident_memories(base_dir)
    now = datetime.now(timezone.utc)

    family_l = family.lower().strip()
    hostname_l = hostname.lower().strip()
    iface_n = normalize_interface_name(interface).lower().strip() if interface else ""
    q_l = q.lower().strip()

    result = []

    for item in records:
        if family_l and family_l not in safe_text(item.get("family")).lower():
            continue

        if hostname_l and hostname_l not in safe_text(item.get("hostname")).lower():
            continue

        if iface_n:
            interfaces = [normalize_interface_name(x).lower() for x in item.get("interfaces") or []]
            if iface_n not in interfaces:
                continue

        if days and days > 0:
            dt = parse_time(item.get("event_time") or item.get("created_at"))
            if dt and now - dt > timedelta(days=days):
                continue

        if q_l:
            haystack = json.dumps(
                {
                    "request_id": item.get("request_id"),
                    "family": item.get("family"),
                    "hostname": item.get("hostname"),
                    "interfaces": item.get("interfaces"),
                    "circuit_alias": item.get("circuit_alias"),
                    "direction": item.get("direction"),
                    "alarm_type": item.get("alarm_type"),
                    "judgement": item.get("judgement"),
                },
                ensure_ascii=False,
            ).lower()

            if q_l not in haystack:
                continue

        result.append(item)

    result.sort(key=lambda x: safe_text(x.get("event_time") or x.get("created_at")), reverse=True)

    if limit and limit > 0:
        result = result[:limit]

    return result


def get_incident_memory(request_id: str, base_dir: Path = DEFAULT_BASE_DIR) -> Optional[Dict[str, Any]]:
    for item in read_incident_memories(base_dir):
        if item.get("request_id") == request_id:
            return item
    return None


def validate_no_raw_sensitive_values(record: Dict[str, Any]) -> Dict[str, Any]:
    values: List[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ("source_files",):
                    continue
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, (str, int, float)):
            values.append(str(value))

    walk(record)

    text = "\n".join(values)
    findings = []

    ipv4_hits = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    if ipv4_hits:
        findings.append({"type": "raw_ipv4", "count": len(ipv4_hits), "samples": ipv4_hits[:3]})

    secret_words = ["password", "passwd", "token", "mcp_server_url", "webhook_secret", "api_key"]
    lower = text.lower()

    for word in secret_words:
        if word in lower:
            findings.append({"type": "keyword", "value": word})

    return {
        "ok": not findings,
        "findings": findings,
    }
