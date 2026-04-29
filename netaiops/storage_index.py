import argparse
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


BASE_DIR = Path("/opt/netaiops-webhook")
DATA_DIR = BASE_DIR / "data"
INDEX_DIR = DATA_DIR / "index"
DB_PATH = INDEX_DIR / "netaiops_meta.sqlite3"

NORMALIZED_DIR = DATA_DIR / "normalized"
ANALYSIS_DIR = DATA_DIR / "analysis"
PLAN_DIR = DATA_DIR / "plans"
EXECUTION_DIR = DATA_DIR / "execution"
REVIEW_DIR = DATA_DIR / "reviews"


def now_utc_str() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def read_json_file(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def connect_db() -> sqlite3.Connection:
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with connect_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS requests (
                request_id TEXT PRIMARY KEY,
                source TEXT,
                event_status TEXT,
                severity TEXT,
                alarm_type TEXT,
                family TEXT,
                hostname TEXT,
                device_ip TEXT,
                object_type TEXT,
                interface_name TEXT,
                peer_ip TEXT,
                pool_member TEXT,
                event_time TEXT,
                created_at TEXT,
                updated_at TEXT,
                has_normalized INTEGER,
                has_analysis INTEGER,
                has_plan INTEGER,
                has_execution INTEGER,
                has_review INTEGER,
                plan_status TEXT,
                execution_status TEXT,
                review_status TEXT,
                execution_source TEXT,
                title TEXT,
                dedup_key TEXT,
                artifact_json TEXT
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS artifacts (
                request_id TEXT,
                kind TEXT,
                path TEXT,
                mtime TEXT,
                size INTEGER,
                PRIMARY KEY (request_id, kind, path)
            )
            """
        )

        conn.execute("CREATE INDEX IF NOT EXISTS idx_requests_device_ip ON requests(device_ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_requests_family ON requests(family)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_requests_interface ON requests(interface_name)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_requests_event_status ON requests(event_status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_requests_updated_at ON requests(updated_at)")
        conn.commit()


def request_id_from_file(path: Path, suffix: str) -> str:
    name = path.name

    if suffix and name.endswith(suffix):
        name = name[: -len(suffix)]

    if "_" in name:
        return name.split("_", 1)[1]

    if name.endswith(".dispatch.request"):
        return name.replace(".dispatch.request", "")

    return ""


def find_optional_file(directory: Path, request_id: str, suffix: str) -> Optional[Path]:
    files = list(directory.glob(f"*_{request_id}{suffix}"))
    if files:
        return files[0]
    return None


def collect_request_ids() -> List[str]:
    request_ids = set()

    patterns = [
        (NORMALIZED_DIR, ".json"),
        (ANALYSIS_DIR, ".analysis.json"),
        (PLAN_DIR, ".plan.json"),
        (EXECUTION_DIR, ".execution.json"),
        (REVIEW_DIR, ".review.json"),
    ]

    for directory, suffix in patterns:
        if not directory.exists():
            continue

        for path in directory.glob(f"*{suffix}"):
            rid = request_id_from_file(path, suffix)
            if rid:
                request_ids.add(rid)

    return sorted(request_ids)


def artifact_info(path: Optional[Path], kind: str, request_id: str) -> Optional[Dict[str, Any]]:
    if not path or not path.exists():
        return None

    stat = path.stat()
    return {
        "request_id": request_id,
        "kind": kind,
        "path": str(path),
        "mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        "size": stat.st_size,
    }


def first_event_from_normalized(data: Dict[str, Any]) -> Dict[str, Any]:
    events = data.get("events", []) or []
    if events and isinstance(events[0], dict):
        return events[0]
    return {}


def build_dedup_key(family: str, device_ip: str, interface_name: str, peer_ip: str, pool_member: str, alarm_type: str) -> str:
    object_id = interface_name or peer_ip or pool_member or alarm_type or "device"
    return "|".join(
        [
            safe_text(family).lower(),
            safe_text(device_ip).lower(),
            safe_text(object_id).lower(),
        ]
    )


def index_request(request_id: str) -> Dict[str, Any]:
    init_db()

    normalized_path = find_optional_file(NORMALIZED_DIR, request_id, ".json")
    analysis_path = find_optional_file(ANALYSIS_DIR, request_id, ".analysis.json")
    plan_path = find_optional_file(PLAN_DIR, request_id, ".plan.json")
    execution_path = find_optional_file(EXECUTION_DIR, request_id, ".execution.json")
    review_path = find_optional_file(REVIEW_DIR, request_id, ".review.json")

    normalized_data = read_json_file(normalized_path) if normalized_path else {}
    analysis_data = read_json_file(analysis_path) if analysis_path else {}
    plan_data = read_json_file(plan_path) if plan_path else {}
    execution_data = read_json_file(execution_path) if execution_path else {}
    review_data = read_json_file(review_path) if review_path else {}

    event = first_event_from_normalized(normalized_data)
    analysis_event = analysis_data.get("event", {}) or {}
    target_scope = plan_data.get("target_scope", {}) or execution_data.get("target_scope", {}) or {}
    family_result = plan_data.get("family_result", {}) or execution_data.get("family_result", {}) or {}
    classification = plan_data.get("classification", {}) or execution_data.get("classification", {}) or {}
    playbook = plan_data.get("playbook", {}) or execution_data.get("playbook", {}) or {}

    family = (
        safe_text(family_result.get("family"))
        or safe_text(classification.get("family"))
        or safe_text(classification.get("playbook_type"))
        or safe_text(playbook.get("playbook_id"))
        or safe_text(event.get("family"))
        or safe_text(event.get("playbook_type_hint"))
    )

    source = safe_text(normalized_data.get("source") or analysis_data.get("source") or event.get("source"))
    event_status = safe_text(event.get("status") or analysis_event.get("status"))
    severity = safe_text(event.get("severity") or analysis_event.get("severity"))
    alarm_type = safe_text(event.get("alarm_type") or analysis_event.get("alarm_type") or target_scope.get("alarm_type"))
    hostname = safe_text(target_scope.get("hostname") or event.get("hostname") or analysis_event.get("hostname"))
    device_ip = safe_text(target_scope.get("device_ip") or event.get("device_ip") or analysis_event.get("device_ip"))
    object_type = safe_text(event.get("object_type") or target_scope.get("object_type"))
    interface_name = safe_text(target_scope.get("interface") or event.get("interface") or event.get("ifName"))
    peer_ip = safe_text(target_scope.get("peer_ip") or event.get("peer_ip"))
    pool_member = safe_text(target_scope.get("pool_member") or event.get("pool_member"))
    event_time = safe_text(event.get("timestamp") or event.get("startsAt") or normalized_data.get("created_at"))

    plan_status = safe_text(plan_data.get("plan_status"))
    execution_status = safe_text(execution_data.get("execution_status"))
    review_status = safe_text(review_data.get("review_status"))
    execution_source = safe_text(plan_data.get("execution_source") or execution_data.get("execution_source"))

    title = safe_text(
        review_data.get("title")
        or ((analysis_data.get("result") or {}).get("summary"))
        or event.get("raw_text")
        or alarm_type
    )

    dedup_key = build_dedup_key(family, device_ip, interface_name, peer_ip, pool_member, alarm_type)

    artifacts = {
        "normalized": str(normalized_path) if normalized_path else "",
        "analysis": str(analysis_path) if analysis_path else "",
        "plan": str(plan_path) if plan_path else "",
        "execution": str(execution_path) if execution_path else "",
        "review": str(review_path) if review_path else "",
    }

    row = {
        "request_id": request_id,
        "source": source,
        "event_status": event_status,
        "severity": severity,
        "alarm_type": alarm_type,
        "family": family,
        "hostname": hostname,
        "device_ip": device_ip,
        "object_type": object_type,
        "interface_name": interface_name,
        "peer_ip": peer_ip,
        "pool_member": pool_member,
        "event_time": event_time,
        "created_at": event_time,
        "updated_at": now_utc_str(),
        "has_normalized": 1 if normalized_path else 0,
        "has_analysis": 1 if analysis_path else 0,
        "has_plan": 1 if plan_path else 0,
        "has_execution": 1 if execution_path else 0,
        "has_review": 1 if review_path else 0,
        "plan_status": plan_status,
        "execution_status": execution_status,
        "review_status": review_status,
        "execution_source": execution_source,
        "title": title,
        "dedup_key": dedup_key,
        "artifact_json": json.dumps(artifacts, ensure_ascii=False),
    }

    artifact_rows = [
        artifact_info(normalized_path, "normalized", request_id),
        artifact_info(analysis_path, "analysis", request_id),
        artifact_info(plan_path, "plan", request_id),
        artifact_info(execution_path, "execution", request_id),
        artifact_info(review_path, "review", request_id),
    ]

    with connect_db() as conn:
        conn.execute("DELETE FROM requests WHERE request_id = ?", (request_id,))

        conn.execute(
            """
            INSERT INTO requests (
                request_id, source, event_status, severity, alarm_type, family,
                hostname, device_ip, object_type, interface_name, peer_ip, pool_member,
                event_time, created_at, updated_at,
                has_normalized, has_analysis, has_plan, has_execution, has_review,
                plan_status, execution_status, review_status, execution_source,
                title, dedup_key, artifact_json
            )
            VALUES (
                :request_id, :source, :event_status, :severity, :alarm_type, :family,
                :hostname, :device_ip, :object_type, :interface_name, :peer_ip, :pool_member,
                :event_time, :created_at, :updated_at,
                :has_normalized, :has_analysis, :has_plan, :has_execution, :has_review,
                :plan_status, :execution_status, :review_status, :execution_source,
                :title, :dedup_key, :artifact_json
            )
            """,
            row,
        )

        conn.execute("DELETE FROM artifacts WHERE request_id = ?", (request_id,))

        for artifact in artifact_rows:
            if not artifact:
                continue
            conn.execute(
                """
                INSERT OR REPLACE INTO artifacts (
                    request_id, kind, path, mtime, size
                )
                VALUES (
                    :request_id, :kind, :path, :mtime, :size
                )
                """,
                artifact,
            )

        conn.commit()

    return row


def rebuild_index(limit: int = 0) -> Dict[str, Any]:
    init_db()
    request_ids = collect_request_ids()
    if limit and limit > 0:
        request_ids = request_ids[:limit]

    indexed = 0
    failed: List[Dict[str, str]] = []

    for rid in request_ids:
        try:
            index_request(rid)
            indexed += 1
        except Exception as e:
            failed.append({"request_id": rid, "error": str(e)})

    return {
        "db_path": str(DB_PATH),
        "total_seen": len(request_ids),
        "indexed": indexed,
        "failed": failed,
    }


def search_requests(
    family: str = "",
    device_ip: str = "",
    interface_name: str = "",
    event_status: str = "",
    text: str = "",
    limit: int = 20,
) -> List[Dict[str, Any]]:
    init_db()

    clauses = []
    params: Dict[str, Any] = {}

    if family:
        clauses.append("family = :family")
        params["family"] = family

    if device_ip:
        clauses.append("device_ip = :device_ip")
        params["device_ip"] = device_ip

    if interface_name:
        clauses.append("interface_name = :interface_name")
        params["interface_name"] = interface_name

    if event_status:
        clauses.append("event_status = :event_status")
        params["event_status"] = event_status

    if text:
        clauses.append("(alarm_type LIKE :text OR title LIKE :text OR hostname LIKE :text)")
        params["text"] = f"%{text}%"

    sql = "SELECT * FROM requests"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)

    sql += " ORDER BY updated_at DESC LIMIT :limit"
    params["limit"] = int(limit)

    with connect_db() as conn:
        rows = conn.execute(sql, params).fetchall()

    result = []
    for row in rows:
        item = dict(row)
        try:
            item["artifact_json"] = json.loads(item.get("artifact_json") or "{}")
        except Exception:
            pass
        result.append(item)

    return result


def show_request(request_id: str) -> Dict[str, Any]:
    init_db()
    with connect_db() as conn:
        row = conn.execute(
            "SELECT * FROM requests WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        artifacts = conn.execute(
            "SELECT * FROM artifacts WHERE request_id = ? ORDER BY kind",
            (request_id,),
        ).fetchall()

    return {
        "request": dict(row) if row else {},
        "artifacts": [dict(x) for x in artifacts],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    p_rebuild = sub.add_parser("rebuild")
    p_rebuild.add_argument("--limit", type=int, default=0)

    p_index = sub.add_parser("index")
    p_index.add_argument("request_id")

    p_search = sub.add_parser("search")
    p_search.add_argument("--family", default="")
    p_search.add_argument("--device-ip", default="")
    p_search.add_argument("--interface", default="")
    p_search.add_argument("--status", default="")
    p_search.add_argument("--text", default="")
    p_search.add_argument("--limit", type=int, default=20)

    p_show = sub.add_parser("show")
    p_show.add_argument("request_id")

    args = parser.parse_args()

    if args.command == "rebuild":
        print(json.dumps(rebuild_index(args.limit), ensure_ascii=False, indent=2))
    elif args.command == "index":
        print(json.dumps(index_request(args.request_id), ensure_ascii=False, indent=2))
    elif args.command == "search":
        print(
            json.dumps(
                search_requests(
                    family=args.family,
                    device_ip=args.device_ip,
                    interface_name=args.interface,
                    event_status=args.status,
                    text=args.text,
                    limit=args.limit,
                ),
                ensure_ascii=False,
                indent=2,
            )
        )
    elif args.command == "show":
        print(json.dumps(show_request(args.request_id), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
