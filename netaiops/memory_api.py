"""v7.1 Incident Memory API helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from netaiops.memory_store import (
    build_memory_for_request_id,
    build_memory_from_existing_files,
    get_incident_memory,
    query_incident_memories,
    read_incident_memories,
    validate_no_raw_sensitive_values,
)


def build_incidents_response(
    base_dir: Path,
    family: str = "",
    hostname: str = "",
    interface: str = "",
    q: str = "",
    days: int = 0,
    limit: int = 20,
    rebuild: bool = False,
    rebuild_limit: int = 0,
) -> Dict[str, Any]:
    rebuild_result = None

    if rebuild:
        rebuild_result = build_memory_from_existing_files(
            base_dir=base_dir,
            limit=rebuild_limit,
            write=True,
        )

    records = query_incident_memories(
        base_dir=base_dir,
        family=family,
        hostname=hostname,
        interface=interface,
        q=q,
        days=days,
        limit=limit,
    )

    return {
        "status": "ok",
        "stage": "v7.1_incident_memory",
        "memory_type": "incident_memory",
        "filters": {
            "family": family,
            "hostname": hostname,
            "interface": interface,
            "q": q,
            "days": days,
            "limit": limit,
        },
        "rebuild_result": rebuild_result,
        "total_memory_records": len(read_incident_memories(base_dir)),
        "record_count": len(records),
        "records": records,
    }


def build_incident_detail_response(
    request_id: str,
    base_dir: Path,
    build: bool = True,
    write: bool = True,
) -> Dict[str, Any]:
    record = None
    build_result = None

    if build:
        record = build_memory_for_request_id(
            request_id=request_id,
            base_dir=base_dir,
            write=write,
        )
        build_result = {
            "built": True,
            "written": write,
            "memory_file": record.get("memory_file", ""),
        }
    else:
        record = get_incident_memory(request_id, base_dir=base_dir)

    if not record:
        raise FileNotFoundError(f"incident memory not found for request_id={request_id}")

    safety_check = validate_no_raw_sensitive_values(record)

    return {
        "status": "ok",
        "stage": "v7.1_incident_memory_detail",
        "request_id": request_id,
        "build_result": build_result,
        "safety_check": safety_check,
        "record": record,
    }
