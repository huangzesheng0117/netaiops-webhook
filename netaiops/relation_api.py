"""v7.2 Relation Engine API helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from netaiops.relation_engine import (
    build_relation_graph,
    find_relations_for_request_id,
    query_relation_graph,
)


def build_relations_response(
    base_dir: Path,
    family: str = "",
    hostname: str = "",
    interface: str = "",
    relation_type: str = "",
    min_score: int = 0,
    limit: int = 20,
    rebuild: bool = False,
    rebuild_limit: int = 0,
) -> Dict[str, Any]:
    return query_relation_graph(
        base_dir=base_dir,
        family=family,
        hostname=hostname,
        interface=interface,
        relation_type=relation_type,
        min_score=min_score,
        limit=limit,
        rebuild=rebuild,
        rebuild_limit=rebuild_limit,
    )


def build_relation_rebuild_response(
    base_dir: Path,
    limit: int = 0,
) -> Dict[str, Any]:
    graph = build_relation_graph(
        base_dir=base_dir,
        limit=limit,
        write=True,
    )
    return {
        "status": "ok",
        "stage": "v7.2_relation_engine_rebuild",
        "record_count": graph.get("record_count", 0),
        "relation_count": graph.get("relation_count", 0),
        "cluster_count": graph.get("cluster_count", 0),
        "relation_file": graph.get("relation_file", ""),
    }


def build_relation_detail_response(
    request_id: str,
    base_dir: Path,
    rebuild: bool = False,
    rebuild_limit: int = 0,
) -> Dict[str, Any]:
    return find_relations_for_request_id(
        request_id=request_id,
        base_dir=base_dir,
        rebuild=rebuild,
        limit=rebuild_limit,
    )
