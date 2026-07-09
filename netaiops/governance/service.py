"""Read-only service layer for NetAIOps Webhook v11 Governance API.

Batch 8 exposes compact Governance Store records through a read-only API.  The
service never calls GLM, Prometheus MCP, Netmiko MCP, or notification endpoints,
and the health check does not create Governance records.
"""
from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from .contracts import GOVERNANCE_SCHEMA_VERSION
from .store import (
    ALLOWED_COLLECTIONS,
    COLLECTION_ID_FIELD,
    COLLECTION_SCHEMA,
    DEFAULT_GOVERNANCE_ROOT,
    GovernanceStore,
    GovernanceStoreError,
    StorePage,
)

GOVERNANCE_API_VERSION = "11.0.0-governance-api-v1"

COLLECTION_ALIASES: Mapping[str, str] = {
    "memories": "incident_memory",
    "memory": "incident_memory",
    "incident_memories": "incident_memory",
    "incident_memory": "incident_memory",
    "signals": "signals",
    "learning_signals": "signals",
    "proposals": "proposals",
    "replays": "replays",
    "reports": "reports",
    "audits": "audits",
    "backfill": "backfill",
}

COLLECTION_DISPLAY_NAMES: Mapping[str, str] = {
    "incident_memory": "Incident Memory",
    "signals": "Learning Signals",
    "proposals": "Proposals",
    "replays": "Offline Replays",
    "reports": "Learning Reports",
    "audits": "Release Audits",
    "backfill": "Backfill Runs",
}

_EXTERNAL_CALLS_FALSE = {
    "glm": False,
    "prometheus": False,
    "device": False,
    "notification": False,
    "production_write": False,
}


class GovernanceApiServiceError(ValueError):
    """Raised when a read-only Governance API request is invalid."""


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _jsonable(child) for key, child in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(child) for child in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _bounded_page(value: int, *, field_name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise GovernanceApiServiceError(f"{field_name} must be an integer")
    number = int(value)
    if number < minimum or number > maximum:
        raise GovernanceApiServiceError(
            f"{field_name} must be between {minimum} and {maximum}"
        )
    return number


def normalise_collection_name(value: str) -> str:
    key = str(value or "").strip().lower().replace("-", "_")
    collection = COLLECTION_ALIASES.get(key, key)
    if collection not in ALLOWED_COLLECTIONS:
        allowed = ", ".join(sorted(COLLECTION_ALIASES))
        raise GovernanceApiServiceError(
            f"unsupported governance collection: {value!r}; allowed aliases: {allowed}"
        )
    return collection


def _collection_metadata(collection: str) -> dict[str, Any]:
    return {
        "collection": collection,
        "display_name": COLLECTION_DISPLAY_NAMES.get(collection, collection),
        "id_field": COLLECTION_ID_FIELD[collection],
        "schema": COLLECTION_SCHEMA.get(collection, "generic"),
        "aliases": sorted(
            alias for alias, target in COLLECTION_ALIASES.items() if target == collection
        ),
    }


class GovernanceReadService:
    """Small read-only facade over :class:`GovernanceStore`."""

    def __init__(self, root: Path | str = DEFAULT_GOVERNANCE_ROOT) -> None:
        self.root = Path(root).expanduser().resolve(strict=False)
        self.store = GovernanceStore(self.root)

    def external_call_policy(self) -> dict[str, bool]:
        return dict(_EXTERNAL_CALLS_FALSE)

    def health(self) -> dict[str, Any]:
        """Return read-only health without creating files or directories."""

        collection_summaries: dict[str, Any] = {}
        corrupt_total = 0
        readable = True
        root_exists = self.root.exists()
        root_is_symlink = self.root.is_symlink()
        parent = self.root if root_exists else self.root.parent
        parent_exists = parent.exists()
        parent_writable = bool(parent_exists and os.access(parent, os.W_OK))

        for collection in sorted(ALLOWED_COLLECTIONS):
            try:
                page = self.store.list_records(collection, page=1, page_size=1)
                collection_summaries[collection] = {
                    "total": page.total,
                    "corrupt_count": page.corrupt_count,
                    "sample_count": len(page.items),
                }
                corrupt_total += page.corrupt_count
            except Exception as exc:  # isolate damaged runtime state
                readable = False
                corrupt_total += 1
                collection_summaries[collection] = {
                    "total": 0,
                    "corrupt_count": 1,
                    "sample_count": 0,
                    "error": f"{type(exc).__name__}: {exc}",
                }

        status = "ok"
        if root_is_symlink or not readable:
            status = "error"
        elif corrupt_total:
            status = "warning"

        return {
            "status": status,
            "service": "netaiops-governance-api",
            "api_version": GOVERNANCE_API_VERSION,
            "schema_version": GOVERNANCE_SCHEMA_VERSION,
            "root": str(self.root),
            "root_exists": root_exists,
            "root_is_symlink": root_is_symlink,
            "parent_exists": parent_exists,
            "parent_writable": parent_writable,
            "read_only": True,
            "external_calls": self.external_call_policy(),
            "collections": collection_summaries,
            "corrupt_total": corrupt_total,
        }

    def collections(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "api_version": GOVERNANCE_API_VERSION,
            "schema_version": GOVERNANCE_SCHEMA_VERSION,
            "read_only": True,
            "external_calls": self.external_call_policy(),
            "collections": [
                _collection_metadata(collection) for collection in sorted(ALLOWED_COLLECTIONS)
            ],
        }

    def list_records(
        self,
        collection: str,
        *,
        page: int = 1,
        page_size: int = 50,
        descending: bool = True,
    ) -> dict[str, Any]:
        name = normalise_collection_name(collection)
        page_number = _bounded_page(page, field_name="page", minimum=1, maximum=100000)
        size = _bounded_page(page_size, field_name="page_size", minimum=1, maximum=500)
        store_page: StorePage = self.store.list_records(
            name,
            page=page_number,
            page_size=size,
            descending=bool(descending),
        )
        return {
            "status": "ok",
            "api_version": GOVERNANCE_API_VERSION,
            "schema_version": GOVERNANCE_SCHEMA_VERSION,
            "read_only": True,
            "external_calls": self.external_call_policy(),
            "collection": _collection_metadata(name),
            "page": store_page.page,
            "page_size": store_page.page_size,
            "total": store_page.total,
            "corrupt_count": store_page.corrupt_count,
            "items": [_jsonable(item) for item in store_page.items],
            "errors": [_jsonable(item) for item in store_page.errors],
        }

    def get_record(self, collection: str, record_id: str) -> dict[str, Any]:
        name = normalise_collection_name(collection)
        data = self.store.read(name, record_id)
        return {
            "status": "ok",
            "api_version": GOVERNANCE_API_VERSION,
            "schema_version": GOVERNANCE_SCHEMA_VERSION,
            "read_only": True,
            "external_calls": self.external_call_policy(),
            "collection": _collection_metadata(name),
            "record_id": str(record_id),
            "data": _jsonable(data),
        }

    def summary(self) -> dict[str, Any]:
        health = self.health()
        totals = {
            name: values.get("total", 0)
            for name, values in health.get("collections", {}).items()
            if isinstance(values, Mapping)
        }
        return {
            "status": health["status"],
            "api_version": GOVERNANCE_API_VERSION,
            "schema_version": GOVERNANCE_SCHEMA_VERSION,
            "read_only": True,
            "external_calls": self.external_call_policy(),
            "total_records": sum(int(value or 0) for value in totals.values()),
            "corrupt_total": health.get("corrupt_total", 0),
            "by_collection": dict(sorted(totals.items())),
        }


def default_governance_service() -> GovernanceReadService:
    return GovernanceReadService(DEFAULT_GOVERNANCE_ROOT)


__all__ = [
    "COLLECTION_ALIASES",
    "COLLECTION_DISPLAY_NAMES",
    "GOVERNANCE_API_VERSION",
    "GovernanceApiServiceError",
    "GovernanceReadService",
    "default_governance_service",
    "normalise_collection_name",
]
