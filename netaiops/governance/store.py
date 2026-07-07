"""Filesystem store for NetAIOps Webhook v11 governance records.

The store is deliberately local and deterministic.  It writes UTF-8 JSON by
atomic replacement, validates known record schemas, rejects sensitive fields,
and isolates damaged files during list operations.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from pydantic import BaseModel, ValidationError

from .contracts import GOVERNANCE_SCHEMA_VERSION
from .schemas import GovernanceBaseModel, validate_governance_id, validate_governance_payload

DEFAULT_GOVERNANCE_ROOT = Path("/opt/netaiops-webhook/data/governance")

COLLECTION_SCHEMA = {
    "incident_memory": "incident_memory",
    "signals": "learning_signal",
    "proposals": "proposal",
    "replays": "replay",
    "audits": "audit",
}
COLLECTION_ID_FIELD = {
    "incident_memory": "memory_id",
    "signals": "signal_id",
    "proposals": "proposal_id",
    "replays": "replay_id",
    "reports": "report_id",
    "audits": "audit_id",
    "backfill": "backfill_id",
}
ALLOWED_COLLECTIONS = frozenset(COLLECTION_ID_FIELD)

_SENSITIVE_EXACT_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "access_token",
        "refresh_token",
        "private_key",
        "client_secret",
    }
)
_SENSITIVE_SUFFIXES = (
    "_password",
    "_passwd",
    "_secret",
    "_api_key",
    "_access_token",
    "_refresh_token",
    "_private_key",
    "_client_secret",
)


class GovernanceStoreError(RuntimeError):
    """Base exception for governed persistence failures."""


class UnsafeStorePathError(GovernanceStoreError):
    """Raised when a collection, identifier or symlink escapes the store root."""


class SensitiveContentError(GovernanceStoreError):
    """Raised when a payload contains forbidden credential material."""


class CorruptRecordError(GovernanceStoreError):
    """Raised when a stored JSON record cannot be safely read and validated."""


class RecordExistsError(GovernanceStoreError):
    """Raised when overwrite=False and the target record already exists."""


@dataclass(frozen=True)
class StoreWriteResult:
    collection: str
    record_id: str
    path: str
    sha256: str
    size_bytes: int
    created: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class StorePage:
    collection: str
    page: int
    page_size: int
    total: int
    corrupt_count: int
    items: tuple[dict[str, Any], ...]
    errors: tuple[dict[str, str], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "collection": self.collection,
            "page": self.page,
            "page_size": self.page_size,
            "total": self.total,
            "corrupt_count": self.corrupt_count,
            "items": [dict(item) for item in self.items],
            "errors": [dict(item) for item in self.errors],
        }


def _normalise_key(value: Any) -> str:
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


def _is_sensitive_key(value: Any) -> bool:
    key = _normalise_key(value)
    return key in _SENSITIVE_EXACT_KEYS or key.endswith(_SENSITIVE_SUFFIXES)


def find_sensitive_paths(value: Any, path: str = "$") -> tuple[str, ...]:
    """Return deterministic JSON paths containing credential-like material."""

    found: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if _is_sensitive_key(key):
                found.append(child_path)
            found.extend(find_sensitive_paths(child, child_path))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            found.extend(find_sensitive_paths(child, f"{path}[{index}]"))
    elif isinstance(value, str):
        text = value.strip()
        lowered = text.lower()
        if lowered.startswith("bearer ") or "-----begin private key-----" in lowered:
            found.append(path)
    return tuple(sorted(set(found)))


def _directory_fsync(path: Path) -> None:
    """Best-effort fsync of a directory after atomic replacement."""

    flags = getattr(os, "O_DIRECTORY", 0) | os.O_RDONLY
    try:
        fd = os.open(str(path), flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class GovernanceStore:
    """Validated JSON store rooted under ``data/governance`` by default."""

    def __init__(self, root: Path | str = DEFAULT_GOVERNANCE_ROOT) -> None:
        self.root = Path(root).expanduser().resolve(strict=False)

    @staticmethod
    def _safe_collection(collection: str) -> str:
        name = str(collection or "").strip()
        if name not in ALLOWED_COLLECTIONS:
            raise UnsafeStorePathError(f"unsupported governance collection: {collection!r}")
        return name

    @staticmethod
    def _safe_record_id(record_id: str) -> str:
        try:
            return validate_governance_id(record_id, field_name="record_id")
        except ValueError as exc:
            raise UnsafeStorePathError(str(exc)) from exc

    def _ensure_within_root(self, path: Path) -> Path:
        resolved = path.resolve(strict=False)
        try:
            resolved.relative_to(self.root)
        except ValueError as exc:
            raise UnsafeStorePathError(f"path escapes governance root: {path}") from exc
        return resolved

    def collection_dir(self, collection: str) -> Path:
        name = self._safe_collection(collection)
        path = self._ensure_within_root(self.root / name)
        if path.exists() and path.is_symlink():
            raise UnsafeStorePathError(f"collection directory must not be a symlink: {path}")
        return path

    def record_path(self, collection: str, record_id: str) -> Path:
        name = self._safe_collection(collection)
        safe_id = self._safe_record_id(record_id)
        return self._ensure_within_root(self.collection_dir(name) / f"{safe_id}.json")

    @staticmethod
    def _mapping_payload(payload: Mapping[str, Any] | BaseModel) -> dict[str, Any]:
        if isinstance(payload, BaseModel):
            return payload.model_dump(mode="json", by_alias=True)
        if not isinstance(payload, Mapping):
            raise TypeError("governance payload must be a Mapping or Pydantic BaseModel")
        return dict(payload)

    @staticmethod
    def _assert_no_sensitive_content(payload: Mapping[str, Any]) -> None:
        paths = find_sensitive_paths(payload)
        if paths:
            raise SensitiveContentError(
                "governance payload contains forbidden sensitive fields: "
                + ", ".join(paths)
            )

    @staticmethod
    def _validate_generic_payload(
        collection: str,
        record_id: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        id_field = COLLECTION_ID_FIELD[collection]
        if payload.get("schema_version") != GOVERNANCE_SCHEMA_VERSION:
            raise GovernanceStoreError(
                f"{collection} payload must use schema_version "
                f"{GOVERNANCE_SCHEMA_VERSION!r}"
            )
        if payload.get(id_field) != record_id:
            raise GovernanceStoreError(
                f"{collection} payload field {id_field!r} must equal record_id"
            )
        try:
            text = json.dumps(payload, ensure_ascii=False, allow_nan=False)
            data = json.loads(text)
        except (TypeError, ValueError) as exc:
            raise GovernanceStoreError(f"payload is not strict JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise GovernanceStoreError("governance payload must encode a JSON object")
        return data

    def _validate_payload(
        self,
        collection: str,
        record_id: str,
        payload: Mapping[str, Any] | BaseModel,
    ) -> dict[str, Any]:
        name = self._safe_collection(collection)
        safe_id = self._safe_record_id(record_id)
        raw = self._mapping_payload(payload)
        self._assert_no_sensitive_content(raw)

        schema_name = COLLECTION_SCHEMA.get(name)
        if schema_name is None:
            normalised = self._validate_generic_payload(name, safe_id, raw)
        else:
            try:
                model = validate_governance_payload(schema_name, raw)
            except (ValidationError, ValueError, TypeError) as exc:
                raise GovernanceStoreError(
                    f"invalid {name} payload for {safe_id}: {exc}"
                ) from exc
            id_field = COLLECTION_ID_FIELD[name]
            if getattr(model, id_field) != safe_id:
                raise GovernanceStoreError(
                    f"{name} payload field {id_field!r} must equal record_id"
                )
            normalised = model.to_payload()

        self._assert_no_sensitive_content(normalised)
        return normalised

    def write(
        self,
        collection: str,
        record_id: str,
        payload: Mapping[str, Any] | GovernanceBaseModel,
        *,
        overwrite: bool = True,
    ) -> StoreWriteResult:
        """Validate and atomically write one governance record."""

        name = self._safe_collection(collection)
        safe_id = self._safe_record_id(record_id)
        data = self._validate_payload(name, safe_id, payload)
        directory = self.collection_dir(name)
        directory.mkdir(parents=True, exist_ok=True)
        if directory.is_symlink():
            raise UnsafeStorePathError(f"collection directory must not be a symlink: {directory}")

        target = self.record_path(name, safe_id)
        if target.is_symlink():
            raise UnsafeStorePathError(f"record target must not be a symlink: {target}")
        existed = target.exists()
        if existed and not overwrite:
            raise RecordExistsError(f"governance record already exists: {name}/{safe_id}")

        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="\n",
                dir=str(directory),
                prefix=f".{safe_id}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temp_path = Path(handle.name)
                json.dump(
                    data,
                    handle,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                    allow_nan=False,
                )
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_path, 0o640)
            os.replace(temp_path, target)
            temp_path = None
            _directory_fsync(directory)
        except Exception:
            if temp_path is not None:
                try:
                    temp_path.unlink()
                except FileNotFoundError:
                    pass
            raise

        content = target.read_bytes()
        return StoreWriteResult(
            collection=name,
            record_id=safe_id,
            path=str(target),
            sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
            created=not existed,
        )

    def read(self, collection: str, record_id: str) -> dict[str, Any]:
        """Read, validate and return one record as JSON-compatible data."""

        name = self._safe_collection(collection)
        safe_id = self._safe_record_id(record_id)
        path = self.record_path(name, safe_id)
        if path.is_symlink():
            raise UnsafeStorePathError(f"record path must not be a symlink: {path}")
        if not path.is_file():
            raise FileNotFoundError(path)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise CorruptRecordError(f"cannot decode {name}/{safe_id}: {exc}") from exc
        if not isinstance(payload, dict):
            raise CorruptRecordError(f"record is not a JSON object: {name}/{safe_id}")
        try:
            return self._validate_payload(name, safe_id, payload)
        except (GovernanceStoreError, SensitiveContentError) as exc:
            raise CorruptRecordError(f"invalid stored record {name}/{safe_id}: {exc}") from exc

    def list_records(
        self,
        collection: str,
        *,
        page: int = 1,
        page_size: int = 50,
        descending: bool = True,
    ) -> StorePage:
        """List valid records while reporting, rather than raising on, corruption."""

        name = self._safe_collection(collection)
        if isinstance(page, bool) or page < 1:
            raise ValueError("page must be an integer >= 1")
        if isinstance(page_size, bool) or page_size < 1 or page_size > 500:
            raise ValueError("page_size must be between 1 and 500")

        directory = self.collection_dir(name)
        if not directory.exists():
            return StorePage(name, page, page_size, 0, 0, (), ())

        valid: list[tuple[str, dict[str, Any]]] = []
        errors: list[dict[str, str]] = []
        for path in sorted(directory.glob("*.json"), key=lambda item: item.name):
            record_id = path.stem
            try:
                item = self.read(name, record_id)
            except Exception as exc:  # isolation boundary for damaged runtime files
                errors.append(
                    {
                        "record_id": record_id,
                        "path": str(path),
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                continue
            valid.append((record_id, item))

        valid.sort(key=lambda pair: pair[0], reverse=descending)
        start = (page - 1) * page_size
        end = start + page_size
        items = tuple(item for _, item in valid[start:end])
        return StorePage(
            collection=name,
            page=page,
            page_size=page_size,
            total=len(valid),
            corrupt_count=len(errors),
            items=items,
            errors=tuple(errors),
        )

    def health(self) -> dict[str, Any]:
        """Check that the store root is writable without creating a record."""

        self.root.mkdir(parents=True, exist_ok=True)
        probe: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(self.root),
                prefix=".governance-health-",
                suffix=".tmp",
                delete=False,
            ) as handle:
                probe = Path(handle.name)
                handle.write("ok\n")
                handle.flush()
                os.fsync(handle.fileno())
            probe.unlink()
            probe = None
        except Exception as exc:
            if probe is not None:
                try:
                    probe.unlink()
                except FileNotFoundError:
                    pass
            return {
                "status": "error",
                "root": str(self.root),
                "writable": False,
                "error": f"{type(exc).__name__}: {exc}",
            }
        return {
            "status": "ok",
            "root": str(self.root),
            "writable": True,
            "schema_version": GOVERNANCE_SCHEMA_VERSION,
            "collections": sorted(ALLOWED_COLLECTIONS),
        }


__all__ = [
    "ALLOWED_COLLECTIONS",
    "COLLECTION_ID_FIELD",
    "COLLECTION_SCHEMA",
    "CorruptRecordError",
    "DEFAULT_GOVERNANCE_ROOT",
    "GovernanceStore",
    "GovernanceStoreError",
    "RecordExistsError",
    "SensitiveContentError",
    "StorePage",
    "StoreWriteResult",
    "UnsafeStorePathError",
    "find_sensitive_paths",
]
