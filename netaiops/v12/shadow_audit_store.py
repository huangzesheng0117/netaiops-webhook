"""Atomic v12 Shadow Integration audit persistence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .atomic_writer import AtomicJsonWriter, AtomicWriteError
from .schema_validator import validate_request_id
from .shadow_contracts import ShadowIntegrationAudit


DEFAULT_SHADOW_AUDIT_ROOT = Path(
    "/opt/netaiops-webhook/data/evidence_hub/requests"
)


class ShadowAuditStoreError(OSError):
    """Raised when a Shadow audit cannot be stored safely."""


class ShadowAuditStore:
    """Write only the v12 shadow_integration.json artifact."""

    def __init__(
        self,
        base_dir: str | Path = DEFAULT_SHADOW_AUDIT_ROOT,
        *,
        writer_factory: Any = AtomicJsonWriter,
    ) -> None:
        self.base_dir = Path(base_dir)
        self.writer_factory = writer_factory

    def persist(
        self,
        audit: ShadowIntegrationAudit,
    ) -> Path:
        request_id = validate_request_id(audit.request_id)
        root = self.base_dir / request_id / "v12"
        request_dir = self.base_dir / request_id
        if request_dir.exists() and request_dir.is_symlink():
            raise ShadowAuditStoreError(
                "request directory must not be a symlink"
            )
        if root.exists() and root.is_symlink():
            raise ShadowAuditStoreError(
                "v12 directory must not be a symlink"
            )

        writer = self.writer_factory(root)
        try:
            return writer.write_json(
                "shadow_integration.json",
                audit,
            )
        except AtomicWriteError as exc:
            raise ShadowAuditStoreError(
                "Shadow audit persistence failed"
            ) from exc
