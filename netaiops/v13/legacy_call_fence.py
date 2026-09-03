"""Persistent request/source fence preventing legacy duplicate real calls.

D3 installs the contract and storage layer only.  The production legacy
Sidecar/Dispatcher hook remains inactive until the later v13 release cutover;
D3 deterministic/replay prove the exact skip decision that the release hook
must consume.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal

from netaiops.v12.atomic_writer import AtomicJsonWriter
from netaiops.v12.schema_validator import validate_request_id

from .evidence_owner_contracts import LegacyCallFenceRecord


class LegacyCallFence:
    def __init__(
        self,
        root: str | Path,
        *,
        utcnow: Callable[[], datetime] | None = None,
    ) -> None:
        self.root = Path(root)
        self._utcnow = utcnow or (lambda: datetime.now(timezone.utc))

    def record(self, fence: LegacyCallFenceRecord) -> Path:
        directory = self._request_dir(fence.request_id)
        writer = AtomicJsonWriter(directory)
        return writer.write_json(f"{fence.source}_owner_fence.json", fence)

    def load(
        self,
        request_id: str,
        source: Literal["metrics", "device"],
    ) -> LegacyCallFenceRecord | None:
        path = self._request_dir(request_id) / f"{source}_owner_fence.json"
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("legacy call fence must be a regular file")
        return LegacyCallFenceRecord.model_validate(json.loads(path.read_text(encoding="utf-8")))

    def legacy_action(
        self,
        request_id: str,
        source: Literal["metrics", "device"],
    ) -> str:
        record = self.load(request_id, source)
        return "skip_duplicate" if record is not None and record.active else "allow_legacy"

    def _request_dir(self, request_id: str) -> Path:
        validate_request_id(request_id)
        request_dir = self.root / request_id
        path = request_dir / "v13"
        if request_dir.exists() and request_dir.is_symlink():
            raise RuntimeError("v13 fence request directory must not be a symlink")
        if path.exists() and path.is_symlink():
            raise RuntimeError("v13 fence trace directory must not be a symlink")
        return path
