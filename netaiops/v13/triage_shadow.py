"""V13-D2 store-only Triage shadow comparison and Agent Trace persistence."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from netaiops.v12.atomic_writer import AtomicJsonWriter, AtomicWriteError
from netaiops.v12.schema_validator import validate_request_id

from .triage_contracts import TriageOwnershipRecord, TriageShadowComparison
from .triage_owner import TriageOwner


DEFAULT_TRACE_ROOT = Path("/opt/netaiops-webhook/data/evidence_hub/requests")


class TriageShadowError(OSError):
    """Raised when the D2 store-only shadow trace cannot be handled safely."""


def legacy_family_from_plan(legacy_plan: Mapping[str, Any]) -> str:
    """Read, never recompute, the persisted legacy family outcome."""

    if not isinstance(legacy_plan, Mapping):
        return ""
    family_result = legacy_plan.get("family_result")
    if isinstance(family_result, Mapping):
        value = str(family_result.get("family") or "").strip()
        if value:
            return value
    classification = legacy_plan.get("classification")
    if isinstance(classification, Mapping):
        value = str(classification.get("family") or "").strip()
        if value:
            return value
    return ""


def compare_with_persisted_legacy(
    record: TriageOwnershipRecord,
    legacy_plan: Mapping[str, Any],
    *,
    utcnow: Callable[[], datetime] | None = None,
) -> TriageShadowComparison:
    """Compare without making a second classification call."""

    now_fn = utcnow or (lambda: datetime.now(timezone.utc))
    now = now_fn()
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("utcnow provider must return timezone-aware datetime")

    legacy_family = legacy_family_from_plan(legacy_plan)
    if not legacy_family:
        comparison = "legacy_missing"
    elif legacy_family == record.family:
        comparison = "match"
    else:
        comparison = "mismatch"

    migration_acceptable = (
        comparison == "match" if record.migrated_family else True
    )
    return TriageShadowComparison(
        request_id=record.request_id,
        triage_owner_ref=TriageOwner.record_ref(record),
        triage_family=record.family,
        legacy_family=legacy_family,
        comparison=comparison,
        migrated_family=record.migrated_family,
        migration_acceptable=migration_acceptable,
        routing_action=record.routing_action,
        compared_at=now,
    )


class TriageShadowStore:
    """Persist D2 trace under a separate v13 directory only."""

    def __init__(
        self,
        base_dir: str | Path = DEFAULT_TRACE_ROOT,
        *,
        writer_factory: Any = AtomicJsonWriter,
    ) -> None:
        self.base_dir = Path(base_dir)
        self.writer_factory = writer_factory

    def request_v13_dir(self, request_id: str) -> Path:
        request_id = validate_request_id(request_id)
        request_dir = self.base_dir / request_id
        v13_dir = request_dir / "v13"
        if request_dir.exists() and request_dir.is_symlink():
            raise TriageShadowError("request directory must not be a symlink")
        if v13_dir.exists() and v13_dir.is_symlink():
            raise TriageShadowError("v13 trace directory must not be a symlink")
        return v13_dir

    def persist(
        self,
        record: TriageOwnershipRecord,
        comparison: TriageShadowComparison,
    ) -> dict[str, Path]:
        if comparison.request_id != record.request_id:
            raise TriageShadowError("record/comparison request_id mismatch")
        directory = self.request_v13_dir(record.request_id)
        writer = self.writer_factory(directory)
        payloads = {
            "triage_owner.json": record,
            "triage_shadow_comparison.json": comparison,
        }
        try:
            return writer.write_many(payloads)
        except AtomicWriteError as exc:
            raise TriageShadowError("v13 D2 trace persistence failed") from exc

    def load(self, request_id: str) -> dict[str, Any]:
        directory = self.request_v13_dir(request_id)
        writer = self.writer_factory(directory)
        try:
            return {
                "triage_owner.json": writer.read_json("triage_owner.json"),
                "triage_shadow_comparison.json": writer.read_json(
                    "triage_shadow_comparison.json"
                ),
            }
        except AtomicWriteError as exc:
            raise TriageShadowError("v13 D2 trace load failed") from exc
