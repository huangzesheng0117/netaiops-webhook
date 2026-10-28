"""Adapt persisted v14 Logs artifacts to the frozen v12 EvidenceEnvelope."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from netaiops.v12.contracts import ContractNotice, EvidenceEnvelope
from netaiops.v12.status import EvidenceSource, EvidenceStatus
from .logs_artifact_store import LogsArtifactStore
from .runtime_config import LogsRuntimeSettings


def _now() -> datetime: return datetime.now(timezone.utc)


def build_v12_logs_envelope(*, request_id: str, project_root: str | Path,
                            settings: LogsRuntimeSettings) -> EvidenceEnvelope | None:
    if not (
        settings.enabled
        and settings.include_in_analysis
        and settings.include_in_review
    ):
        return None
    store = LogsArtifactStore(Path(project_root) / "data/evidence_hub")
    index = store.read_request_index(request_id)
    if not isinstance(index, Mapping): return None
    data = index.get("data") if isinstance(index.get("data"), Mapping) else {}
    jobs = data.get("jobs") if isinstance(data.get("jobs"), list) else []
    if not jobs: return None
    statuses = [str(j.get("evidence_status") or "") for j in jobs if isinstance(j, Mapping)]
    windows = [bool(j.get("window_complete")) for j in jobs if isinstance(j, Mapping)]
    states = [str(j.get("collection_state") or "") for j in jobs if isinstance(j, Mapping)]
    refs = [str(j.get("evidence_ref")) for j in jobs if isinstance(j, Mapping) and j.get("evidence_ref")]
    usable = {"success", "no_data", "partial"}
    unavailable = {"failed", "not_available"}
    observed = set(statuses)
    if statuses and observed <= {"success"}:
        status = EvidenceStatus.SUCCESS
    elif statuses and observed <= {"no_data"}:
        status = EvidenceStatus.NO_DATA
    elif observed & usable and (observed & unavailable or "partial" in observed or len(observed) > 1):
        # Preserve usable evidence from the successful/no_data jobs while
        # accurately declaring the multi-job request only partially covered.
        status = EvidenceStatus.PARTIAL
    elif statuses and observed <= {"failed"}:
        status = EvidenceStatus.FAILED
    elif statuses and observed <= {"not_available"}:
        status = EvidenceStatus.NOT_AVAILABLE
    elif statuses:
        status = EvidenceStatus.PARTIAL
    else:
        status = EvidenceStatus.NOT_AVAILABLE
    collected_values: list[datetime] = []
    for item in jobs:
        if not isinstance(item, Mapping): continue
        raw = item.get("query_executed_at")
        if isinstance(raw, str):
            try:
                parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                if parsed.tzinfo: collected_values.append(parsed)
            except ValueError: pass
    collected_at = max(collected_values) if collected_values else _now()
    reason = "logs_artifact_not_available" if status == EvidenceStatus.NOT_AVAILABLE else None
    notices: list[ContractNotice] = []
    if status == EvidenceStatus.NO_DATA:
        notices.append(ContractNotice(code="logs_no_data_not_normal", message="No matching logs is not evidence of normal health.", stage="logs_evidence", retryable=False))
    facts = {
        "collection_state": "complete" if jobs and all(windows) else ("provisional" if "provisional" in states else "partial"),
        "window_complete": bool(jobs) and all(windows),
        "job_count": len(jobs),
        "matched_total": sum(int(j.get("matched_total") or 0) for j in jobs if isinstance(j, Mapping)),
        "analyzed_total": sum(int(j.get("analyzed_total") or 0) for j in jobs if isinstance(j, Mapping)),
        "result_truncated": any(bool(j.get("result_truncated")) for j in jobs if isinstance(j, Mapping)),
        "no_data_interpreted_as_normal": False,
        "include_in_rca": settings.include_in_rca,
        "r1_stage": settings.r1_stage,
        "jobs": [{k: j.get(k) for k in ("job_id", "profile_id", "artifact_phase", "collection_state", "window_complete", "matched_total", "analyzed_total", "evidence_ref")} for j in jobs if isinstance(j, Mapping)],
    }
    scope = {"source": "v14_logs_evidence", "request_id": request_id, "ingestion_grace_seconds": settings.ingestion_grace_seconds}
    evidence_refs = refs if status in {EvidenceStatus.SUCCESS, EvidenceStatus.PARTIAL, EvidenceStatus.NO_DATA} else []
    return EvidenceEnvelope(schema_version="v12.1", request_id=request_id, source=EvidenceSource.LOGS,
        evidence_kind="evidence", status=status, summary=f"Logs Evidence jobs={len(jobs)} state={facts['collection_state']}",
        facts=facts, scope=scope, warnings=notices, evidence_refs=evidence_refs,
        collected_at=collected_at, reason=reason)
