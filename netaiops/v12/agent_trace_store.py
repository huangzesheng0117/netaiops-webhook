"""Persistent v12 Evidence Bundle and Agent Trace Store."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .atomic_writer import AtomicJsonWriter, AtomicWriteError
from .contracts import EvidenceBundle
from .evidence_bundle import BundleArtifacts
from .execution_context import OrchestrationResult
from .redaction import redact_for_persistence
from .schema_validator import (
    parse_contract_ref,
    validate_request_id,
)


DEFAULT_TRACE_ROOT = Path(
    "/opt/netaiops-webhook/data/evidence_hub/requests"
)
_CORE_FILES = (
    "unified_event.json",
    "evidence_plan.json",
    "agent_runs.json",
    "evidence_bundle.json",
)


class AgentTraceStoreError(OSError):
    """Raised when v12 trace artifacts cannot be persisted safely."""


@dataclass(frozen=True, slots=True)
class StoredTrace:
    request_id: str
    directory: Path
    files: Mapping[str, Path]
    governance_summary: Mapping[str, Any]


class AgentTraceStore:
    """Write v12 trace files without touching v10/v11 request artifacts."""

    def __init__(
        self,
        base_dir: str | Path = DEFAULT_TRACE_ROOT,
        *,
        writer_factory: Any = AtomicJsonWriter,
    ) -> None:
        self.base_dir = Path(base_dir)
        self.writer_factory = writer_factory

    def request_v12_dir(self, request_id: str) -> Path:
        request_id = validate_request_id(request_id)
        request_dir = self.base_dir / request_id
        v12_dir = request_dir / "v12"
        if request_dir.exists() and request_dir.is_symlink():
            raise AgentTraceStoreError(
                "request directory must not be a symlink"
            )
        if v12_dir.exists() and v12_dir.is_symlink():
            raise AgentTraceStoreError(
                "v12 trace directory must not be a symlink"
            )
        return v12_dir

    def persist(
        self,
        result: OrchestrationResult,
        artifacts: BundleArtifacts,
    ) -> StoredTrace:
        request_id = validate_request_id(result.request_id)
        if artifacts.evidence_bundle.request_id != request_id:
            raise AgentTraceStoreError(
                "EvidenceBundle request_id mismatch"
            )
        if artifacts.unified_event.request_id != request_id:
            raise AgentTraceStoreError(
                "UnifiedAlertEvent request_id mismatch"
            )
        if artifacts.evidence_plan.request_id != request_id:
            raise AgentTraceStoreError(
                "EvidencePlan request_id mismatch"
            )

        directory = self.request_v12_dir(request_id)
        writer = self.writer_factory(directory)
        trace = self._agent_runs_payload(result)
        payloads = {
            "unified_event.json": artifacts.unified_event,
            "evidence_plan.json": artifacts.evidence_plan,
            "agent_runs.json": trace,
            "evidence_bundle.json": artifacts.evidence_bundle,
        }
        try:
            files = writer.write_many(payloads)
        except AtomicWriteError as exc:
            raise AgentTraceStoreError(
                "v12 trace persistence failed"
            ) from exc

        return StoredTrace(
            request_id=request_id,
            directory=directory,
            files=files,
            governance_summary=self.governance_summary(
                result,
                artifacts.evidence_bundle,
            ),
        )

    def load_core(self, request_id: str) -> dict[str, Any]:
        directory = self.request_v12_dir(request_id)
        writer = self.writer_factory(directory)
        return {
            name: writer.read_json(name)
            for name in _CORE_FILES
        }

    @staticmethod
    def _agent_runs_payload(
        result: OrchestrationResult,
    ) -> dict[str, Any]:
        return {
            "schema_version": "v12.1",
            "request_id": result.request_id,
            "final_state": result.final_state.value,
            "state_history": [
                state.value for state in result.state_history
            ],
            "fallback_to_legacy": result.fallback_to_legacy,
            "stop_reason": result.stop_reason,
            "elapsed_ms": result.elapsed_ms,
            "agent_runs": [
                run.model_dump(mode="json", exclude_none=False)
                for run in result.agent_runs
            ],
        }

    @staticmethod
    def governance_summary(
        result: OrchestrationResult,
        bundle: EvidenceBundle,
    ) -> dict[str, Any]:
        if bundle.request_id != result.request_id:
            raise AgentTraceStoreError(
                "Governance summary request_id mismatch"
            )
        statuses = Counter(
            run.status.value for run in result.agent_runs
        )
        evidence_refs: list[str] = []
        for envelope in (
            bundle.evidence.metrics,
            bundle.evidence.device,
            bundle.evidence.logs,
        ):
            evidence_refs.extend(envelope.evidence_refs)
        for reference in evidence_refs:
            parsed = parse_contract_ref(reference)
            if parsed["request_id"] != result.request_id:
                raise AgentTraceStoreError(
                    "Governance evidence_ref request_id mismatch"
                )
        summary = {
            "schema_version": "v12.1",
            "request_id": result.request_id,
            "final_state": result.final_state.value,
            "fallback_to_legacy": result.fallback_to_legacy,
            "stop_reason": result.stop_reason,
            "elapsed_ms": result.elapsed_ms,
            "bundle_status": bundle.bundle_status.value,
            "agent_status_counts": dict(sorted(statuses.items())),
            "event_ref": bundle.event_ref,
            "plan_ref": bundle.plan_ref,
            "evidence_refs": sorted(set(evidence_refs)),
            "full_facts_copied": False,
            "raw_payload_copied": False,
            "raw_device_output_copied": False,
            "full_logs_copied": False,
        }
        return redact_for_persistence(summary)
