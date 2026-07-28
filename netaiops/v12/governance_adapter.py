"""Allowlisted Governance summary adapter for v12 Agent Trace data."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Mapping

from pydantic import AwareDatetime, Field, field_validator

from .api import AgentTraceReadService, DEFAULT_AGENT_TRACE_ROOT
from .atomic_writer import AtomicJsonWriter, AtomicWriteError
from .contracts import StrictContractModel
from .redaction import redact_for_persistence
from .schema_validator import parse_contract_ref, validate_request_id


DEFAULT_AGENT_GOVERNANCE_ROOT = Path(
    "/opt/netaiops-webhook/data/governance/agent_traces"
)


class GovernanceTraceSummary(StrictContractModel):
    schema_version: Literal["v12.1"] = "v12.1"
    record_type: Literal["agent_trace_summary"] = (
        "agent_trace_summary"
    )
    request_id: str
    generated_at: AwareDatetime
    final_state: str
    fallback_to_legacy: bool
    stop_reason: str | None = None
    elapsed_ms: int = Field(ge=0)
    agent_statuses: list[Mapping[str, Any]] = Field(
        default_factory=list
    )
    missing_evidence_types: list[str] = Field(
        default_factory=list
    )
    judge_result: Mapping[str, Any] = Field(default_factory=dict)
    rca_confidence: Mapping[str, Any] = Field(default_factory=dict)
    artifact_refs: list[str] = Field(default_factory=list)
    error_categories: list[str] = Field(default_factory=list)
    full_logs_copied: Literal[False] = False
    full_device_output_copied: Literal[False] = False
    full_metrics_copied: Literal[False] = False
    raw_payload_copied: Literal[False] = False
    external_calls: Mapping[str, bool] = Field(default_factory=dict)

    @field_validator("request_id")
    @classmethod
    def _request_id_is_safe(cls, value: str) -> str:
        return validate_request_id(value)

    @field_validator("artifact_refs")
    @classmethod
    def _refs_match_request(
        cls,
        value: list[str],
        info: Any,
    ) -> list[str]:
        request_id = str(info.data.get("request_id") or "")
        output = sorted(set(value))
        for reference in output:
            parsed = parse_contract_ref(reference)
            if parsed["request_id"] != request_id:
                raise ValueError(
                    "Governance artifact_ref request_id mismatch"
                )
        return output


class AgentTraceGovernanceAdapterError(RuntimeError):
    """Raised for invalid Governance Agent Trace summaries."""


class AgentTraceGovernanceAdapter:
    """Persist only approved Agent Trace summary fields."""

    def __init__(
        self,
        *,
        trace_service: AgentTraceReadService | None = None,
        governance_root: str | Path = DEFAULT_AGENT_GOVERNANCE_ROOT,
        writer_factory: Any = AtomicJsonWriter,
        utcnow: Any | None = None,
    ) -> None:
        self.trace_service = trace_service or AgentTraceReadService(
            DEFAULT_AGENT_TRACE_ROOT
        )
        self.governance_root = Path(governance_root)
        self.writer_factory = writer_factory
        self._utcnow = utcnow or (
            lambda: datetime.now(timezone.utc)
        )

    @staticmethod
    def external_call_policy() -> dict[str, bool]:
        return {
            "glm": False,
            "prometheus_mcp": False,
            "netmiko_mcp": False,
            "evidence_mcp": False,
            "ops_es_api": False,
            "notification": False,
        }

    def build_for_request(
        self,
        request_id: str,
    ) -> GovernanceTraceSummary:
        return self.build_summary(
            self.trace_service.get_trace(request_id)
        )

    def build_summary(
        self,
        detail: Mapping[str, Any],
    ) -> GovernanceTraceSummary:
        request_id = validate_request_id(
            str(detail.get("request_id") or "")
        )
        agent_statuses = []
        error_categories: set[str] = set()
        for item in detail.get("agent_runs", []):
            if not isinstance(item, Mapping):
                continue
            agent_statuses.append(
                {
                    "agent_name": str(item.get("agent_name") or ""),
                    "status": str(item.get("status") or ""),
                    "duration_ms": self._safe_int(
                        item.get("duration_ms")
                    ),
                }
            )
            for category in item.get("error_categories", []):
                error_categories.add(str(category))

        missing: set[str] = set()
        judge = detail.get("judge")
        judge_summary: dict[str, Any] = {}
        if isinstance(judge, Mapping):
            required = self._string_list(
                judge.get("missing_required_sources")
            )
            optional = self._string_list(
                judge.get("missing_optional_sources")
            )
            missing.update(required)
            missing.update(optional)
            judge_summary = {
                "status": str(judge.get("status") or ""),
                "rca_allowed": bool(
                    judge.get("rca_allowed", False)
                ),
                "confidence_cap": self._safe_float(
                    judge.get("confidence_cap")
                ),
                "conflict_count": len(
                    judge.get("conflicts")
                    if isinstance(judge.get("conflicts"), list)
                    else []
                ),
            }

        rca = detail.get("rca")
        confidences: list[float] = []
        if isinstance(rca, Mapping):
            missing.update(
                self._string_list(rca.get("missing_evidence"))
            )
            for candidate in rca.get("candidates", []):
                if not isinstance(candidate, Mapping):
                    continue
                confidences.append(
                    self._safe_float(candidate.get("confidence"))
                )
                missing.update(
                    self._string_list(
                        candidate.get("missing_evidence")
                    )
                )
        rca_confidence = {
            "status": (
                str(rca.get("status") or "")
                if isinstance(rca, Mapping)
                else "not_persisted"
            ),
            "candidate_count": len(confidences),
            "maximum": max(confidences) if confidences else 0.0,
            "average": (
                sum(confidences) / len(confidences)
                if confidences
                else 0.0
            ),
        }

        artifact_refs = sorted(
            set(self._string_list(detail.get("artifact_refs")))
        )
        for reference in artifact_refs:
            parsed = parse_contract_ref(reference)
            if parsed["request_id"] != request_id:
                raise AgentTraceGovernanceAdapterError(
                    "artifact_ref request_id mismatch"
                )

        generated_at = self._utcnow()
        if (
            generated_at.tzinfo is None
            or generated_at.utcoffset() is None
        ):
            raise AgentTraceGovernanceAdapterError(
                "utcnow must return an aware datetime"
            )

        payload = {
            "schema_version": "v12.1",
            "record_type": "agent_trace_summary",
            "request_id": request_id,
            "generated_at": generated_at,
            "final_state": str(detail.get("final_state") or ""),
            "fallback_to_legacy": bool(
                detail.get("fallback_to_legacy", False)
            ),
            "stop_reason": detail.get("stop_reason"),
            "elapsed_ms": self._safe_int(detail.get("elapsed_ms")),
            "agent_statuses": agent_statuses,
            "missing_evidence_types": sorted(missing),
            "judge_result": judge_summary,
            "rca_confidence": rca_confidence,
            "artifact_refs": artifact_refs,
            "error_categories": sorted(error_categories),
            "full_logs_copied": False,
            "full_device_output_copied": False,
            "full_metrics_copied": False,
            "raw_payload_copied": False,
            "external_calls": self.external_call_policy(),
        }
        return GovernanceTraceSummary.model_validate(
            redact_for_persistence(payload)
        )

    def persist_for_request(self, request_id: str) -> dict[str, Any]:
        return self.persist(self.build_for_request(request_id))

    def persist(
        self,
        summary: GovernanceTraceSummary,
    ) -> dict[str, Any]:
        request_id = validate_request_id(summary.request_id)
        if self.governance_root.is_symlink():
            raise AgentTraceGovernanceAdapterError(
                "Governance Agent Trace root must not be a symlink"
            )
        writer = self.writer_factory(self.governance_root)
        try:
            path = writer.write_json(
                f"{request_id}.json",
                summary,
            )
        except AtomicWriteError as exc:
            raise AgentTraceGovernanceAdapterError(
                "Governance Agent Trace persistence failed"
            ) from exc
        return {
            "ok": True,
            "status": "completed",
            "schema_version": "v12.1",
            "request_id": request_id,
            "path": str(path),
            "external_calls": self.external_call_policy(),
        }

    def load(self, request_id: str) -> GovernanceTraceSummary:
        safe_id = validate_request_id(request_id)
        writer = self.writer_factory(self.governance_root)
        try:
            payload = writer.read_json(f"{safe_id}.json")
        except AtomicWriteError as exc:
            raise AgentTraceGovernanceAdapterError(
                "Governance Agent Trace is unreadable"
            ) from exc
        return GovernanceTraceSummary.model_validate(payload)

    def persist_for_request_safe(
        self,
        request_id: str,
    ) -> dict[str, Any]:
        try:
            return self.persist_for_request(request_id)
        except Exception as exc:
            return {
                "ok": False,
                "status": "failed",
                "schema_version": "v12.1",
                "request_id": str(request_id),
                "error_category": type(exc).__name__,
                "external_calls": self.external_call_policy(),
            }

    @staticmethod
    def _string_list(value: Any) -> list[str]:
        if not isinstance(value, (list, tuple)):
            return []
        return [str(item) for item in value if item is not None]

    @staticmethod
    def _safe_int(value: Any) -> int:
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _safe_float(value: Any) -> float:
        try:
            return float(value or 0.0)
        except (TypeError, ValueError):
            return 0.0


__all__ = [
    "AgentTraceGovernanceAdapter",
    "AgentTraceGovernanceAdapterError",
    "DEFAULT_AGENT_GOVERNANCE_ROOT",
    "GovernanceTraceSummary",
]
