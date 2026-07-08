"""Offline replay engine for NetAIOps Webhook v11 governance.

Replay is deterministic and local.  It reads historical request artifacts,
rebuilds Incident Memory, Learning Signals, and draft Proposals, then compares
compact before/after snapshots.  It never calls real GLM, Prometheus, devices,
or notification endpoints and never writes production Governance data.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Sequence

from .artifact_reader import RequestArtifactBundle, read_request_artifacts
from .contracts import DEFAULT_EXTERNAL_CALL_POLICY, ExternalCallPolicy, ReplayMode
from .memory_builder import build_incident_memory
from .proposal_builder import (
    ProposalBuilder,
    ProposalBuilderError,
    ProposalNotEligibleError,
    proposal_safety_summary,
)
from .replay_compare import build_replay_comparison
from .schemas import (
    ArtifactReference,
    IncidentMemoryRecord,
    LearningSignalRecord,
    ProposalRecord,
    ReplayRecord,
)
from .signal_detector import detect_learning_signals

REPLAY_LOGIC_VERSION = "11.0.0-offline-replay-v1"


class ReplayEngineError(RuntimeError):
    """Raised when an offline replay cannot be built safely."""


@dataclass(frozen=True)
class ReplayExecution:
    record: ReplayRecord
    memory: IncidentMemoryRecord
    signals: tuple[LearningSignalRecord, ...]
    proposals: tuple[ProposalRecord, ...]

    def summary(self) -> dict[str, Any]:
        return {
            "replay_id": self.record.replay_id,
            "request_id": self.record.request_id,
            "mode": _enum_value(self.record.mode),
            "signal_count": len(self.signals),
            "proposal_count": len(self.proposals),
            "quality_outcome": self.record.quality_delta.get("outcome", ""),
            "quality_score_delta": self.record.quality_delta.get("score_delta", 0),
            "safety_regression": bool(self.record.safety_delta.get("regression", False)),
            "external_calls": dict(self.record.external_calls),
            "errors": list(self.record.errors),
            "warnings": list(self.record.warnings),
        }


def _enum_value(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value


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


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _deep_merge(base: Mapping[str, Any], patch: Mapping[str, Any]) -> dict[str, Any]:
    result = {str(key): _jsonable(value) for key, value in base.items()}
    for key, value in patch.items():
        key = str(key)
        if isinstance(value, Mapping) and isinstance(result.get(key), Mapping):
            result[key] = _deep_merge(_mapping(result[key]), value)
        else:
            result[key] = _jsonable(value)
    return result


def _external_call_map(policy: ExternalCallPolicy) -> dict[str, bool]:
    return {
        "glm": bool(policy.real_glm),
        "prometheus": bool(policy.real_prometheus),
        "device": bool(policy.real_device),
        "notification": bool(policy.real_notification),
        "production_write": bool(policy.write_production_data),
    }


def _plan_summary(plan: Mapping[str, Any]) -> dict[str, Any]:
    classification = _mapping(plan.get("classification"))
    playbook = _mapping(plan.get("playbook"))
    policy = _mapping(plan.get("policy_result"))
    selected_playbook = {
        "matched": bool(playbook.get("matched", False)),
        "id": str(
            playbook.get("playbook_id")
            or playbook.get("selected_playbook_id")
            or plan.get("selected_playbook_id")
            or ""
        ),
        "file": str(
            playbook.get("playbook_file")
            or playbook.get("selected_playbook_file")
            or plan.get("selected_playbook_file")
            or ""
        ),
    }
    return {
        "classification": {
            "family": str(classification.get("family") or ""),
            "match_reason": str(classification.get("match_reason") or ""),
        },
        "selected_playbook": selected_playbook,
        "policy": {
            "status": str(
                policy.get("status")
                or policy.get("decision")
                or plan.get("plan_status")
                or ""
            ),
            "readonly_only": bool(plan.get("readonly_only", False)),
            "blocked_reasons": list(policy.get("reasons") or policy.get("blocked_reasons") or []),
        },
    }


def _evidence_status(memory: IncidentMemoryRecord) -> dict[str, str]:
    return {str(key): str(_enum_value(value)) for key, value in memory.evidence_status.items()}


def _proposal_view(proposals: Sequence[ProposalRecord]) -> list[dict[str, Any]]:
    return [
        {
            "proposal_id": item.proposal_id,
            "signal_id": item.signal_id,
            "signal_type": item.signal_type,
            "status": str(_enum_value(item.status)),
            "auto_apply": bool(item.risk.get("auto_apply", False)),
        }
        for item in proposals
    ]


def _snapshot(
    memory: IncidentMemoryRecord,
    *,
    plan: Mapping[str, Any],
    signals: Sequence[LearningSignalRecord],
    proposals: Sequence[ProposalRecord],
    external_calls: Mapping[str, bool],
) -> dict[str, Any]:
    plan_view = _plan_summary(plan)
    family = plan_view["classification"].get("family") or memory.family
    readonly_only = bool(
        plan_view["policy"].get("readonly_only")
        or memory.command_summary.get("readonly_only", False)
    )
    return {
        "classification": {
            **plan_view["classification"],
            "family": family,
        },
        "selected_playbook": plan_view["selected_playbook"],
        "policy": plan_view["policy"],
        "evidence_status": _evidence_status(memory),
        "command_summary": _jsonable(memory.command_summary),
        "review_summary": _jsonable(memory.review_summary),
        "notification_summary": _jsonable(memory.notification_result),
        "quality_flags": sorted(set(memory.quality_flags)),
        "learning_signals": [
            {
                "signal_id": item.signal_id,
                "signal_type": item.signal_type,
                "severity": str(_enum_value(item.severity)),
                "proposal_eligible": item.proposal_eligible,
            }
            for item in signals
        ],
        "proposals": _proposal_view(proposals),
        "safety": {
            "readonly_only": readonly_only,
            "external_calls": dict(external_calls),
            "proposal_auto_apply_count": sum(
                1 for item in proposals if bool(item.risk.get("auto_apply", False))
            ),
        },
    }


def _dedupe_refs(values: Sequence[ArtifactReference]) -> list[ArtifactReference]:
    result: list[ArtifactReference] = []
    seen: set[tuple[str, str, str]] = set()
    for ref in values:
        key = (ref.kind, ref.path, ref.sha256)
        if key in seen:
            continue
        result.append(ref)
        seen.add(key)
    return result


def _candidate_refs(
    memory: IncidentMemoryRecord,
    signals: Sequence[LearningSignalRecord],
    proposals: Sequence[ProposalRecord],
) -> list[ArtifactReference]:
    refs: list[ArtifactReference] = []
    for signal in signals:
        refs.extend(signal.evidence_refs)
    for proposal in proposals:
        refs.extend(proposal.evidence_refs)
    if not refs:
        refs.extend(memory.artifact_refs)
    return _dedupe_refs(refs)


def _replay_id(
    request_id: str,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
) -> str:
    material = json.dumps(
        {
            "version": REPLAY_LOGIC_VERSION,
            "request_id": request_id,
            "before": _jsonable(before),
            "after": _jsonable(after),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"replay_{hashlib.sha256(material).hexdigest()[:24]}"


def _aware_utc(value: datetime | None) -> datetime:
    result = value or datetime.now(timezone.utc)
    if result.tzinfo is None or result.utcoffset() is None:
        raise ReplayEngineError("generated_at must include timezone information")
    return result.astimezone(timezone.utc)


def build_offline_replay(
    memory: IncidentMemoryRecord | Mapping[str, Any],
    *,
    plan: Mapping[str, Any] | None = None,
    candidate_patch: Mapping[str, Any] | None = None,
    generated_at: datetime | None = None,
    external_policy: ExternalCallPolicy = DEFAULT_EXTERNAL_CALL_POLICY,
    inherited_errors: Sequence[str] = (),
    inherited_warnings: Sequence[str] = (),
) -> ReplayExecution:
    """Build one side-effect-free offline Replay from an Incident Memory."""

    external_policy.assert_offline()
    external_calls = _external_call_map(external_policy)
    if any(external_calls.values()):
        raise ReplayEngineError("offline replay external call policy must be all false")

    record = (
        memory
        if isinstance(memory, IncidentMemoryRecord)
        else IncidentMemoryRecord.model_validate(dict(memory))
    )
    timestamp = _aware_utc(generated_at)
    signals = detect_learning_signals(record, generated_at=timestamp)

    builder = ProposalBuilder()
    proposals: list[ProposalRecord] = []
    errors = [str(item) for item in inherited_errors if str(item)]
    for signal in signals:
        if not signal.proposal_eligible:
            continue
        try:
            proposals.append(builder.build_for_memory(signal, record, generated_at=timestamp))
        except ProposalNotEligibleError:
            continue
        except ProposalBuilderError as exc:
            errors.append(f"proposal_build_failed:{signal.signal_type}:{exc}")

    plan_payload = dict(plan or {})
    before = _snapshot(
        record,
        plan=plan_payload,
        signals=(),
        proposals=(),
        external_calls=external_calls,
    )
    after = _snapshot(
        record,
        plan=plan_payload,
        signals=signals,
        proposals=proposals,
        external_calls=external_calls,
    )
    if candidate_patch:
        after = _deep_merge(after, candidate_patch)

    comparison = build_replay_comparison(before, after)
    warnings = [str(item) for item in inherited_warnings if str(item)]
    if record.evidence_status.get("logs") is not None:
        logs_status = str(_enum_value(record.evidence_status.get("logs")))
        if logs_status == "not_available":
            warnings.append("logs_evidence_not_available:elasticsearch_query_interface_pending")

    replay_record = ReplayRecord(
        replay_id=_replay_id(record.request_id, before, after),
        request_id=record.request_id,
        mode=ReplayMode.OFFLINE,
        created_at=timestamp,
        baseline_refs=list(record.artifact_refs),
        candidate_refs=_candidate_refs(record, signals, proposals),
        before=before,
        after=after,
        diff=comparison["diff"],
        quality_delta=comparison["quality_delta"],
        safety_delta=comparison["safety_delta"],
        external_calls=external_calls,
        errors=errors,
        warnings=sorted(set(warnings)),
    )
    if any(replay_record.external_calls.values()):
        raise ReplayEngineError("offline ReplayRecord contains enabled external calls")
    if replay_record.safety_delta.get("regression"):
        replay_record.warnings.append("candidate_safety_regression_detected")

    return ReplayExecution(
        record=ReplayRecord.model_validate(replay_record.to_payload()),
        memory=record,
        signals=tuple(signals),
        proposals=tuple(proposals),
    )


def run_offline_replay(
    project_root: str,
    request_id: str,
    *,
    candidate_patch: Mapping[str, Any] | None = None,
    generated_at: datetime | None = None,
    external_policy: ExternalCallPolicy = DEFAULT_EXTERNAL_CALL_POLICY,
) -> ReplayExecution:
    """Read historical artifacts and run the deterministic offline Replay."""

    bundle: RequestArtifactBundle = read_request_artifacts(project_root, request_id)
    memory = build_incident_memory(bundle, generated_at=generated_at)
    plan = bundle.get("plan")
    inherited_errors = [
        f"artifact_read_error:{item.get('kind', '')}:{item.get('error', '')}"
        for item in bundle.read_errors
    ]
    return build_offline_replay(
        memory,
        plan=plan,
        candidate_patch=candidate_patch,
        generated_at=generated_at,
        external_policy=external_policy,
        inherited_errors=inherited_errors,
        inherited_warnings=bundle.warnings,
    )


def replay_safety_summary(execution: ReplayExecution) -> dict[str, Any]:
    proposal_safety = [proposal_safety_summary(item) for item in execution.proposals]
    enabled_calls = sorted(
        key for key, value in execution.record.external_calls.items() if bool(value)
    )
    return {
        "safe": not enabled_calls
        and not execution.record.safety_delta.get("regression", False)
        and all(item.get("safe", False) for item in proposal_safety),
        "enabled_external_calls": enabled_calls,
        "safety_regression": bool(execution.record.safety_delta.get("regression", False)),
        "proposal_safety": proposal_safety,
        "baseline_ref_count": len(execution.record.baseline_refs),
        "candidate_ref_count": len(execution.record.candidate_refs),
    }


__all__ = [
    "REPLAY_LOGIC_VERSION",
    "ReplayEngineError",
    "ReplayExecution",
    "build_offline_replay",
    "replay_safety_summary",
    "run_offline_replay",
]
