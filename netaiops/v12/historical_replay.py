"""Offline v12 replay of sanitized historical Evidence Hub scenarios."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from .agents.notification_report_agent import NotificationReportAgent
from .agents.rca_agent import RCAAgent
from .contracts import (
    AlertObject,
    ContextEnvelope,
    DeviceIdentity,
    EvidenceBundle,
    EvidenceCollection,
    EvidenceEnvelope,
    EvidencePlan,
    EvidenceSourcePlan,
    RCAResult,
    UnifiedAlertEvent,
)
from .execution_context import AgentInvocation
from .judge_rules import evaluate_evidence
from .quality_gates import evaluate_quality_gates
from .rca_validator import bundle_evidence_refs
from .schema_validator import (
    build_contract_ref,
    build_evidence_ref,
    stable_json_dumps,
    validate_request_id,
)
from .state_machine import OrchestrationState
from .status import (
    AgentName,
    AgentStatus,
    AlertLifecycleStatus,
    AlertSource,
    EvidenceBundleStatus,
    EvidenceSource,
    EvidenceStatus,
    JudgeStatus,
)


REPLAY_SCHEMA_VERSION = "v12-historical-replay-1"
FIXTURE_SCHEMA_VERSION = "v12-historical-fixture-1"
MOCK_PROVIDER = "mock-historical-replay"


class HistoricalReplayError(ValueError):
    """Raised when a sanitized historical fixture is invalid."""


class FixtureMockRCAClient:
    """Strict offline Mock GLM used only by historical replay."""

    provider = MOCK_PROVIDER

    def __init__(self, response: Mapping[str, Any] | None) -> None:
        self.response = copy.deepcopy(response)
        self.calls = 0

    async def generate(self, prompt: str) -> Mapping[str, Any] | None:
        self.calls += 1
        return copy.deepcopy(self.response)


def load_fixture(path: str | Path) -> dict[str, Any]:
    value = Path(path)
    try:
        payload = json.loads(value.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HistoricalReplayError(
            f"fixture cannot be decoded: {value}"
        ) from exc
    if not isinstance(payload, dict):
        raise HistoricalReplayError(
            f"fixture root must be an object: {value}"
        )
    return payload


def discover_fixtures(root: str | Path) -> list[Path]:
    directory = Path(root)
    if directory.is_symlink():
        raise HistoricalReplayError(
            "fixture directory must not be a symlink"
        )
    if not directory.is_dir():
        raise HistoricalReplayError(
            f"fixture directory does not exist: {directory}"
        )
    files = [
        path
        for path in sorted(directory.glob("*.json"))
        if path.is_file() and not path.is_symlink()
    ]
    if not files:
        raise HistoricalReplayError(
            f"no historical replay fixtures found: {directory}"
        )
    return files


def _aware_datetime(value: Any, *, field: str) -> datetime:
    text = str(value or "")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise HistoricalReplayError(
            f"{field} must use ISO 8601"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise HistoricalReplayError(
            f"{field} must be timezone-aware"
        )
    return parsed


def _mapping(value: Any, *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise HistoricalReplayError(
            f"{field} must be an object"
        )
    return value


def _strings(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [str(item) for item in value if item is not None]


def _status(value: Any) -> EvidenceStatus:
    try:
        return EvidenceStatus(str(value))
    except ValueError as exc:
        raise HistoricalReplayError(
            f"unsupported evidence status: {value}"
        ) from exc


def _validate_fixture(payload: Mapping[str, Any]) -> None:
    if payload.get("schema_version") != FIXTURE_SCHEMA_VERSION:
        raise HistoricalReplayError(
            "fixture schema_version mismatch"
        )
    if payload.get("source_kind") != (
        "sanitized_historical_request_fixture"
    ):
        raise HistoricalReplayError(
            "fixture source_kind must be sanitized"
        )
    validate_request_id(str(payload.get("request_id") or ""))
    for field in (
        "scenario_id",
        "category",
        "request_id",
        "occurred_at",
        "event",
        "plan",
        "evidence",
        "legacy",
        "expected",
    ):
        if field not in payload:
            raise HistoricalReplayError(
                f"fixture field is missing: {field}"
            )
    evidence = _mapping(payload["evidence"], field="evidence")
    expected_sources = {
        "metrics",
        "device",
        "logs",
        "knowledge",
    }
    if set(evidence) != expected_sources:
        raise HistoricalReplayError(
            "fixture evidence must contain exactly "
            "metrics, device, logs, and knowledge"
        )


def _event(payload: Mapping[str, Any]) -> UnifiedAlertEvent:
    request_id = str(payload["request_id"])
    event = _mapping(payload["event"], field="event")
    occurred_at = _aware_datetime(
        payload["occurred_at"],
        field="occurred_at",
    )
    return UnifiedAlertEvent(
        schema_version="v12.1",
        request_id=request_id,
        event_id=str(event.get("event_id") or "event-o"),
        source=AlertSource.REPLAY,
        alert_status=AlertLifecycleStatus(
            str(event.get("alert_status") or "firing")
        ),
        alert_name=str(event.get("alert_name") or ""),
        occurred_at=occurred_at,
        received_at=occurred_at,
        device=DeviceIdentity(
            name=str(event.get("device_name") or ""),
            ip=str(event.get("device_ip") or ""),
            vendor=str(event.get("vendor") or "unknown"),
            platform=(
                str(event["platform"])
                if event.get("platform")
                else None
            ),
            site=(
                str(event["site"])
                if event.get("site")
                else None
            ),
        ),
        alert_object=AlertObject(
            kind=str(event.get("object_kind") or "device"),
            name=str(event.get("object_name") or "device"),
        ),
        labels={
            str(key): str(value)
            for key, value in _mapping(
                event.get("labels", {}),
                field="event.labels",
            ).items()
        },
        annotations={
            "summary": str(
                event.get("summary")
                or event.get("alert_name")
                or ""
            )
        },
        family=str(
            _mapping(payload["plan"], field="plan").get(
                "family"
            )
            or ""
        ),
        event_key=f"replay:{payload['scenario_id']}",
    )


def _plan(payload: Mapping[str, Any]) -> EvidencePlan:
    request_id = str(payload["request_id"])
    plan = _mapping(payload["plan"], field="plan")
    required = set(_strings(plan.get("required_sources")))
    unknown = required - {
        "metrics",
        "device",
        "logs",
        "knowledge",
    }
    if unknown:
        raise HistoricalReplayError(
            "unknown required sources: " + ", ".join(sorted(unknown))
        )
    sources = []
    for source in (
        EvidenceSource.METRICS,
        EvidenceSource.DEVICE,
        EvidenceSource.LOGS,
        EvidenceSource.KNOWLEDGE,
    ):
        constraints: dict[str, Any] = {
            "enabled": source
            in {
                EvidenceSource.METRICS,
                EvidenceSource.DEVICE,
            }
        }
        if source == EvidenceSource.LOGS:
            constraints.update(
                {
                    "enabled": False,
                    "reason": "logs_evidence_not_approved",
                    "dsl_generation_allowed": False,
                }
            )
        if source == EvidenceSource.KNOWLEDGE:
            constraints.update(
                {
                    "enabled": False,
                    "reason": "local_knowledge_base_not_built",
                    "evidence_kind": "context",
                }
            )
        sources.append(
            EvidenceSourcePlan(
                source=source,
                required=source.value in required,
                constraints=constraints,
                max_items=(
                    0
                    if source
                    in {
                        EvidenceSource.LOGS,
                        EvidenceSource.KNOWLEDGE,
                    }
                    else 1
                ),
            )
        )
    occurred_at = _aware_datetime(
        payload["occurred_at"],
        field="occurred_at",
    )
    return EvidencePlan(
        schema_version="v12.1",
        request_id=request_id,
        plan_ref=build_contract_ref(
            "plan",
            request_id,
            "evidence_plan",
            "plan-o",
        ),
        planner_mode="deterministic",
        family=str(plan.get("family") or ""),
        selected_playbook=(
            str(plan["selected_playbook"])
            if plan.get("selected_playbook")
            else None
        ),
        sources=sources,
        readonly_only=True,
        created_at=occurred_at,
    )


def _evidence_envelope(
    payload: Mapping[str, Any],
    source: EvidenceSource,
    occurred_at: datetime,
) -> EvidenceEnvelope:
    request_id = str(payload["request_id"])
    raw = _mapping(
        _mapping(payload["evidence"], field="evidence")[
            source.value
        ],
        field=f"evidence.{source.value}",
    )
    status = _status(raw.get("status"))
    refs = []
    if status in {
        EvidenceStatus.SUCCESS,
        EvidenceStatus.PARTIAL,
    }:
        refs = [
            build_evidence_ref(
                request_id,
                source.value,
                f"{source.value}-o-1",
            )
        ]
    reason = raw.get("reason")
    if status == EvidenceStatus.NOT_AVAILABLE and not reason:
        reason = (
            "logs_evidence_not_approved"
            if source == EvidenceSource.LOGS
            else f"{source.value}_not_available"
        )
    return EvidenceEnvelope(
        schema_version="v12.1",
        request_id=request_id,
        source=source,
        evidence_kind="evidence",
        status=status,
        summary=str(
            raw.get("summary")
            or f"{source.value} historical evidence"
        ),
        facts=dict(
            _mapping(raw.get("facts", {}), field="facts")
        ),
        scope=dict(
            _mapping(raw.get("scope", {}), field="scope")
        ),
        evidence_refs=refs,
        collected_at=occurred_at,
        reason=str(reason) if reason else None,
    )


def _knowledge_envelope(
    payload: Mapping[str, Any],
    occurred_at: datetime,
) -> ContextEnvelope:
    request_id = str(payload["request_id"])
    raw = _mapping(
        _mapping(payload["evidence"], field="evidence")[
            "knowledge"
        ],
        field="evidence.knowledge",
    )
    status = _status(raw.get("status"))
    if status == EvidenceStatus.SUCCESS:
        source_refs = [
            build_contract_ref(
                "context",
                request_id,
                "knowledge_context",
                "knowledge-o-1",
            )
        ]
        as_of = occurred_at
        reason = None
    else:
        source_refs = []
        as_of = None
        reason = str(
            raw.get("reason")
            or "local_knowledge_base_not_built"
        )
    return ContextEnvelope(
        schema_version="v12.1",
        request_id=request_id,
        source="knowledge",
        evidence_kind="context",
        status=status,
        reason=reason,
        context_facts=[],
        source_refs=source_refs,
        as_of=as_of,
        collected_at=occurred_at,
    )


def _bundle_status(
    plan: EvidencePlan,
    statuses: Mapping[EvidenceSource, EvidenceStatus],
) -> EvidenceBundleStatus:
    hard_missing = {
        EvidenceStatus.FAILED,
        EvidenceStatus.SKIPPED,
        EvidenceStatus.NOT_AVAILABLE,
    }
    required = {
        item.source
        for item in plan.sources
        if item.required
    }
    if any(
        statuses[source] in hard_missing
        for source in required
    ):
        return EvidenceBundleStatus.INSUFFICIENT
    if any(
        status != EvidenceStatus.SUCCESS
        for status in statuses.values()
    ):
        return EvidenceBundleStatus.PARTIAL
    return EvidenceBundleStatus.COMPLETE


def _bundle(
    payload: Mapping[str, Any],
    event: UnifiedAlertEvent,
    plan: EvidencePlan,
) -> EvidenceBundle:
    occurred_at = _aware_datetime(
        payload["occurred_at"],
        field="occurred_at",
    )
    metrics = _evidence_envelope(
        payload,
        EvidenceSource.METRICS,
        occurred_at,
    )
    device = _evidence_envelope(
        payload,
        EvidenceSource.DEVICE,
        occurred_at,
    )
    logs = _evidence_envelope(
        payload,
        EvidenceSource.LOGS,
        occurred_at,
    )
    knowledge = _knowledge_envelope(payload, occurred_at)
    statuses = {
        EvidenceSource.METRICS: metrics.status,
        EvidenceSource.DEVICE: device.status,
        EvidenceSource.LOGS: logs.status,
        EvidenceSource.KNOWLEDGE: knowledge.status,
    }
    event_ref = build_contract_ref(
        "event",
        event.request_id,
        "unified_alert",
        "event-o",
    )
    return EvidenceBundle(
        schema_version="v12.1",
        request_id=event.request_id,
        event_ref=event_ref,
        plan_ref=plan.plan_ref,
        evidence=EvidenceCollection(
            metrics=metrics,
            device=device,
            logs=logs,
            knowledge=knowledge,
        ),
        bundle_status=_bundle_status(plan, statuses),
        built_at=occurred_at,
    )


def _source_refs(bundle: EvidenceBundle) -> dict[str, list[str]]:
    return {
        "metrics": list(bundle.evidence.metrics.evidence_refs),
        "device": list(bundle.evidence.device.evidence_refs),
        "logs": list(bundle.evidence.logs.evidence_refs),
        "knowledge": list(bundle.evidence.knowledge.source_refs),
    }


def _fixture_rca_response(
    payload: Mapping[str, Any],
    bundle: EvidenceBundle,
) -> Mapping[str, Any] | None:
    raw = payload.get("rca")
    if raw is None:
        return None
    rca = _mapping(raw, field="rca")
    refs = _source_refs(bundle)
    supporting = []
    for source in _strings(rca.get("supporting_sources")):
        supporting.extend(refs.get(source, []))
    contradicting = []
    for source in _strings(rca.get("contradicting_sources")):
        contradicting.extend(refs.get(source, []))
    return {
        "candidates": [
            {
                "statement": str(rca.get("statement") or ""),
                "confidence": float(rca.get("confidence") or 0.0),
                "supporting_evidence_refs": sorted(
                    set(supporting)
                ),
                "contradicting_evidence_refs": sorted(
                    set(contradicting)
                ),
                "missing_evidence": _strings(
                    rca.get("missing_evidence")
                ),
                "uncertainties": _strings(
                    rca.get("uncertainties")
                ),
                "scope": dict(
                    _mapping(rca.get("scope", {}), field="rca.scope")
                ),
            }
        ],
        "missing_evidence": _strings(
            rca.get("missing_evidence")
        ),
        "uncertainties": _strings(
            rca.get("uncertainties")
        ),
    }


def _all_refs(
    event_ref: str,
    plan: EvidencePlan,
    bundle_ref: str,
    judge_ref: str,
    rca_ref: str,
    report_refs: Sequence[str],
    bundle: EvidenceBundle,
    rca: RCAResult,
) -> list[str]:
    refs = [
        event_ref,
        plan.plan_ref,
        bundle_ref,
        judge_ref,
        rca_ref,
        *report_refs,
        *bundle_evidence_refs(bundle),
        *bundle.evidence.knowledge.source_refs,
    ]
    for candidate in rca.candidates:
        refs.extend(candidate.supporting_evidence_refs)
        refs.extend(candidate.contradicting_evidence_refs)
    return sorted(set(refs))


async def replay_case(
    payload: Mapping[str, Any],
    *,
    fixture_name: str = "<memory>",
) -> dict[str, Any]:
    """Replay one sanitized scenario through Judge, RCA, and Report."""

    _validate_fixture(payload)
    request_id = str(payload["request_id"])
    scenario_id = str(payload["scenario_id"])
    event = _event(payload)
    plan = _plan(payload)
    bundle = _bundle(payload, event, plan)
    if {
        event.request_id,
        plan.request_id,
        bundle.request_id,
    } != {request_id}:
        raise HistoricalReplayError(
            "fixture contracts do not share one request_id"
        )

    judge = evaluate_evidence(plan, bundle)
    bundle_ref = build_contract_ref(
        "artifact",
        request_id,
        "evidence_bundle",
        "bundle-o",
    )
    judge_ref = build_contract_ref(
        "artifact",
        request_id,
        "judge_result",
        "judge-o",
    )
    response = _fixture_rca_response(payload, bundle)
    client = FixtureMockRCAClient(response)
    prior_refs = (
        bundle.event_ref,
        plan.plan_ref,
        bundle_ref,
        judge_ref,
        *bundle_evidence_refs(bundle),
        *bundle.evidence.knowledge.source_refs,
    )
    rca_invocation = AgentInvocation(
        request_id=request_id,
        agent_name=AgentName.RCA,
        orchestration_state=OrchestrationState.RCA,
        prior_output_refs=tuple(prior_refs),
        prior_outputs={
            AgentName.TRIAGE.value: {
                "unified_event": event.model_dump(mode="json")
            },
            "evidence_bundle": {
                "evidence_bundle": bundle.model_dump(mode="json")
            },
            AgentName.EVIDENCE_JUDGE.value: {
                "judge_result": judge.model_dump(mode="json")
            },
        },
    )
    occurred_at = _aware_datetime(
        payload["occurred_at"],
        field="occurred_at",
    )
    rca_outcome = await RCAAgent(
        enabled=True,
        client=client,
        utcnow=lambda: occurred_at,
    ).run(rca_invocation)
    if rca_outcome.status == AgentStatus.FAILED:
        errors = [
            item.model_dump(mode="json")
            for item in rca_outcome.errors
        ]
        raise HistoricalReplayError(
            "RCA replay failed: " + stable_json_dumps(errors)
        )
    rca = RCAResult.model_validate(
        rca_outcome.output["rca_result"]
    )
    if len(rca_outcome.output_refs) != 1:
        raise HistoricalReplayError(
            "RCA replay must produce one output ref"
        )
    rca_ref = rca_outcome.output_refs[0]

    report_invocation = AgentInvocation(
        request_id=request_id,
        agent_name=AgentName.NOTIFICATION_REPORT,
        orchestration_state=OrchestrationState.REPORTING,
        prior_output_refs=tuple([*prior_refs, rca_ref]),
        prior_outputs={
            AgentName.TRIAGE.value: {
                "unified_event": event.model_dump(mode="json")
            },
            "evidence_bundle": {
                "evidence_bundle": bundle.model_dump(mode="json")
            },
            AgentName.EVIDENCE_JUDGE.value: {
                "judge_result": judge.model_dump(mode="json")
            },
            AgentName.RCA.value: {
                "rca_result": rca.model_dump(mode="json")
            },
        },
    )
    report_outcome = await NotificationReportAgent(
        utcnow=lambda: occurred_at
    ).run(report_invocation)
    if report_outcome.status == AgentStatus.FAILED:
        errors = [
            item.model_dump(mode="json")
            for item in report_outcome.errors
        ]
        raise HistoricalReplayError(
            "Report replay failed: "
            + stable_json_dumps(errors)
        )

    legacy = _mapping(payload["legacy"], field="legacy")
    token = str(legacy.get("match_token") or "").strip().lower()
    statements = " ".join(
        candidate.statement
        for candidate in rca.candidates
    ).lower()
    if token and token in statements:
        comparison_status = "matched"
    elif judge.status in {
        JudgeStatus.INSUFFICIENT,
        JudgeStatus.BLOCKED,
    }:
        comparison_status = "not_comparable_due_to_evidence"
    else:
        comparison_status = "mismatch"

    source_statuses = {
        "metrics": bundle.evidence.metrics.status.value,
        "device": bundle.evidence.device.status.value,
        "logs": bundle.evidence.logs.status.value,
        "knowledge": bundle.evidence.knowledge.status.value,
    }
    source_required = {
        item.source.value: item.required
        for item in plan.sources
    }
    notification_plan = dict(
        report_outcome.output["notification_plan"]
    )
    report_refs = list(report_outcome.output_refs)

    result = {
        "schema_version": REPLAY_SCHEMA_VERSION,
        "fixture_name": fixture_name,
        "scenario_id": scenario_id,
        "category": str(payload["category"]),
        "source_kind": str(payload["source_kind"]),
        "request_id": request_id,
        "legacy": {
            "conclusion": str(legacy.get("conclusion") or ""),
            "match_token": token,
            "comparison_status": comparison_status,
        },
        "expected": dict(
            _mapping(payload["expected"], field="expected")
        ),
        "source_statuses": source_statuses,
        "source_required": source_required,
        "judge": judge.model_dump(mode="json"),
        "rca": rca.model_dump(mode="json"),
        "report": {
            "status": report_outcome.status.value,
            "compatibility_card_keys": list(
                report_outcome.output[
                    "compatibility_card"
                ].keys()
            ),
            "notification_plan": notification_plan,
            "notification_sent": bool(
                report_outcome.output["notification_sent"]
            ),
        },
        "all_refs": _all_refs(
            bundle.event_ref,
            plan,
            bundle_ref,
            judge_ref,
            rca_ref,
            report_refs,
            bundle,
            rca,
        ),
        "external_calls": {
            "mock_glm": bool(
                rca_outcome.output.get(
                    "mock_glm_called",
                    False,
                )
            ),
            "production_glm": bool(
                rca_outcome.output.get(
                    "production_glm_called",
                    False,
                )
            ),
            "prometheus_mcp": False,
            "netmiko_mcp": False,
            "evidence_mcp": False,
            "ops_es_api": False,
            "analytics_mcp": False,
            "notification": bool(
                report_outcome.output["notification_sent"]
            ),
            "tool": bool(
                rca_outcome.output.get("tool_called", False)
                or report_outcome.output.get(
                    "tool_called",
                    False,
                )
            ),
        },
        "mock_glm_call_count": client.calls,
        "execution_error": None,
    }
    fingerprint_payload = dict(result)
    result["fingerprint"] = hashlib.sha256(
        stable_json_dumps(fingerprint_payload).encode("utf-8")
    ).hexdigest()
    return result


async def replay_fixture(path: str | Path) -> dict[str, Any]:
    fixture_path = Path(path)
    return await replay_case(
        load_fixture(fixture_path),
        fixture_name=fixture_path.name,
    )


async def run_replay_suite(
    fixture_root: str | Path,
) -> dict[str, Any]:
    """Run every fixture twice and enforce deterministic quality gates."""

    cases = []
    for path in discover_fixtures(fixture_root):
        try:
            first = await replay_fixture(path)
            second = await replay_fixture(path)
            first["deterministic"] = (
                first["fingerprint"]
                == second["fingerprint"]
            )
            cases.append(first)
        except Exception as exc:
            cases.append(
                {
                    "schema_version": REPLAY_SCHEMA_VERSION,
                    "fixture_name": path.name,
                    "scenario_id": path.stem,
                    "category": "",
                    "request_id": "",
                    "expected": {},
                    "judge": {},
                    "rca": {},
                    "report": {},
                    "all_refs": [],
                    "source_statuses": {},
                    "source_required": {},
                    "external_calls": {},
                    "legacy": {
                        "comparison_status": "mismatch"
                    },
                    "deterministic": False,
                    "execution_error": (
                        f"{type(exc).__name__}: {exc}"
                    ),
                }
            )

    gates = evaluate_quality_gates(cases)
    return {
        "schema_version": "v12-replay-suite-report-1",
        "replay_schema_version": REPLAY_SCHEMA_VERSION,
        "fixture_root": str(Path(fixture_root)),
        "status": gates["status"],
        "case_count": len(cases),
        "deterministic_case_count": sum(
            1 for case in cases if case.get("deterministic")
        ),
        "cases": cases,
        "quality_gates": gates,
        "external_calls": {
            "production_glm": False,
            "prometheus_mcp": False,
            "netmiko_mcp": False,
            "evidence_mcp": False,
            "ops_es_api": False,
            "analytics_mcp": False,
            "notification": False,
        },
    }


def run_replay_suite_sync(
    fixture_root: str | Path,
) -> dict[str, Any]:
    return asyncio.run(run_replay_suite(fixture_root))


__all__ = [
    "FIXTURE_SCHEMA_VERSION",
    "HistoricalReplayError",
    "MOCK_PROVIDER",
    "REPLAY_SCHEMA_VERSION",
    "discover_fixtures",
    "load_fixture",
    "replay_case",
    "replay_fixture",
    "run_replay_suite",
    "run_replay_suite_sync",
]
