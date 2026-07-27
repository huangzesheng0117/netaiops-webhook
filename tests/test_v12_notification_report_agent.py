from __future__ import annotations

import asyncio
import copy
import inspect
import json
import socket
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from netaiops.v12.agent_registry import (
    AgentFailurePolicy,
    AgentSpec,
)
from netaiops.v12.agents.notification_report_agent import (
    NotificationReportAgent,
)
from netaiops.v12.contracts import (
    AlertObject,
    ContextEnvelope,
    DeviceIdentity,
    EvidenceBundle,
    EvidenceCollection,
    EvidenceEnvelope,
    EvidenceJudgeResult,
    RCACandidate,
    RCAResult,
    ReportArtifact,
    UnifiedAlertEvent,
)
from netaiops.v12.execution_context import AgentInvocation
from netaiops.v12.report_renderer import (
    CURRENT_CARD_KEYS,
    RENDERER_VERSION,
    ReportRenderError,
    render_report,
)
from netaiops.v12.schema_validator import (
    parse_contract_ref,
    stable_json_dumps,
)
from netaiops.v12.state_machine import OrchestrationState
from netaiops.v12.status import (
    AgentName,
    AgentStatus,
    AlertLifecycleStatus,
    AlertSource,
    EvidenceBundleStatus,
    EvidenceSource,
    EvidenceStatus,
    JudgeStatus,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GOLDEN_ROOT = (
    PROJECT_ROOT
    / "tests/golden/v12/current_card"
)
REQUEST_ID = "req-batch-l-001"
NOW = datetime(
    2026,
    7,
    23,
    7,
    0,
    tzinfo=timezone.utc,
)
EVENT_REF = (
    f"event://{REQUEST_ID}/unified_alert/evt-l"
)
METRICS_REF = (
    f"evidence://{REQUEST_ID}/metrics/metrics-l-1"
)
DEVICE_REF = (
    f"evidence://{REQUEST_ID}/device/device-l-1"
)
LOGS_REF = (
    f"evidence://{REQUEST_ID}/logs/logs-l-1"
)
BUNDLE_REF = (
    f"artifact://{REQUEST_ID}/evidence_bundle/bundle-l"
)
JUDGE_REF = (
    f"artifact://{REQUEST_ID}/judge_result/judge-l"
)
RCA_REF = (
    f"artifact://{REQUEST_ID}/rca_result/rca-l"
)


def golden(name: str) -> dict:
    return json.loads(
        (GOLDEN_ROOT / name).read_text(
            encoding="utf-8"
        )
    )


def event_payload(
    *,
    resolved: bool = False,
) -> dict:
    return UnifiedAlertEvent(
        schema_version="v12.1",
        request_id=REQUEST_ID,
        event_id="evt-l",
        source=AlertSource.ALERTMANAGER,
        alert_status=(
            AlertLifecycleStatus.RESOLVED
            if resolved
            else AlertLifecycleStatus.FIRING
        ),
        alert_name="InterfaceDown",
        occurred_at=NOW,
        received_at=NOW,
        ends_at=NOW if resolved else None,
        device=DeviceIdentity(
            name="SW01",
            ip="10.0.0.1",
            vendor="cisco",
        ),
        alert_object=AlertObject(
            kind="interface",
            name="Ethernet1/1",
        ),
        labels={"severity": "critical"},
        annotations={"summary": "interface down"},
        family="interface_status_or_flap",
        event_key="event:l",
    ).model_dump(mode="json")


def evidence(
    source: EvidenceSource,
    status: EvidenceStatus,
    reference: str | None,
    *,
    facts: dict | None = None,
) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        schema_version="v12.1",
        request_id=REQUEST_ID,
        source=source,
        evidence_kind="evidence",
        status=status,
        summary=f"{source.value} evidence",
        facts=facts or {"observed_state": "down"},
        scope={
            "device_ip": "10.0.0.1",
            "interface": "Ethernet1/1",
        },
        evidence_refs=[reference] if reference else [],
        collected_at=NOW,
        reason=(
            f"{source.value}_not_available"
            if status == EvidenceStatus.NOT_AVAILABLE
            else None
        ),
    )


def bundle_payload(
    *,
    ready: bool = False,
    insufficient: bool = False,
) -> dict:
    metrics_status = (
        EvidenceStatus.FAILED
        if insufficient
        else EvidenceStatus.SUCCESS
    )
    logs_status = (
        EvidenceStatus.SUCCESS
        if ready
        else EvidenceStatus.NOT_AVAILABLE
    )
    knowledge_status = (
        EvidenceStatus.SUCCESS
        if ready
        else EvidenceStatus.NOT_AVAILABLE
    )
    knowledge = ContextEnvelope(
        schema_version="v12.1",
        request_id=REQUEST_ID,
        source="knowledge",
        evidence_kind="context",
        status=knowledge_status,
        reason=(
            None
            if ready
            else "local_knowledge_base_not_built"
        ),
        context_facts=[],
        source_refs=(
            [
                f"context://{REQUEST_ID}/"
                "knowledge_context/context-l"
            ]
            if ready
            else []
        ),
        as_of=NOW if ready else None,
        collected_at=NOW,
    )
    return EvidenceBundle(
        schema_version="v12.1",
        request_id=REQUEST_ID,
        event_ref=EVENT_REF,
        plan_ref=(
            f"plan://{REQUEST_ID}/evidence_plan/plan-l"
        ),
        evidence=EvidenceCollection(
            metrics=evidence(
                EvidenceSource.METRICS,
                metrics_status,
                METRICS_REF
                if metrics_status == EvidenceStatus.SUCCESS
                else None,
                facts={
                    "raw_output": "DO-NOT-LEAK",
                    "token": "DO-NOT-LEAK-TOKEN",
                },
            ),
            device=evidence(
                EvidenceSource.DEVICE,
                EvidenceStatus.SUCCESS,
                DEVICE_REF,
                facts={
                    "observed_state": "down",
                    "full_device_output": "DO-NOT-LEAK",
                },
            ),
            logs=evidence(
                EvidenceSource.LOGS,
                logs_status,
                LOGS_REF if ready else None,
                facts=(
                    {"event": "link down"}
                    if ready
                    else {}
                ),
            ),
            knowledge=knowledge,
        ),
        bundle_status=(
            EvidenceBundleStatus.COMPLETE
            if ready
            else EvidenceBundleStatus.INSUFFICIENT
            if insufficient
            else EvidenceBundleStatus.PARTIAL
        ),
        built_at=NOW,
    ).model_dump(mode="json")


def judge_payload(
    *,
    ready: bool = False,
    insufficient: bool = False,
    blocked: bool = False,
) -> dict:
    status = (
        JudgeStatus.BLOCKED
        if blocked
        else JudgeStatus.INSUFFICIENT
        if insufficient
        else JudgeStatus.READY
        if ready
        else JudgeStatus.PARTIAL
    )
    allowed = status in {
        JudgeStatus.READY,
        JudgeStatus.PARTIAL,
    }
    return EvidenceJudgeResult(
        schema_version="v12.1",
        request_id=REQUEST_ID,
        status=status,
        required_sources=[
            EvidenceSource.METRICS,
            EvidenceSource.DEVICE,
        ],
        missing_required_sources=(
            [EvidenceSource.METRICS]
            if insufficient
            else []
        ),
        missing_optional_sources=(
            []
            if ready
            else [
                EvidenceSource.LOGS,
                EvidenceSource.KNOWLEDGE,
            ]
        ),
        conflicts=[],
        rca_allowed=allowed,
        confidence_cap=(
            1.0
            if ready
            else 0.85
            if allowed
            else 0.0
        ),
        evidence_refs=(
            [METRICS_REF, DEVICE_REF, LOGS_REF]
            if ready
            else [DEVICE_REF]
            if insufficient
            else [METRICS_REF, DEVICE_REF]
        ),
        judged_at=NOW,
    ).model_dump(mode="json")


def rca_payload(
    *,
    ready: bool = False,
    insufficient: bool = False,
    blocked: bool = False,
) -> dict:
    candidate = RCACandidate(
        statement=(
            "The interface is likely down because metrics "
            "and device evidence agree."
        ),
        confidence=0.8,
        supporting_evidence_refs=[
            METRICS_REF,
            DEVICE_REF,
        ],
        contradicting_evidence_refs=[],
        missing_evidence=[],
        uncertainties=[
            "The initiating physical event is not directly observed."
        ],
        scope={
            "device_ip": "10.0.0.1",
            "interface": "Ethernet1/1",
        },
    )
    return RCAResult(
        schema_version="v12.1",
        request_id=REQUEST_ID,
        status=(
            AgentStatus.SUCCESS
            if ready
            else AgentStatus.SKIPPED
        ),
        event_ref=EVENT_REF,
        bundle_ref=BUNDLE_REF,
        judge_ref=JUDGE_REF,
        candidates=[candidate] if ready else [],
        missing_evidence=(
            []
            if ready
            else ["metrics", "logs", "knowledge"]
            if insufficient
            else ["logs", "knowledge"]
        ),
        uncertainties=(
            ["evidence_conflict"]
            if blocked
            else ["judge_status_insufficient"]
            if insufficient
            else ["rca_disabled_by_default"]
            if not ready
            else [
                "Root cause remains an evidence-grounded hypothesis."
            ]
        ),
        generated_at=NOW,
        provider="mock-glm-5.2" if ready else None,
    ).model_dump(mode="json")


def invocation(
    *,
    resolved: bool = False,
    ready: bool = False,
    insufficient: bool = False,
    blocked: bool = False,
    agent_name: AgentName = AgentName.NOTIFICATION_REPORT,
) -> AgentInvocation:
    return AgentInvocation(
        request_id=REQUEST_ID,
        agent_name=agent_name,
        orchestration_state=OrchestrationState.REPORTING,
        prior_output_refs=(
            EVENT_REF,
            BUNDLE_REF,
            JUDGE_REF,
            RCA_REF,
            METRICS_REF,
            DEVICE_REF,
            *((LOGS_REF,) if ready else ()),
        ),
        prior_outputs={
            AgentName.TRIAGE.value: {
                "unified_event": event_payload(
                    resolved=resolved
                )
            },
            "evidence_bundle": {
                "evidence_bundle": bundle_payload(
                    ready=ready,
                    insufficient=insufficient,
                )
            },
            AgentName.EVIDENCE_JUDGE.value: {
                "judge_result": judge_payload(
                    ready=ready,
                    insufficient=insufficient,
                    blocked=blocked,
                )
            },
            AgentName.RCA.value: {
                "rca_result": rca_payload(
                    ready=ready,
                    insufficient=insufficient,
                    blocked=blocked,
                )
            },
        },
    )


class NotificationReportAgentTests(unittest.TestCase):
    golden_names = (
        "firing_insufficient_skipped.json",
        "firing_partial_skipped.json",
        "firing_ready_success.json",
        "resolved_partial_skipped.json",
    )

    def execute(
        self,
        value: AgentInvocation,
        *,
        utcnow=lambda: NOW,
    ):
        return asyncio.run(
            NotificationReportAgent(
                utcnow=utcnow
            ).run(value)
        )

    def test_golden_set_is_complete(self) -> None:
        names = tuple(
            path.name
            for path in sorted(GOLDEN_ROOT.glob("*.json"))
        )
        self.assertEqual(names, self.golden_names)

    def test_firing_partial_golden(self) -> None:
        outcome = self.execute(invocation())
        expected = golden(
            "firing_partial_skipped.json"
        )
        self.assertEqual(
            outcome.output["compatibility_card"],
            expected["compatibility_card"],
        )
        self.assertEqual(
            outcome.output["evidence_hub_summary"],
            expected["evidence_hub_summary"],
        )

    def test_resolved_partial_golden(self) -> None:
        outcome = self.execute(
            invocation(resolved=True)
        )
        expected = golden(
            "resolved_partial_skipped.json"
        )
        self.assertEqual(
            outcome.output["compatibility_card"],
            expected["compatibility_card"],
        )
        self.assertEqual(
            outcome.output["evidence_hub_summary"],
            expected["evidence_hub_summary"],
        )

    def test_firing_ready_golden(self) -> None:
        outcome = self.execute(
            invocation(ready=True)
        )
        expected = golden(
            "firing_ready_success.json"
        )
        self.assertEqual(
            outcome.output["compatibility_card"],
            expected["compatibility_card"],
        )
        self.assertEqual(
            outcome.output["evidence_hub_summary"],
            expected["evidence_hub_summary"],
        )

    def test_insufficient_golden(self) -> None:
        outcome = self.execute(
            invocation(insufficient=True)
        )
        expected = golden(
            "firing_insufficient_skipped.json"
        )
        self.assertEqual(
            outcome.output["compatibility_card"],
            expected["compatibility_card"],
        )
        self.assertEqual(
            outcome.output["evidence_hub_summary"],
            expected["evidence_hub_summary"],
        )

    def test_current_card_keys_are_exact(self) -> None:
        value = invocation()
        rendered = render_report(
            event=UnifiedAlertEvent.model_validate(
                value.prior_outputs[
                    AgentName.TRIAGE.value
                ]["unified_event"]
            ),
            bundle=EvidenceBundle.model_validate(
                value.prior_outputs[
                    "evidence_bundle"
                ]["evidence_bundle"]
            ),
            judge=EvidenceJudgeResult.model_validate(
                value.prior_outputs[
                    AgentName.EVIDENCE_JUDGE.value
                ]["judge_result"]
            ),
            rca=RCAResult.model_validate(
                value.prior_outputs[
                    AgentName.RCA.value
                ]["rca_result"]
            ),
            bundle_ref=BUNDLE_REF,
            judge_ref=JUDGE_REF,
            rca_ref=RCA_REF,
            generated_at=NOW,
        )
        self.assertEqual(
            tuple(rendered.compatibility_card),
            CURRENT_CARD_KEYS,
        )

    def test_evidence_hub_summary_keys_are_exact(self) -> None:
        value = invocation()
        rendered = render_report(
            event=UnifiedAlertEvent.model_validate(
                value.prior_outputs[
                    AgentName.TRIAGE.value
                ]["unified_event"]
            ),
            bundle=EvidenceBundle.model_validate(
                value.prior_outputs[
                    "evidence_bundle"
                ]["evidence_bundle"]
            ),
            judge=EvidenceJudgeResult.model_validate(
                value.prior_outputs[
                    AgentName.EVIDENCE_JUDGE.value
                ]["judge_result"]
            ),
            rca=RCAResult.model_validate(
                value.prior_outputs[
                    AgentName.RCA.value
                ]["rca_result"]
            ),
            bundle_ref=BUNDLE_REF,
            judge_ref=JUDGE_REF,
            rca_ref=RCA_REF,
            generated_at=NOW,
        )
        self.assertEqual(
            tuple(rendered.evidence_hub_summary),
            (
                "request_id",
                "alert_name",
                "alert_status",
                "device",
                "alert_object",
                "current_judgment",
                "recommendations",
                "evidence_summary",
                "details_url",
            ),
        )

    def test_report_artifact_contract(self) -> None:
        result = ReportArtifact.model_validate(
            self.execute(
                invocation()
            ).output["report_artifact"]
        )
        self.assertTrue(result.notification_compatible)

    def test_report_sections_match_current_fields(self) -> None:
        result = ReportArtifact.model_validate(
            self.execute(
                invocation()
            ).output["report_artifact"]
        )
        self.assertEqual(
            [section.key for section in result.sections],
            [
                "alert_status",
                "device",
                "alert_object",
                "alert_content",
                "current_judgment",
                "recommendations",
                "evidence_summary",
            ],
        )

    def test_report_artifact_refs_are_exact(self) -> None:
        result = ReportArtifact.model_validate(
            self.execute(
                invocation()
            ).output["report_artifact"]
        )
        self.assertEqual(
            result.artifact_refs,
            [BUNDLE_REF, JUDGE_REF, RCA_REF],
        )

    def test_report_evidence_refs_are_sorted_unique(self) -> None:
        result = ReportArtifact.model_validate(
            self.execute(
                invocation(ready=True)
            ).output["report_artifact"]
        )
        self.assertEqual(
            result.evidence_refs,
            sorted(set(result.evidence_refs)),
        )

    def test_ready_report_is_success(self) -> None:
        outcome = self.execute(
            invocation(ready=True)
        )
        self.assertEqual(outcome.status, AgentStatus.SUCCESS)

    def test_partial_report_is_partial(self) -> None:
        outcome = self.execute(invocation())
        self.assertEqual(outcome.status, AgentStatus.PARTIAL)

    def test_insufficient_still_generates_partial_report(self) -> None:
        outcome = self.execute(
            invocation(insufficient=True)
        )
        self.assertEqual(outcome.status, AgentStatus.PARTIAL)
        self.assertIn("report_artifact", outcome.output)

    def test_blocked_still_generates_partial_report(self) -> None:
        outcome = self.execute(
            invocation(blocked=True)
        )
        self.assertEqual(outcome.status, AgentStatus.PARTIAL)
        self.assertIn(
            "证据存在冲突",
            outcome.output["compatibility_card"][
                "current_judgment"
            ],
        )

    def test_firing_title_is_compatible(self) -> None:
        card = self.execute(
            invocation()
        ).output["compatibility_card"]
        self.assertEqual(
            card["title"],
            "[network][告警] InterfaceDown",
        )

    def test_resolved_title_is_compatible(self) -> None:
        card = self.execute(
            invocation(resolved=True)
        ).output["compatibility_card"]
        self.assertEqual(
            card["title"],
            "[network][恢复] InterfaceDown",
        )

    def test_device_field_is_compatible(self) -> None:
        card = self.execute(
            invocation()
        ).output["compatibility_card"]
        self.assertEqual(
            card["device"],
            "SW01 (10.0.0.1)",
        )

    def test_alert_object_field_is_compatible(self) -> None:
        card = self.execute(
            invocation()
        ).output["compatibility_card"]
        self.assertEqual(
            card["alert_object"],
            "interface: Ethernet1/1",
        )

    def test_alert_content_uses_summary(self) -> None:
        card = self.execute(
            invocation()
        ).output["compatibility_card"]
        self.assertEqual(
            card["alert_content"],
            "interface down",
        )

    def test_rca_candidate_becomes_current_judgment(self) -> None:
        card = self.execute(
            invocation(ready=True)
        ).output["compatibility_card"]
        self.assertIn("候选根因", card["current_judgment"])
        self.assertIn("80%", card["current_judgment"])

    def test_rca_skipped_uses_conservative_fallback(self) -> None:
        card = self.execute(
            invocation()
        ).output["compatibility_card"]
        self.assertIn(
            "保守判断",
            card["current_judgment"],
        )

    def test_insufficient_uses_safe_fallback(self) -> None:
        card = self.execute(
            invocation(insufficient=True)
        ).output["compatibility_card"]
        self.assertIn(
            "必要证据不足",
            card["current_judgment"],
        )

    def test_resolved_judgment_mentions_recovery(self) -> None:
        card = self.execute(
            invocation(resolved=True)
        ).output["compatibility_card"]
        self.assertTrue(
            card["current_judgment"].startswith(
                "告警已恢复"
            )
        )

    def test_missing_optional_sources_do_not_block_report(self) -> None:
        outcome = self.execute(invocation())
        self.assertNotEqual(
            outcome.status,
            AgentStatus.FAILED,
        )

    def test_not_available_is_not_rendered_as_normal(self) -> None:
        serialized = stable_json_dumps(
            self.execute(invocation()).output
        )
        self.assertNotIn("日志正常", serialized)
        self.assertNotIn("未发现日志异常", serialized)
        self.assertIn("未启用/不可用", serialized)

    def test_no_data_is_not_rendered_as_normal(self) -> None:
        payload = bundle_payload()
        payload["evidence"]["metrics"]["status"] = "no_data"
        payload["evidence"]["metrics"]["evidence_refs"] = []
        value = invocation()
        prior = copy.deepcopy(dict(value.prior_outputs))
        prior["evidence_bundle"]["evidence_bundle"] = payload
        prior[AgentName.EVIDENCE_JUDGE.value][
            "judge_result"
        ]["missing_required_sources"] = ["metrics"]
        prior[AgentName.EVIDENCE_JUDGE.value][
            "judge_result"
        ]["confidence_cap"] = 0.65
        prior[AgentName.EVIDENCE_JUDGE.value][
            "judge_result"
        ]["evidence_refs"] = [DEVICE_REF]
        prior[AgentName.RCA.value]["rca_result"][
            "missing_evidence"
        ] = ["metrics", "logs", "knowledge"]
        outcome = self.execute(
            AgentInvocation(
                request_id=value.request_id,
                agent_name=value.agent_name,
                orchestration_state=value.orchestration_state,
                prior_output_refs=value.prior_output_refs,
                prior_outputs=prior,
            )
        )
        self.assertIn(
            "指定窗口未命中",
            outcome.output["compatibility_card"][
                "evidence_summary"
            ],
        )

    def test_failed_is_rendered_as_query_failed(self) -> None:
        card = self.execute(
            invocation(insufficient=True)
        ).output["compatibility_card"]
        self.assertIn("查询失败", card["evidence_summary"])

    def test_notification_is_never_sent(self) -> None:
        output = self.execute(invocation()).output
        self.assertFalse(output["notification_sent"])
        self.assertFalse(
            output["notification_plan"][
                "send_notification"
            ]
        )

    def test_notification_count_is_zero(self) -> None:
        plan = self.execute(
            invocation()
        ).output["notification_plan"]
        self.assertEqual(plan["notification_count"], 0)

    def test_second_card_is_never_sent(self) -> None:
        plan = self.execute(
            invocation()
        ).output["notification_plan"]
        self.assertFalse(plan["second_card_sent"])

    def test_production_card_is_not_replaced(self) -> None:
        plan = self.execute(
            invocation()
        ).output["notification_plan"]
        self.assertFalse(plan["production_card_replaced"])

    def test_evidence_hub_is_not_written(self) -> None:
        output = self.execute(invocation()).output
        self.assertFalse(output["evidence_hub_written"])

    def test_no_external_calls(self) -> None:
        outcome = self.execute(invocation())
        self.assertEqual(outcome.external_calls, ())

    def test_output_call_flags_are_false(self) -> None:
        output = self.execute(invocation()).output
        self.assertFalse(output["glm_called"])
        self.assertFalse(output["mcp_called"])
        self.assertFalse(output["tool_called"])

    def test_no_raw_payload_leak(self) -> None:
        serialized = stable_json_dumps(
            self.execute(invocation()).output
        )
        self.assertNotIn("DO-NOT-LEAK", serialized)
        self.assertNotIn("DO-NOT-LEAK-TOKEN", serialized)
        self.assertNotIn("full_device_output", serialized)

    def test_no_complete_log_or_command_fields(self) -> None:
        serialized = stable_json_dumps(
            self.execute(invocation()).output
        )
        for token in (
            "command_output",
            "command_outputs",
            "full_log",
            "full_logs",
            "raw_payload",
            "prometheus_samples",
        ):
            self.assertNotIn(token, serialized)

    def test_deterministic_payload_for_same_input(self) -> None:
        first = self.execute(invocation()).output
        second = self.execute(invocation()).output
        self.assertEqual(
            stable_json_dumps(first),
            stable_json_dumps(second),
        )

    def test_output_ref_is_stable(self) -> None:
        first = self.execute(invocation()).output_refs
        second = self.execute(invocation()).output_refs
        self.assertEqual(first, second)
        parsed = parse_contract_ref(first[0])
        self.assertEqual(parsed["scheme"], "report")
        self.assertEqual(parsed["kind"], "report_artifact")

    def test_renderer_version_is_frozen(self) -> None:
        output = self.execute(invocation()).output
        self.assertEqual(
            output["renderer_version"],
            RENDERER_VERSION,
        )

    def test_naive_generated_at_fails(self) -> None:
        outcome = self.execute(
            invocation(),
            utcnow=lambda: datetime(2026, 7, 23, 7, 0),
        )
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_wrong_agent_name_fails(self) -> None:
        outcome = self.execute(
            invocation(agent_name=AgentName.RCA)
        )
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_missing_event_fails(self) -> None:
        value = invocation()
        prior = dict(value.prior_outputs)
        prior.pop(AgentName.TRIAGE.value)
        broken = AgentInvocation(
            request_id=value.request_id,
            agent_name=value.agent_name,
            orchestration_state=value.orchestration_state,
            prior_output_refs=value.prior_output_refs,
            prior_outputs=prior,
        )
        self.assertEqual(
            self.execute(broken).status,
            AgentStatus.FAILED,
        )

    def test_missing_bundle_fails(self) -> None:
        value = invocation()
        prior = dict(value.prior_outputs)
        prior.pop("evidence_bundle")
        broken = AgentInvocation(
            request_id=value.request_id,
            agent_name=value.agent_name,
            orchestration_state=value.orchestration_state,
            prior_output_refs=value.prior_output_refs,
            prior_outputs=prior,
        )
        self.assertEqual(
            self.execute(broken).status,
            AgentStatus.FAILED,
        )

    def test_missing_judge_fails(self) -> None:
        value = invocation()
        prior = dict(value.prior_outputs)
        prior.pop(AgentName.EVIDENCE_JUDGE.value)
        broken = AgentInvocation(
            request_id=value.request_id,
            agent_name=value.agent_name,
            orchestration_state=value.orchestration_state,
            prior_output_refs=value.prior_output_refs,
            prior_outputs=prior,
        )
        self.assertEqual(
            self.execute(broken).status,
            AgentStatus.FAILED,
        )

    def test_missing_rca_fails(self) -> None:
        value = invocation()
        prior = dict(value.prior_outputs)
        prior.pop(AgentName.RCA.value)
        broken = AgentInvocation(
            request_id=value.request_id,
            agent_name=value.agent_name,
            orchestration_state=value.orchestration_state,
            prior_output_refs=value.prior_output_refs,
            prior_outputs=prior,
        )
        self.assertEqual(
            self.execute(broken).status,
            AgentStatus.FAILED,
        )

    def test_request_id_mismatch_fails(self) -> None:
        value = invocation()
        prior = copy.deepcopy(dict(value.prior_outputs))
        prior["evidence_bundle"]["evidence_bundle"][
            "request_id"
        ] = "req-other"
        broken = AgentInvocation(
            request_id=value.request_id,
            agent_name=value.agent_name,
            orchestration_state=value.orchestration_state,
            prior_output_refs=value.prior_output_refs,
            prior_outputs=prior,
        )
        self.assertEqual(
            self.execute(broken).status,
            AgentStatus.FAILED,
        )

    def test_missing_bundle_ref_fails(self) -> None:
        value = invocation()
        refs = tuple(
            ref
            for ref in value.prior_output_refs
            if ref != BUNDLE_REF
        )
        broken = AgentInvocation(
            request_id=value.request_id,
            agent_name=value.agent_name,
            orchestration_state=value.orchestration_state,
            prior_output_refs=refs,
            prior_outputs=value.prior_outputs,
        )
        self.assertEqual(
            self.execute(broken).status,
            AgentStatus.FAILED,
        )

    def test_duplicate_judge_ref_fails(self) -> None:
        value = invocation()
        broken = AgentInvocation(
            request_id=value.request_id,
            agent_name=value.agent_name,
            orchestration_state=value.orchestration_state,
            prior_output_refs=(
                *value.prior_output_refs,
                (
                    f"artifact://{REQUEST_ID}/"
                    "judge_result/judge-l-2"
                ),
            ),
            prior_outputs=value.prior_outputs,
        )
        self.assertEqual(
            self.execute(broken).status,
            AgentStatus.FAILED,
        )

    def test_rca_bundle_ref_mismatch_fails(self) -> None:
        value = invocation()
        prior = copy.deepcopy(dict(value.prior_outputs))
        prior[AgentName.RCA.value]["rca_result"][
            "bundle_ref"
        ] = (
            f"artifact://{REQUEST_ID}/"
            "evidence_bundle/other"
        )
        broken = AgentInvocation(
            request_id=value.request_id,
            agent_name=value.agent_name,
            orchestration_state=value.orchestration_state,
            prior_output_refs=value.prior_output_refs,
            prior_outputs=prior,
        )
        self.assertEqual(
            self.execute(broken).status,
            AgentStatus.FAILED,
        )

    def test_rca_judge_ref_mismatch_fails(self) -> None:
        value = invocation()
        prior = copy.deepcopy(dict(value.prior_outputs))
        prior[AgentName.RCA.value]["rca_result"][
            "judge_ref"
        ] = (
            f"artifact://{REQUEST_ID}/"
            "judge_result/other"
        )
        broken = AgentInvocation(
            request_id=value.request_id,
            agent_name=value.agent_name,
            orchestration_state=value.orchestration_state,
            prior_output_refs=value.prior_output_refs,
            prior_outputs=prior,
        )
        self.assertEqual(
            self.execute(broken).status,
            AgentStatus.FAILED,
        )

    def test_judge_ref_outside_bundle_fails(self) -> None:
        value = invocation()
        prior = copy.deepcopy(dict(value.prior_outputs))
        prior[AgentName.EVIDENCE_JUDGE.value][
            "judge_result"
        ]["evidence_refs"] = [
            (
                f"evidence://{REQUEST_ID}/"
                "device/not-in-bundle"
            )
        ]
        broken = AgentInvocation(
            request_id=value.request_id,
            agent_name=value.agent_name,
            orchestration_state=value.orchestration_state,
            prior_output_refs=value.prior_output_refs,
            prior_outputs=prior,
        )
        self.assertEqual(
            self.execute(broken).status,
            AgentStatus.FAILED,
        )

    def test_render_report_rejects_naive_timestamp(self) -> None:
        value = invocation()
        event = UnifiedAlertEvent.model_validate(
            value.prior_outputs[
                AgentName.TRIAGE.value
            ]["unified_event"]
        )
        bundle = EvidenceBundle.model_validate(
            value.prior_outputs[
                "evidence_bundle"
            ]["evidence_bundle"]
        )
        judge = EvidenceJudgeResult.model_validate(
            value.prior_outputs[
                AgentName.EVIDENCE_JUDGE.value
            ]["judge_result"]
        )
        rca = RCAResult.model_validate(
            value.prior_outputs[
                AgentName.RCA.value
            ]["rca_result"]
        )
        with self.assertRaises(ReportRenderError):
            render_report(
                event=event,
                bundle=bundle,
                judge=judge,
                rca=rca,
                bundle_ref=BUNDLE_REF,
                judge_ref=JUDGE_REF,
                rca_ref=RCA_REF,
                generated_at=datetime(2026, 7, 23, 7, 0),
            )

    def test_agent_does_not_create_network_socket(self) -> None:
        agent = NotificationReportAgent(
            utcnow=lambda: NOW
        )
        value = invocation()
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            with mock.patch.object(
                socket,
                "socket",
                side_effect=AssertionError(
                    "network forbidden"
                ),
            ):
                outcome = loop.run_until_complete(
                    agent.run(value)
                )
        finally:
            asyncio.set_event_loop(None)
            loop.close()
        self.assertEqual(outcome.status, AgentStatus.PARTIAL)

    def test_async_registry_protocol(self) -> None:
        agent = NotificationReportAgent(
            utcnow=lambda: NOW
        )
        self.assertTrue(
            inspect.iscoroutinefunction(agent.run)
        )
        spec = AgentSpec(
            name=AgentName.NOTIFICATION_REPORT,
            agent=agent,
            required=False,
            failure_policy=AgentFailurePolicy.CONTINUE,
        )
        self.assertEqual(spec.retry_limit, 0)

    def test_production_modules_have_no_external_clients(self) -> None:
        paths = (
            PROJECT_ROOT / "netaiops/v12/report_renderer.py",
            PROJECT_ROOT
            / "netaiops/v12/agents/"
            "notification_report_agent.py",
        )
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in paths
        ).lower()
        for token in (
            "import requests",
            "import httpx",
            "import socket",
            "import subprocess",
            "fastmcp(",
            "elasticsearch(",
            "prometheusbridge",
            "execute_commands(",
            "send_dongdong(",
            "send_notification(",
            "universalcard(",
            "openai(",
        ):
            self.assertNotIn(token, text)

    def test_no_free_loop_or_followup(self) -> None:
        paths = (
            PROJECT_ROOT / "netaiops/v12/report_renderer.py",
            PROJECT_ROOT
            / "netaiops/v12/agents/"
            "notification_report_agent.py",
        )
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in paths
        )
        for token in (
            "while True",
            "followup_query(",
            "supplement_evidence(",
            "retry(",
        ):
            self.assertNotIn(token, text)


if __name__ == "__main__":
    unittest.main()
