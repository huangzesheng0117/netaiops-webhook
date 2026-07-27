"""v12 Notification / Report compatibility Agent."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Mapping

from pydantic import ValidationError

from ..contracts import (
    ContractNotice,
    EvidenceBundle,
    EvidenceJudgeResult,
    RCAResult,
    UnifiedAlertEvent,
)
from ..execution_context import AgentInvocation, AgentOutcome
from ..report_renderer import (
    RENDERER_VERSION,
    ReportRenderError,
    render_report,
)
from ..schema_validator import (
    build_contract_ref,
    parse_contract_ref,
    stable_json_dumps,
)
from ..status import AgentName, AgentStatus


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _notice(
    code: str,
    message: str,
    *,
    details: Mapping[str, Any] | None = None,
) -> ContractNotice:
    return ContractNotice(
        code=code,
        message=message,
        stage="notification_report",
        retryable=False,
        details=dict(details or {}),
    )


class NotificationReportAgent:
    """Build current-card-compatible output without sending it."""

    def __init__(
        self,
        *,
        utcnow: Any | None = None,
    ) -> None:
        self._utcnow = utcnow or (
            lambda: datetime.now(timezone.utc)
        )

    async def run(
        self,
        invocation: AgentInvocation,
    ) -> AgentOutcome:
        if (
            invocation.agent_name
            != AgentName.NOTIFICATION_REPORT
        ):
            return self._failed(
                "report_agent_name_mismatch",
                "NotificationReportAgent can only run as "
                "notification_report",
            )

        try:
            event, bundle, judge, rca = self._contracts(
                invocation
            )
            bundle_ref = self._unique_artifact_ref(
                invocation,
                "evidence_bundle",
            )
            judge_ref = self._unique_artifact_ref(
                invocation,
                "judge_result",
            )
            rca_ref = self._unique_artifact_ref(
                invocation,
                "rca_result",
            )
            rendered = render_report(
                event=event,
                bundle=bundle,
                judge=judge,
                rca=rca,
                bundle_ref=bundle_ref,
                judge_ref=judge_ref,
                rca_ref=rca_ref,
                generated_at=self._aware_now(),
            )
        except (
            ValueError,
            ValidationError,
            ReportRenderError,
        ) as exc:
            return self._failed(
                "report_input_or_render_failed",
                "Report inputs or compatibility rendering failed",
                details={
                    "exception_type": type(exc).__name__,
                },
            )

        output_ref = self._output_ref(
            rendered.report_artifact.model_dump(
                mode="json"
            )
        )
        return AgentOutcome(
            status=rendered.report_artifact.status,
            output_refs=(output_ref,),
            output={
                "report_artifact": (
                    rendered.report_artifact.model_dump(
                        mode="json"
                    )
                ),
                "compatibility_card": dict(
                    rendered.compatibility_card
                ),
                "evidence_hub_summary": dict(
                    rendered.evidence_hub_summary
                ),
                "renderer_version": RENDERER_VERSION,
                "notification_plan": {
                    "mode": "shadow_compatible",
                    "send_notification": False,
                    "notification_count": 0,
                    "second_card_sent": False,
                    "production_card_replaced": False,
                },
                "notification_sent": False,
                "evidence_hub_written": False,
                "glm_called": False,
                "mcp_called": False,
                "tool_called": False,
            },
            external_calls=(),
        )

    @staticmethod
    def _contracts(
        invocation: AgentInvocation,
    ) -> tuple[
        UnifiedAlertEvent,
        EvidenceBundle,
        EvidenceJudgeResult,
        RCAResult,
    ]:
        raw_event = _mapping(
            invocation.prior_outputs.get(
                AgentName.TRIAGE.value
            )
        ).get("unified_event")
        raw_bundle = _mapping(
            invocation.prior_outputs.get(
                "evidence_bundle"
            )
        ).get("evidence_bundle")
        raw_judge = _mapping(
            invocation.prior_outputs.get(
                AgentName.EVIDENCE_JUDGE.value
            )
        ).get("judge_result")
        raw_rca = _mapping(
            invocation.prior_outputs.get(
                AgentName.RCA.value
            )
        ).get("rca_result")

        for label, payload in (
            ("UnifiedAlertEvent", raw_event),
            ("EvidenceBundle", raw_bundle),
            ("EvidenceJudgeResult", raw_judge),
            ("RCAResult", raw_rca),
        ):
            if not isinstance(payload, Mapping):
                raise ValueError(f"{label} is missing")

        event = UnifiedAlertEvent.model_validate(raw_event)
        bundle = EvidenceBundle.model_validate(raw_bundle)
        judge = EvidenceJudgeResult.model_validate(
            raw_judge
        )
        rca = RCAResult.model_validate(raw_rca)

        request_ids = {
            invocation.request_id,
            event.request_id,
            bundle.request_id,
            judge.request_id,
            rca.request_id,
        }
        if request_ids != {invocation.request_id}:
            raise ValueError(
                "Report input request_id mismatch"
            )
        return event, bundle, judge, rca

    @staticmethod
    def _unique_artifact_ref(
        invocation: AgentInvocation,
        kind: str,
    ) -> str:
        matches: list[str] = []
        for reference in invocation.prior_output_refs:
            parsed = parse_contract_ref(reference)
            if (
                parsed["scheme"] == "artifact"
                and parsed["kind"] == kind
            ):
                if (
                    parsed["request_id"]
                    != invocation.request_id
                ):
                    raise ValueError(
                        "Report artifact request_id mismatch"
                    )
                matches.append(reference)

        if len(matches) != 1:
            raise ValueError(
                f"expected one artifact ref for {kind}"
            )
        return matches[0]

    @staticmethod
    def _output_ref(
        report_payload: Mapping[str, Any],
    ) -> str:
        request_id = str(report_payload["request_id"])
        digest = hashlib.sha256(
            stable_json_dumps(report_payload).encode(
                "utf-8"
            )
        ).hexdigest()[:16]
        return build_contract_ref(
            "report",
            request_id,
            "report_artifact",
            f"report-{digest}",
        )

    def _aware_now(self) -> datetime:
        value = self._utcnow()
        if (
            value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise ValueError(
                "utcnow provider must return "
                "a timezone-aware datetime"
            )
        return value

    @staticmethod
    def _failed(
        code: str,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> AgentOutcome:
        notice = _notice(
            code,
            message,
            details=details,
        )
        return AgentOutcome(
            status=AgentStatus.FAILED,
            output={
                "renderer_version": RENDERER_VERSION,
                "notification_plan": {
                    "mode": "shadow_compatible",
                    "send_notification": False,
                    "notification_count": 0,
                    "second_card_sent": False,
                    "production_card_replaced": False,
                },
                "notification_sent": False,
                "evidence_hub_written": False,
                "glm_called": False,
                "mcp_called": False,
                "tool_called": False,
            },
            errors=(notice,),
            external_calls=(),
        )
