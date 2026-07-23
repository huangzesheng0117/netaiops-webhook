"""Evidence-grounded v12 RCA Agent using only an injected Mock GLM."""

from __future__ import annotations

import hashlib
import inspect
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol

from pydantic import ValidationError

from ..contracts import (
    ContractNotice,
    EvidenceBundle,
    EvidenceJudgeResult,
    RCAResult,
    UnifiedAlertEvent,
)
from ..execution_context import AgentInvocation, AgentOutcome
from ..rca_validator import (
    RCAValidationError,
    bundle_evidence_refs,
    inherited_missing_evidence,
    validate_rca_response,
)
from ..redaction import redact_for_persistence
from ..schema_validator import (
    build_contract_ref,
    parse_contract_ref,
    stable_json_dumps,
)
from ..status import AgentName, AgentStatus, JudgeStatus


PROMPT_VERSION = "rca_v1"
DEFAULT_PROMPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "prompts"
    / "rca_v1.txt"
)


class MockRCAClient(Protocol):
    """Narrow test-only Mock GLM interface."""

    provider: str

    async def generate(self, prompt: str) -> Mapping[str, Any] | str:
        """Return one structured RCA response without external calls."""


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
        stage="rca",
        retryable=False,
        details=dict(details or {}),
    )


class RCAAgent:
    """Generate RCA only when explicitly enabled with a Mock GLM."""

    def __init__(
        self,
        *,
        enabled: bool = False,
        client: MockRCAClient | None = None,
        utcnow: Any | None = None,
        prompt_path: str | Path | None = None,
    ) -> None:
        self.enabled = bool(enabled)
        self.client = client
        self._utcnow = utcnow or (
            lambda: datetime.now(timezone.utc)
        )
        self.prompt_path = Path(
            prompt_path or DEFAULT_PROMPT_PATH
        )

    async def run(self, invocation: AgentInvocation) -> AgentOutcome:
        if invocation.agent_name != AgentName.RCA:
            return self._failed(
                "rca_agent_name_mismatch",
                "RCAAgent can only run as rca",
            )

        try:
            event, bundle, judge = self._contracts(invocation)
            bundle_ref = self._unique_artifact_ref(
                invocation,
                "evidence_bundle",
            )
            judge_ref = self._unique_artifact_ref(
                invocation,
                "judge_result",
            )
        except (ValueError, ValidationError) as exc:
            return self._failed(
                "rca_input_contract_invalid",
                "RCA input contracts or references are invalid",
                details={"exception_type": type(exc).__name__},
            )

        if not self.enabled:
            result = self._skipped_result(
                bundle=bundle,
                judge=judge,
                bundle_ref=bundle_ref,
                judge_ref=judge_ref,
                reason="rca_disabled_by_default",
            )
            return self._result_outcome(
                result,
                mock_glm_called=False,
                prompt_sha256=None,
            )

        if (
            not judge.rca_allowed
            or judge.status in {
                JudgeStatus.INSUFFICIENT,
                JudgeStatus.BLOCKED,
            }
        ):
            result = self._skipped_result(
                bundle=bundle,
                judge=judge,
                bundle_ref=bundle_ref,
                judge_ref=judge_ref,
                reason=f"judge_status_{judge.status.value}",
            )
            return self._result_outcome(
                result,
                mock_glm_called=False,
                prompt_sha256=None,
            )

        if self.client is None:
            return self._failed(
                "rca_mock_client_missing",
                "enabled Batch K RCA requires an injected Mock GLM",
            )

        provider = str(
            getattr(self.client, "provider", "")
        ).strip()
        if not provider.startswith("mock-"):
            return self._failed(
                "rca_production_provider_forbidden",
                "Batch K only allows a provider beginning with mock-",
            )

        generate = getattr(self.client, "generate", None)
        if (
            generate is None
            or not callable(generate)
            or not inspect.iscoroutinefunction(generate)
        ):
            return self._failed(
                "rca_mock_client_invalid",
                "Mock GLM must provide async generate(prompt)",
            )

        try:
            prompt = self._render_prompt(
                event=event,
                bundle=bundle,
                judge=judge,
            )
        except (OSError, UnicodeError, ValueError) as exc:
            return self._failed(
                "rca_prompt_render_failed",
                "RCA prompt could not be rendered safely",
                details={"exception_type": type(exc).__name__},
            )

        try:
            response = await generate(prompt)
        except Exception as exc:
            return self._failed(
                "rca_mock_generation_failed",
                "Mock GLM generation failed",
                details={"exception_type": type(exc).__name__},
            )

        try:
            result = validate_rca_response(
                response,
                bundle=bundle,
                judge=judge,
                event_ref=bundle.event_ref,
                bundle_ref=bundle_ref,
                judge_ref=judge_ref,
                generated_at=self._aware_now(),
                provider=provider,
            )
        except (RCAValidationError, ValidationError) as exc:
            return self._failed(
                "rca_response_rejected",
                "Mock GLM RCA response failed evidence validation",
                details={"exception_type": type(exc).__name__},
            )

        prompt_sha256 = hashlib.sha256(
            prompt.encode("utf-8")
        ).hexdigest()
        return self._result_outcome(
            result,
            mock_glm_called=True,
            prompt_sha256=prompt_sha256,
        )

    @staticmethod
    def _contracts(
        invocation: AgentInvocation,
    ) -> tuple[
        UnifiedAlertEvent,
        EvidenceBundle,
        EvidenceJudgeResult,
    ]:
        raw_event = _mapping(
            invocation.prior_outputs.get(
                AgentName.TRIAGE.value
            )
        ).get("unified_event")
        if not isinstance(raw_event, Mapping):
            raise ValueError("UnifiedAlertEvent is missing")

        raw_bundle = _mapping(
            invocation.prior_outputs.get("evidence_bundle")
        ).get("evidence_bundle")
        if not isinstance(raw_bundle, Mapping):
            raise ValueError("EvidenceBundle is missing")

        raw_judge = _mapping(
            invocation.prior_outputs.get(
                AgentName.EVIDENCE_JUDGE.value
            )
        ).get("judge_result")
        if not isinstance(raw_judge, Mapping):
            raise ValueError("EvidenceJudgeResult is missing")

        event = UnifiedAlertEvent.model_validate(raw_event)
        bundle = EvidenceBundle.model_validate(raw_bundle)
        judge = EvidenceJudgeResult.model_validate(raw_judge)

        request_ids = {
            invocation.request_id,
            event.request_id,
            bundle.request_id,
            judge.request_id,
        }
        if request_ids != {invocation.request_id}:
            raise ValueError("RCA input request_id mismatch")
        if bundle.event_ref not in invocation.prior_output_refs:
            raise ValueError(
                "EvidenceBundle event_ref is absent from prior_output_refs"
            )
        if not set(judge.evidence_refs).issubset(
            bundle_evidence_refs(bundle)
        ):
            raise ValueError(
                "JudgeResult exposes evidence_refs outside EvidenceBundle"
            )
        return event, bundle, judge

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
                if parsed["request_id"] != invocation.request_id:
                    raise ValueError(
                        "RCA artifact reference request_id mismatch"
                    )
                matches.append(reference)
        if len(matches) != 1:
            raise ValueError(
                f"expected one artifact ref for {kind}"
            )
        return matches[0]

    def _render_prompt(
        self,
        *,
        event: UnifiedAlertEvent,
        bundle: EvidenceBundle,
        judge: EvidenceJudgeResult,
    ) -> str:
        template = self.prompt_path.read_text(encoding="utf-8")
        values = {
            "{{prompt_version}}": PROMPT_VERSION,
            "{{event_json}}": stable_json_dumps(
                redact_for_persistence(event)
            ),
            "{{bundle_json}}": stable_json_dumps(
                redact_for_persistence(bundle)
            ),
            "{{judge_json}}": stable_json_dumps(
                redact_for_persistence(judge)
            ),
            "{{allowed_evidence_refs_json}}": stable_json_dumps(
                sorted(
                    set(bundle_evidence_refs(bundle))
                    & set(judge.evidence_refs)
                )
            ),
            "{{inherited_missing_evidence_json}}": (
                stable_json_dumps(
                    inherited_missing_evidence(judge)
                )
            ),
            "{{confidence_cap}}": str(judge.confidence_cap),
        }
        rendered = template
        for token, value in values.items():
            if rendered.count(token) != 1:
                raise ValueError(
                    f"prompt token count must be one: {token}"
                )
            rendered = rendered.replace(token, value, 1)
        unresolved_tokens = (
            "{{prompt_version}}",
            "{{event_json}}",
            "{{bundle_json}}",
            "{{judge_json}}",
            "{{allowed_evidence_refs_json}}",
            "{{inherited_missing_evidence_json}}",
            "{{confidence_cap}}",
        )
        if any(token in rendered for token in unresolved_tokens):
            raise ValueError(
                "unresolved RCA prompt placeholder remains"
            )
        return rendered

    def _skipped_result(
        self,
        *,
        bundle: EvidenceBundle,
        judge: EvidenceJudgeResult,
        bundle_ref: str,
        judge_ref: str,
        reason: str,
    ) -> RCAResult:
        return RCAResult(
            schema_version="v12.1",
            request_id=bundle.request_id,
            status=AgentStatus.SKIPPED,
            event_ref=bundle.event_ref,
            bundle_ref=bundle_ref,
            judge_ref=judge_ref,
            candidates=[],
            missing_evidence=inherited_missing_evidence(judge),
            uncertainties=[reason],
            generated_at=self._aware_now(),
            provider=None,
        )

    def _result_outcome(
        self,
        result: RCAResult,
        *,
        mock_glm_called: bool,
        prompt_sha256: str | None,
    ) -> AgentOutcome:
        output_ref = self._output_ref(result)
        return AgentOutcome(
            status=result.status,
            output_refs=(output_ref,),
            output={
                "rca_result": result.model_dump(mode="json"),
                "prompt_version": PROMPT_VERSION,
                "prompt_sha256": prompt_sha256,
                "mock_glm_called": mock_glm_called,
                "production_glm_called": False,
                "mcp_called": False,
                "tool_called": False,
                "automatic_followup_queries": False,
            },
            external_calls=(),
        )

    @staticmethod
    def _output_ref(result: RCAResult) -> str:
        seed = stable_json_dumps(
            {
                "status": result.status.value,
                "provider": result.provider,
                "candidates": [
                    candidate.model_dump(mode="json")
                    for candidate in result.candidates
                ],
                "missing_evidence": result.missing_evidence,
                "uncertainties": result.uncertainties,
            }
        )
        digest = hashlib.sha256(
            seed.encode("utf-8")
        ).hexdigest()[:16]
        return build_contract_ref(
            "artifact",
            result.request_id,
            "rca_result",
            f"rca-{digest}",
        )

    def _aware_now(self) -> datetime:
        value = self._utcnow()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(
                "utcnow provider must return a timezone-aware datetime"
            )
        return value

    @staticmethod
    def _failed(
        code: str,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> AgentOutcome:
        notice = _notice(code, message, details=details)
        return AgentOutcome(
            status=AgentStatus.FAILED,
            output={
                "prompt_version": PROMPT_VERSION,
                "mock_glm_called": False,
                "production_glm_called": False,
                "mcp_called": False,
                "tool_called": False,
                "automatic_followup_queries": False,
            },
            errors=(notice,),
            external_calls=(),
        )
