"""Validation and evidence-grounding rules for v12 RCA output."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Mapping

from pydantic import Field, ValidationError

from .contracts import (
    EvidenceBundle,
    EvidenceJudgeResult,
    RCACandidate,
    RCAResult,
    StrictContractModel,
)
from .schema_validator import parse_contract_ref
from .status import (
    AgentStatus,
    EvidenceStatus,
    JudgeStatus,
)


class RCAValidationError(ValueError):
    """Raised when a Mock GLM response is not evidence-grounded."""


class _RCAResponse(StrictContractModel):
    candidates: list[RCACandidate] = Field(min_length=1, max_length=3)
    missing_evidence: list[str]
    uncertainties: list[str] = Field(min_length=1)


def _unique_strings(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value).strip()
        if text and text not in seen:
            output.append(text)
            seen.add(text)
    return output


def bundle_evidence_refs(bundle: EvidenceBundle) -> list[str]:
    refs: list[str] = []
    for envelope in (
        bundle.evidence.metrics,
        bundle.evidence.device,
        bundle.evidence.logs,
    ):
        refs.extend(envelope.evidence_refs)
    output = sorted(set(refs))
    for reference in output:
        parsed = parse_contract_ref(reference)
        if parsed["request_id"] != bundle.request_id:
            raise RCAValidationError(
                "EvidenceBundle contains a foreign evidence_ref"
            )
    return output


def inherited_missing_evidence(
    judge: EvidenceJudgeResult,
) -> list[str]:
    values = [
        *(
            source.value
            for source in judge.missing_required_sources
        ),
        *(
            source.value
            for source in judge.missing_optional_sources
        ),
    ]
    return _unique_strings(values)


def _parse_response(value: Any) -> Mapping[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise RCAValidationError(
                "Mock GLM response is not valid JSON"
            ) from exc
    if not isinstance(value, Mapping):
        raise RCAValidationError(
            "Mock GLM response root must be an object"
        )
    return value


def _contains_any(text: str, tokens: tuple[str, ...]) -> bool:
    normalized = " ".join(str(text).lower().split())
    return any(token in normalized for token in tokens)


def _reject_unsupported_claims(
    statement: str,
    *,
    logs_success: bool,
) -> None:
    if not logs_success and _contains_any(
        statement,
        (
            "logs are normal",
            "logs normal",
            "log is normal",
            "no log anomalies",
            "no abnormal logs",
            "日志正常",
            "日志无异常",
            "未发现日志异常",
            "日志没有异常",
        ),
    ):
        raise RCAValidationError(
            "RCA cannot claim Logs are normal when Logs are unavailable"
        )

    if _contains_any(
        statement,
        (
            "command output shows",
            "cli output shows",
            "executed command shows",
            "show command returned",
            "show command output",
            "命令输出显示",
            "执行命令后发现",
            "执行了命令",
        ),
    ):
        raise RCAValidationError(
            "RCA cannot invent or restate unsupported command execution"
        )

    if _contains_any(
        statement,
        (
            "knowledge confirms current",
            "knowledge proves current",
            "knowledge base confirms current",
            "knowledge base proves current",
            "知识库确认当前",
            "知识库证明当前",
        ),
    ):
        raise RCAValidationError(
            "Knowledge Context cannot substitute for real-time evidence"
        )


def validate_rca_response(
    response: Any,
    *,
    bundle: EvidenceBundle,
    judge: EvidenceJudgeResult,
    event_ref: str,
    bundle_ref: str,
    judge_ref: str,
    generated_at: datetime,
    provider: str,
) -> RCAResult:
    """Validate a Mock GLM response and build the frozen RCAResult."""

    if not judge.rca_allowed:
        raise RCAValidationError(
            "JudgeResult does not allow RCA generation"
        )
    if judge.status in {
        JudgeStatus.INSUFFICIENT,
        JudgeStatus.BLOCKED,
    }:
        raise RCAValidationError(
            "insufficient or blocked evidence cannot generate RCA"
        )
    if bundle.request_id != judge.request_id:
        raise RCAValidationError(
            "EvidenceBundle and JudgeResult request_id mismatch"
        )

    raw = _parse_response(response)
    required_root_keys = {
        "candidates",
        "missing_evidence",
        "uncertainties",
    }
    if not required_root_keys.issubset(raw):
        raise RCAValidationError(
            "Mock GLM response must declare candidates, "
            "missing_evidence, and uncertainties"
        )

    raw_candidates = raw.get("candidates")
    if not isinstance(raw_candidates, list):
        raise RCAValidationError("candidates must be a list")
    for index, candidate in enumerate(raw_candidates):
        if not isinstance(candidate, Mapping):
            raise RCAValidationError(
                f"candidate {index} must be an object"
            )
        for key in (
            "statement",
            "confidence",
            "supporting_evidence_refs",
            "missing_evidence",
            "uncertainties",
        ):
            if key not in candidate:
                raise RCAValidationError(
                    f"candidate {index} must declare {key}"
                )

    try:
        parsed = _RCAResponse.model_validate(raw)
    except ValidationError as exc:
        raise RCAValidationError(
            "Mock GLM response failed RCA response validation"
        ) from exc

    inherited = inherited_missing_evidence(judge)
    top_missing = _unique_strings(parsed.missing_evidence)
    if not set(inherited).issubset(top_missing):
        raise RCAValidationError(
            "RCAResult missing_evidence must inherit JudgeResult"
        )
    if not parsed.uncertainties:
        raise RCAValidationError(
            "RCAResult uncertainties must not be empty"
        )

    bundle_refs = set(bundle_evidence_refs(bundle))
    judge_refs = set(judge.evidence_refs)
    allowed_refs = bundle_refs & judge_refs
    if not allowed_refs:
        raise RCAValidationError(
            "JudgeResult does not expose usable evidence_refs"
        )

    logs_success = (
        bundle.evidence.logs.status == EvidenceStatus.SUCCESS
    )
    statements: set[str] = set()
    candidates: list[RCACandidate] = []

    for candidate in parsed.candidates:
        if candidate.statement in statements:
            raise RCAValidationError(
                "RCA candidates must have unique statements"
            )
        statements.add(candidate.statement)

        supporting = set(candidate.supporting_evidence_refs)
        contradicting = set(candidate.contradicting_evidence_refs)

        if not supporting:
            raise RCAValidationError(
                "each RCA candidate requires supporting evidence"
            )
        if not supporting.issubset(allowed_refs):
            raise RCAValidationError(
                "supporting_evidence_refs must exist in Bundle and Judge"
            )
        if not contradicting.issubset(allowed_refs):
            raise RCAValidationError(
                "contradicting_evidence_refs must exist in Bundle and Judge"
            )
        if supporting & contradicting:
            raise RCAValidationError(
                "supporting and contradicting evidence_refs must not overlap"
            )
        if candidate.confidence > judge.confidence_cap + 1e-12:
            raise RCAValidationError(
                "candidate confidence exceeds Judge confidence_cap"
            )
        if not set(inherited).issubset(
            _unique_strings(candidate.missing_evidence)
        ):
            raise RCAValidationError(
                "each candidate missing_evidence must inherit JudgeResult"
            )
        if not candidate.uncertainties:
            raise RCAValidationError(
                "each candidate uncertainties must not be empty"
            )

        _reject_unsupported_claims(
            candidate.statement,
            logs_success=logs_success,
        )
        candidates.append(candidate)

    status = (
        AgentStatus.SUCCESS
        if judge.status == JudgeStatus.READY
        else AgentStatus.PARTIAL
    )
    return RCAResult(
        schema_version="v12.1",
        request_id=bundle.request_id,
        status=status,
        event_ref=event_ref,
        bundle_ref=bundle_ref,
        judge_ref=judge_ref,
        candidates=candidates,
        missing_evidence=top_missing,
        uncertainties=_unique_strings(parsed.uncertainties),
        generated_at=generated_at,
        provider=provider,
    )
