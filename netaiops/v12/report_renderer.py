"""Backward-compatible v12 ReportArtifact and current-card renderer."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from .contracts import (
    EvidenceBundle,
    EvidenceJudgeResult,
    RCAResult,
    ReportArtifact,
    ReportSection,
    UnifiedAlertEvent,
)
from .schema_validator import parse_contract_ref
from .status import (
    AgentStatus,
    AlertLifecycleStatus,
    EvidenceStatus,
    JudgeStatus,
)


RENDERER_VERSION = "v12-current-card-compat-1"
CURRENT_CARD_KEYS = (
    "title",
    "alert_status",
    "device",
    "alert_object",
    "alert_content",
    "current_judgment",
    "recommendations",
    "evidence_summary",
    "evidence_url",
)
_REPORT_SECTION_KEYS = (
    "alert_status",
    "device",
    "alert_object",
    "alert_content",
    "current_judgment",
    "recommendations",
    "evidence_summary",
)
_STATUS_TEXT = {
    EvidenceStatus.SUCCESS: "可用",
    EvidenceStatus.PARTIAL: "部分可用",
    EvidenceStatus.NO_DATA: "指定窗口未命中",
    EvidenceStatus.FAILED: "查询失败",
    EvidenceStatus.SKIPPED: "已跳过",
    EvidenceStatus.NOT_AVAILABLE: "未启用/不可用",
}


class ReportRenderError(ValueError):
    """Raised when incompatible inputs cannot be rendered safely."""


@dataclass(frozen=True, slots=True)
class RenderedReport:
    report_artifact: ReportArtifact
    compatibility_card: Mapping[str, Any]
    evidence_hub_summary: Mapping[str, Any]


def _clean_text(value: Any, *, limit: int = 512) -> str:
    text = " ".join(str(value or "").split())
    if not text:
        return "-"
    if len(text) <= limit:
        return text
    return text[: max(1, limit - 1)].rstrip() + "…"


def _device_text(event: UnifiedAlertEvent) -> str:
    name = _clean_text(event.device.name, limit=180)
    ip = _clean_text(event.device.ip, limit=180)
    if name != "-" and ip != "-":
        return _clean_text(f"{name} ({ip})", limit=512)
    return name if name != "-" else ip


def _alert_content(event: UnifiedAlertEvent) -> str:
    for key in ("summary", "description", "message"):
        value = event.annotations.get(key)
        if value:
            return _clean_text(value)
    return _clean_text(event.alert_name)


def _recommendations(
    event: UnifiedAlertEvent,
    bundle: EvidenceBundle,
    judge: EvidenceJudgeResult,
    rca: RCAResult,
) -> list[str]:
    if event.alert_status == AlertLifecycleStatus.RESOLVED:
        items = [
            "确认业务和设备状态持续稳定。",
            "在 Evidence Hub 查看完整证据与缺失项。",
        ]
    elif judge.status == JudgeStatus.BLOCKED:
        items = [
            "先处理证据冲突，再确认根因。",
            "在 Evidence Hub 查看冲突来源与完整引用。",
        ]
    elif judge.status == JudgeStatus.INSUFFICIENT:
        items = [
            "补充必要证据后再确认根因。",
            "在 Evidence Hub 查看完整证据与缺失项。",
        ]
    elif rca.candidates:
        items = [
            "按现有生产流程核实候选原因，不自动执行任何操作。",
            "在 Evidence Hub 查看完整证据与引用。",
        ]
    else:
        items = [
            "继续沿用现有生产处置流程。",
            "在 Evidence Hub 查看完整证据与缺失项。",
        ]

    if (
        bundle.evidence.logs.status
        != EvidenceStatus.SUCCESS
        or bundle.evidence.knowledge.status
        != EvidenceStatus.SUCCESS
    ):
        items.append(
            "日志或知识上下文未启用，不得据此判断为正常。"
        )
    return items[:3]


def _recommendation_text(values: list[str]) -> str:
    return "\n".join(
        f"{index}. {_clean_text(value, limit=450)}"
        for index, value in enumerate(values, start=1)
    )


def _evidence_summary(bundle: EvidenceBundle) -> str:
    return (
        f"指标：{_STATUS_TEXT[bundle.evidence.metrics.status]}；"
        f"设备：{_STATUS_TEXT[bundle.evidence.device.status]}；"
        f"日志：{_STATUS_TEXT[bundle.evidence.logs.status]}；"
        f"知识：{_STATUS_TEXT[bundle.evidence.knowledge.status]}。"
    )


def _current_judgment(
    event: UnifiedAlertEvent,
    judge: EvidenceJudgeResult,
    rca: RCAResult,
) -> str:
    if rca.candidates:
        candidate = rca.candidates[0]
        judgment = (
            f"候选根因：{candidate.statement}"
            f"（置信度 {candidate.confidence:.0%}）"
        )
    elif judge.status == JudgeStatus.BLOCKED:
        judgment = (
            "结构化证据存在冲突，当前阻止 RCA；"
            "沿用现有生产分析与处置流程。"
        )
    elif judge.status == JudgeStatus.INSUFFICIENT:
        judgment = (
            "必要证据不足，当前无法形成可靠 RCA；"
            "沿用现有生产分析与处置流程。"
        )
    elif judge.status == JudgeStatus.READY:
        judgment = (
            "证据已满足 RCA 条件，但 v12 RCA 默认关闭；"
            "沿用现有生产分析结果。"
        )
    else:
        judgment = (
            "当前证据仅支持保守判断；"
            "缺失项已在 Evidence Hub 标记。"
        )

    if event.alert_status == AlertLifecycleStatus.RESOLVED:
        judgment = f"告警已恢复；{judgment}"
    return _clean_text(judgment)


def _evidence_refs(
    judge: EvidenceJudgeResult,
    rca: RCAResult,
) -> list[str]:
    refs = list(judge.evidence_refs)
    for candidate in rca.candidates:
        refs.extend(candidate.supporting_evidence_refs)
        refs.extend(candidate.contradicting_evidence_refs)
    return sorted(set(refs))


def _validate_artifact_ref(
    value: str,
    *,
    request_id: str,
    kind: str,
) -> None:
    parsed = parse_contract_ref(value)
    if parsed["request_id"] != request_id:
        raise ReportRenderError(
            f"{kind} artifact reference request_id mismatch"
        )
    if parsed["scheme"] != "artifact" or parsed["kind"] != kind:
        raise ReportRenderError(
            f"expected artifact reference kind: {kind}"
        )


def _report_status(
    judge: EvidenceJudgeResult,
    rca: RCAResult,
) -> AgentStatus:
    if (
        judge.status == JudgeStatus.READY
        and rca.status == AgentStatus.SUCCESS
    ):
        return AgentStatus.SUCCESS
    return AgentStatus.PARTIAL


def render_report(
    *,
    event: UnifiedAlertEvent,
    bundle: EvidenceBundle,
    judge: EvidenceJudgeResult,
    rca: RCAResult,
    bundle_ref: str,
    judge_ref: str,
    rca_ref: str,
    generated_at: datetime,
) -> RenderedReport:
    """Render current card semantics without sending any notification."""

    request_ids = {
        event.request_id,
        bundle.request_id,
        judge.request_id,
        rca.request_id,
    }
    if request_ids != {event.request_id}:
        raise ReportRenderError(
            "Report inputs must use one request_id"
        )
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise ReportRenderError(
            "generated_at must be timezone-aware"
        )
    if bundle.event_ref != rca.event_ref:
        raise ReportRenderError(
            "RCAResult event_ref must match EvidenceBundle"
        )

    bundle_refs = {
        reference
        for envelope in (
            bundle.evidence.metrics,
            bundle.evidence.device,
            bundle.evidence.logs,
        )
        for reference in envelope.evidence_refs
    }
    if not set(judge.evidence_refs).issubset(bundle_refs):
        raise ReportRenderError(
            "JudgeResult evidence_refs must exist in EvidenceBundle"
        )

    _validate_artifact_ref(
        bundle_ref,
        request_id=event.request_id,
        kind="evidence_bundle",
    )
    _validate_artifact_ref(
        judge_ref,
        request_id=event.request_id,
        kind="judge_result",
    )
    _validate_artifact_ref(
        rca_ref,
        request_id=event.request_id,
        kind="rca_result",
    )
    if rca.bundle_ref != bundle_ref:
        raise ReportRenderError(
            "RCAResult bundle_ref mismatch"
        )
    if rca.judge_ref != judge_ref:
        raise ReportRenderError(
            "RCAResult judge_ref mismatch"
        )

    alert_status = (
        "恢复"
        if event.alert_status == AlertLifecycleStatus.RESOLVED
        else "告警"
    )
    device = _device_text(event)
    alert_object = _clean_text(
        f"{event.alert_object.kind}: {event.alert_object.name}"
    )
    alert_content = _alert_content(event)
    current_judgment = _current_judgment(
        event,
        judge,
        rca,
    )
    recommendations = _recommendation_text(
        _recommendations(event, bundle, judge, rca)
    )
    evidence_summary = _evidence_summary(bundle)
    evidence_url = f"/evidence-ui/{event.request_id}"
    title = _clean_text(
        f"[network][{alert_status}] {event.alert_name}"
    )

    compatibility_card = {
        "title": title,
        "alert_status": alert_status,
        "device": device,
        "alert_object": alert_object,
        "alert_content": alert_content,
        "current_judgment": current_judgment,
        "recommendations": recommendations,
        "evidence_summary": evidence_summary,
        "evidence_url": evidence_url,
    }
    if tuple(compatibility_card) != CURRENT_CARD_KEYS:
        raise ReportRenderError(
            "current card field order drifted"
        )

    evidence_hub_summary = {
        "request_id": event.request_id,
        "alert_name": _clean_text(event.alert_name),
        "alert_status": alert_status,
        "device": device,
        "alert_object": alert_object,
        "current_judgment": current_judgment,
        "recommendations": recommendations,
        "evidence_summary": evidence_summary,
        "details_url": evidence_url,
    }

    refs = _evidence_refs(judge, rca)
    section_values = {
        "alert_status": alert_status,
        "device": device,
        "alert_object": alert_object,
        "alert_content": alert_content,
        "current_judgment": current_judgment,
        "recommendations": recommendations,
        "evidence_summary": evidence_summary,
    }
    section_titles = {
        "alert_status": "告警状态",
        "device": "设备",
        "alert_object": "告警对象",
        "alert_content": "告警内容",
        "current_judgment": "当前判断",
        "recommendations": "处理建议",
        "evidence_summary": "证据摘要",
    }
    sections = [
        ReportSection(
            key=key,
            title=section_titles[key],
            body=_clean_text(
                section_values[key],
                limit=512,
            ),
            evidence_refs=(
                refs
                if key
                in {
                    "current_judgment",
                    "evidence_summary",
                }
                else []
            ),
        )
        for key in _REPORT_SECTION_KEYS
    ]

    report_artifact = ReportArtifact(
        schema_version="v12.1",
        request_id=event.request_id,
        status=_report_status(judge, rca),
        title=title,
        summary=current_judgment,
        sections=sections,
        evidence_refs=refs,
        artifact_refs=[
            bundle_ref,
            judge_ref,
            rca_ref,
        ],
        generated_at=generated_at,
        notification_compatible=True,
    )
    return RenderedReport(
        report_artifact=report_artifact,
        compatibility_card=compatibility_card,
        evidence_hub_summary=evidence_hub_summary,
    )
