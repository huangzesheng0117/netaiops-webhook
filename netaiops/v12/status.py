"""Shared status and identity enumerations for v12 contracts."""

from enum import Enum


class StringEnum(str, Enum):
    """Enum whose values serialize as stable lowercase strings."""

    def __str__(self) -> str:
        return self.value


class AgentStatus(StringEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"
    NOT_AVAILABLE = "not_available"


class EvidenceStatus(StringEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    NO_DATA = "no_data"
    FAILED = "failed"
    SKIPPED = "skipped"
    NOT_AVAILABLE = "not_available"


class JudgeStatus(StringEnum):
    READY = "ready"
    PARTIAL = "partial"
    INSUFFICIENT = "insufficient"
    BLOCKED = "blocked"


class EvidenceBundleStatus(StringEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    INSUFFICIENT = "insufficient"
    BLOCKED = "blocked"


class AlertLifecycleStatus(StringEnum):
    FIRING = "firing"
    RESOLVED = "resolved"


class AlertSource(StringEnum):
    ALERTMANAGER = "alertmanager"
    ELASTIC = "elastic"
    REPLAY = "replay"


class EvidenceSource(StringEnum):
    METRICS = "metrics"
    DEVICE = "device"
    LOGS = "logs"
    KNOWLEDGE = "knowledge"


class AgentName(StringEnum):
    TRIAGE = "triage"
    STATIC_PLANNER = "static_planner"
    METRICS_EVIDENCE = "metrics_evidence"
    DEVICE_EVIDENCE = "device_evidence"
    LOGS_EVIDENCE = "logs_evidence"
    KNOWLEDGE_CONTEXT = "knowledge_context"
    EVIDENCE_JUDGE = "evidence_judge"
    RCA = "rca"
    NOTIFICATION_REPORT = "notification_report"


class ExternalCallStatus(StringEnum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    NOT_AVAILABLE = "not_available"
