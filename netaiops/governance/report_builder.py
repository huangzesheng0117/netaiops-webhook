"""Learning Report aggregation for NetAIOps Webhook v11 Governance.

Batch 6 reads only compact Governance records from a local GovernanceStore and
produces deterministic JSON/Markdown summaries for daily, weekly, or monthly
windows.  It never reads raw request artifacts, calls GLM/MCP/notification
endpoints, modifies Skill/Playbook files, or writes production configuration.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import date, datetime, time, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .contracts import (
    GOVERNANCE_SCHEMA_VERSION,
    LEARNING_SIGNAL_TYPES,
    ProposalStatus,
)
from .store import GovernanceStore, StorePage

REPORT_VERSION = "11.0.0-learning-report-v1"
REPORT_PERIODS = ("daily", "weekly", "monthly")
_COLLECTIONS = ("incident_memory", "signals", "proposals", "replays")
_REPLAY_OUTCOMES = ("improved", "unchanged", "regressed")
_ENVIRONMENT_SIGNAL_TYPES = frozenset({"logs_not_available"})


class LearningReportError(ValueError):
    """Raised when a Learning Report cannot be built safely."""


def _enum_value(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _jsonable(child) for key, child in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(child) for child in value]
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise LearningReportError("datetime values must include timezone information")
        return value.astimezone(timezone.utc).isoformat()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _aware_utc(value: datetime | None) -> datetime:
    result = value or datetime.now(timezone.utc)
    if result.tzinfo is None or result.utcoffset() is None:
        raise LearningReportError("created_at must include timezone information")
    return result.astimezone(timezone.utc)


def _anchor_date(value: date | str) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value or "").strip()
    try:
        return date.fromisoformat(text)
    except ValueError as exc:
        raise LearningReportError(f"invalid report date: {value!r}") from exc


def report_window(period: str, anchor: date | str) -> tuple[datetime, datetime]:
    """Return a half-open UTC report window ``[start, end)``."""

    period_name = str(period or "").strip().lower()
    if period_name not in REPORT_PERIODS:
        raise LearningReportError(
            f"invalid period: {period!r}; expected one of {', '.join(REPORT_PERIODS)}"
        )
    anchor_day = _anchor_date(anchor)
    if period_name == "daily":
        start_day = anchor_day
        end_day = anchor_day + timedelta(days=1)
    elif period_name == "weekly":
        start_day = anchor_day - timedelta(days=anchor_day.weekday())
        end_day = start_day + timedelta(days=7)
    else:
        start_day = anchor_day.replace(day=1)
        if start_day.month == 12:
            end_day = date(start_day.year + 1, 1, 1)
        else:
            end_day = date(start_day.year, start_day.month + 1, 1)
    return (
        datetime.combine(start_day, time.min, tzinfo=timezone.utc),
        datetime.combine(end_day, time.min, tzinfo=timezone.utc),
    )


def _parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _in_window(record: Mapping[str, Any], start: datetime, end: datetime) -> bool:
    created_at = _parse_timestamp(record.get("created_at"))
    return created_at is not None and start <= created_at < end


def _load_collection(
    store: GovernanceStore,
    collection: str,
    *,
    page_size: int = 500,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Read all valid records while deduplicating corruption diagnostics."""

    records: list[dict[str, Any]] = []
    error_map: dict[tuple[str, str], dict[str, str]] = {}
    page_number = 1
    while True:
        page: StorePage = store.list_records(
            collection,
            page=page_number,
            page_size=page_size,
            descending=False,
        )
        records.extend(dict(item) for item in page.items)
        for error in page.errors:
            key = (str(error.get("record_id", "")), str(error.get("path", "")))
            error_map[key] = dict(error)
        if not page.items or len(records) >= page.total:
            break
        page_number += 1
        if page_number > 100000:
            raise LearningReportError(f"pagination guard exceeded for {collection}")
    return records, list(error_map.values())


def _count_names(values: Iterable[Any], *, include: Sequence[str] = ()) -> dict[str, int]:
    counter = Counter(str(_enum_value(value) or "unknown") for value in values)
    for name in include:
        counter.setdefault(str(name), 0)
    return dict(sorted(counter.items()))


def _family_distribution(memories: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter(str(item.get("family") or "unknown") for item in memories)
    return [
        {"family": family, "count": count}
        for family, count in sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))
    ]


def _evidence_coverage(memories: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, int]]:
    by_source: dict[str, Counter[str]] = {}
    for memory in memories:
        evidence = memory.get("evidence_status")
        if not isinstance(evidence, Mapping):
            continue
        for source, status in evidence.items():
            by_source.setdefault(str(source), Counter())[str(_enum_value(status) or "unknown")] += 1
    return {
        source: dict(sorted(counter.items()))
        for source, counter in sorted(by_source.items())
    }


def _report_id(period: str, start: datetime, end: datetime) -> str:
    material = f"{REPORT_VERSION}|{period}|{start.isoformat()}|{end.isoformat()}".encode("utf-8")
    return f"report_{hashlib.sha256(material).hexdigest()[:24]}"


def _collection_stats(
    records: Mapping[str, Sequence[Mapping[str, Any]]],
    errors: Mapping[str, Sequence[Mapping[str, str]]],
) -> dict[str, Any]:
    return {
        name: {
            "valid_in_window": len(records.get(name, ())),
            "corrupt_total": len(errors.get(name, ())),
        }
        for name in _COLLECTIONS
    }


def _health_findings(report: Mapping[str, Any]) -> list[dict[str, str]]:
    summary = report.get("summary") if isinstance(report.get("summary"), Mapping) else {}
    findings: list[dict[str, str]] = []
    if int(summary.get("request_count", 0)) == 0:
        findings.append(
            {
                "level": "warning",
                "code": "no_incident_memory_in_window",
                "message": "No Incident Memory records were found in the selected report window.",
            }
        )
    if int(summary.get("issue_signal_count", 0)) > 0:
        findings.append(
            {
                "level": "info",
                "code": "governance_signals_present",
                "message": "Governance signals require review; no automatic change is applied.",
            }
        )
    if int(summary.get("replay_regression_count", 0)) > 0:
        findings.append(
            {
                "level": "warning",
                "code": "replay_regression_present",
                "message": "At least one offline Replay reported a quality regression.",
            }
        )
    if int(summary.get("replay_safety_regression_count", 0)) > 0:
        findings.append(
            {
                "level": "critical",
                "code": "replay_safety_regression_present",
                "message": "At least one offline Replay reported a safety regression.",
            }
        )
    if int(summary.get("logs_not_available_count", 0)) > 0:
        findings.append(
            {
                "level": "info",
                "code": "logs_coverage_not_available",
                "message": "Logs evidence is not available; this is coverage status, not a Webhook failure.",
            }
        )
    if int(summary.get("corrupt_record_count", 0)) > 0:
        findings.append(
            {
                "level": "warning",
                "code": "corrupt_governance_record_present",
                "message": "One or more Governance records were isolated as corrupt.",
            }
        )
    if not findings:
        findings.append(
            {
                "level": "info",
                "code": "governance_window_healthy",
                "message": "No blocking Governance issue was found in the selected report window.",
            }
        )
    return findings


def build_learning_report(
    governance_root: Path | str,
    *,
    period: str,
    anchor_date: date | str,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    """Aggregate Memory, Signal, Proposal, and Replay records into one report."""

    root = Path(governance_root).expanduser().resolve(strict=False)
    start, end = report_window(period, anchor_date)
    generated_at = _aware_utc(created_at)
    store = GovernanceStore(root)

    all_records: dict[str, list[dict[str, Any]]] = {}
    errors: dict[str, list[dict[str, str]]] = {}
    for collection in _COLLECTIONS:
        rows, collection_errors = _load_collection(store, collection)
        all_records[collection] = [row for row in rows if _in_window(row, start, end)]
        errors[collection] = collection_errors

    memories = all_records["incident_memory"]
    signals = all_records["signals"]
    proposals = all_records["proposals"]
    replays = all_records["replays"]

    signal_types = [str(item.get("signal_type") or "unknown") for item in signals]
    signal_counts = _count_names(signal_types, include=LEARNING_SIGNAL_TYPES)
    logs_count = signal_counts.get("logs_not_available", 0)
    issue_signal_count = sum(
        count for name, count in signal_counts.items() if name not in _ENVIRONMENT_SIGNAL_TYPES
    )
    proposal_status_counts = _count_names(
        (item.get("status") for item in proposals),
        include=tuple(status.value for status in ProposalStatus),
    )
    replay_outcomes = _count_names(
        (
            (item.get("quality_delta") or {}).get("outcome", "unknown")
            if isinstance(item.get("quality_delta"), Mapping)
            else "unknown"
            for item in replays
        ),
        include=_REPLAY_OUTCOMES,
    )
    safety_regressions = sum(
        1
        for item in replays
        if isinstance(item.get("safety_delta"), Mapping)
        and bool(item["safety_delta"].get("regression", False))
    )
    unique_request_ids = {
        str(item.get("request_id"))
        for item in memories
        if str(item.get("request_id") or "").strip()
    }
    corrupt_count = sum(len(value) for value in errors.values())

    report: dict[str, Any] = {
        "schema_version": GOVERNANCE_SCHEMA_VERSION,
        "report_version": REPORT_VERSION,
        "report_id": _report_id(str(period).lower(), start, end),
        "created_at": generated_at.isoformat(),
        "period": str(period).lower(),
        "window": {
            "anchor_date": _anchor_date(anchor_date).isoformat(),
            "start": start.isoformat(),
            "end_exclusive": end.isoformat(),
            "timezone": "UTC",
        },
        "source": {
            "governance_root": str(root),
            "collections": list(_COLLECTIONS),
            "external_calls": {
                "glm": False,
                "prometheus": False,
                "device": False,
                "notification": False,
            },
            "production_write": False,
        },
        "summary": {
            "request_count": len(unique_request_ids),
            "memory_count": len(memories),
            "signal_count": len(signals),
            "issue_signal_count": issue_signal_count,
            "logs_not_available_count": logs_count,
            "proposal_count": len(proposals),
            "replay_count": len(replays),
            "replay_improved_count": replay_outcomes.get("improved", 0),
            "replay_unchanged_count": replay_outcomes.get("unchanged", 0),
            "replay_regression_count": replay_outcomes.get("regressed", 0),
            "replay_safety_regression_count": safety_regressions,
            "corrupt_record_count": corrupt_count,
        },
        "family_distribution": _family_distribution(memories),
        "signal_counts": signal_counts,
        "proposal_status_counts": proposal_status_counts,
        "replay_outcome_counts": replay_outcomes,
        "replay_safety": {
            "regression_count": safety_regressions,
            "no_regression_count": len(replays) - safety_regressions,
        },
        "evidence_coverage": _evidence_coverage(memories),
        "collection_stats": _collection_stats(all_records, errors),
        "corrupt_records": {
            name: [
                {
                    "record_id": str(item.get("record_id", "")),
                    "error": str(item.get("error", ""))[:500],
                }
                for item in errors[name]
            ]
            for name in _COLLECTIONS
        },
        "governance_boundaries": {
            "automatic_skill_or_playbook_change": False,
            "automatic_proposal_execution": False,
            "external_calls_performed": False,
            "logs_not_available_is_webhook_failure": False,
        },
    }
    report["findings"] = _health_findings(report)
    return _jsonable(report)


def _markdown_table(rows: Sequence[Sequence[Any]], headers: Sequence[str]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(value).replace("|", "\\|") for value in row) + " |")
    return lines


def render_learning_report_markdown(report: Mapping[str, Any]) -> str:
    """Render a deterministic Markdown view from the JSON report payload."""

    summary = report.get("summary") if isinstance(report.get("summary"), Mapping) else {}
    window = report.get("window") if isinstance(report.get("window"), Mapping) else {}
    lines = [
        "# NetAIOps Webhook v11 Learning Report",
        "",
        f"- Report ID: `{report.get('report_id', '')}`",
        f"- Period: `{report.get('period', '')}`",
        f"- Window: `{window.get('start', '')}` to `{window.get('end_exclusive', '')}` (UTC, end exclusive)",
        f"- Generated at: `{report.get('created_at', '')}`",
        "",
        "## Summary",
        "",
    ]
    summary_rows = [
        ("Requests", summary.get("request_count", 0)),
        ("Incident Memory", summary.get("memory_count", 0)),
        ("Learning Signals", summary.get("signal_count", 0)),
        ("Issue Signals", summary.get("issue_signal_count", 0)),
        ("Logs not available", summary.get("logs_not_available_count", 0)),
        ("Proposals", summary.get("proposal_count", 0)),
        ("Replays", summary.get("replay_count", 0)),
        ("Replay improved", summary.get("replay_improved_count", 0)),
        ("Replay unchanged", summary.get("replay_unchanged_count", 0)),
        ("Replay regressed", summary.get("replay_regression_count", 0)),
        ("Replay safety regression", summary.get("replay_safety_regression_count", 0)),
        ("Corrupt records", summary.get("corrupt_record_count", 0)),
    ]
    lines.extend(_markdown_table(summary_rows, ("Metric", "Count")))

    lines.extend(["", "## Family Distribution", ""])
    family_rows = [
        (item.get("family", "unknown"), item.get("count", 0))
        for item in report.get("family_distribution", [])
        if isinstance(item, Mapping)
    ]
    lines.extend(_markdown_table(family_rows or [("(none)", 0)], ("Family", "Count")))

    lines.extend(["", "## Learning Signals", ""])
    signal_counts = report.get("signal_counts") if isinstance(report.get("signal_counts"), Mapping) else {}
    lines.extend(
        _markdown_table(
            [(name, signal_counts[name]) for name in sorted(signal_counts)],
            ("Signal Type", "Count"),
        )
    )
    lines.extend(
        [
            "",
            "> `logs_not_available` is a data-source coverage status and is not counted as a Webhook failure.",
        ]
    )

    lines.extend(["", "## Proposal Status", ""])
    proposal_counts = (
        report.get("proposal_status_counts")
        if isinstance(report.get("proposal_status_counts"), Mapping)
        else {}
    )
    lines.extend(
        _markdown_table(
            [(name, proposal_counts[name]) for name in sorted(proposal_counts)],
            ("Status", "Count"),
        )
    )

    lines.extend(["", "## Replay Outcomes", ""])
    replay_counts = (
        report.get("replay_outcome_counts")
        if isinstance(report.get("replay_outcome_counts"), Mapping)
        else {}
    )
    lines.extend(
        _markdown_table(
            [(name, replay_counts[name]) for name in sorted(replay_counts)],
            ("Outcome", "Count"),
        )
    )

    lines.extend(["", "## Evidence Coverage", ""])
    coverage = report.get("evidence_coverage") if isinstance(report.get("evidence_coverage"), Mapping) else {}
    coverage_rows: list[tuple[str, str, int]] = []
    for source in sorted(coverage):
        statuses = coverage[source]
        if isinstance(statuses, Mapping):
            for status in sorted(statuses):
                coverage_rows.append((source, status, int(statuses[status])))
    lines.extend(
        _markdown_table(coverage_rows or [("(none)", "(none)", 0)], ("Source", "Status", "Count"))
    )

    lines.extend(["", "## Findings", ""])
    findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    if findings:
        for item in findings:
            if isinstance(item, Mapping):
                lines.append(
                    f"- **{item.get('level', 'info')} / {item.get('code', '')}**: {item.get('message', '')}"
                )
    else:
        lines.append("- No findings.")

    lines.extend(
        [
            "",
            "## Governance Boundaries",
            "",
            "- No automatic Skill or Playbook modification.",
            "- No automatic Proposal execution.",
            "- No GLM, Prometheus MCP, Netmiko MCP, or notification call.",
            "- Report content is aggregated Governance metadata only.",
            "",
        ]
    )
    return "\n".join(lines)


def report_consistency_summary(report: Mapping[str, Any], markdown: str) -> dict[str, Any]:
    """Verify that every summary count is represented in Markdown."""

    summary = report.get("summary") if isinstance(report.get("summary"), Mapping) else {}
    expected = {
        "Requests": int(summary.get("request_count", 0)),
        "Incident Memory": int(summary.get("memory_count", 0)),
        "Learning Signals": int(summary.get("signal_count", 0)),
        "Issue Signals": int(summary.get("issue_signal_count", 0)),
        "Logs not available": int(summary.get("logs_not_available_count", 0)),
        "Proposals": int(summary.get("proposal_count", 0)),
        "Replays": int(summary.get("replay_count", 0)),
        "Replay improved": int(summary.get("replay_improved_count", 0)),
        "Replay unchanged": int(summary.get("replay_unchanged_count", 0)),
        "Replay regressed": int(summary.get("replay_regression_count", 0)),
        "Replay safety regression": int(summary.get("replay_safety_regression_count", 0)),
        "Corrupt records": int(summary.get("corrupt_record_count", 0)),
    }
    missing = [
        label
        for label, count in expected.items()
        if f"| {label} | {count} |" not in markdown
    ]
    return {
        "consistent": not missing,
        "checked_metrics": len(expected),
        "missing_metrics": missing,
    }


__all__ = [
    "LearningReportError",
    "REPORT_PERIODS",
    "REPORT_VERSION",
    "build_learning_report",
    "render_learning_report_markdown",
    "report_consistency_summary",
    "report_window",
]
