"""Deterministic before/after comparison helpers for v11 offline replay.

The comparer consumes compact governance snapshots only.  It never reads raw
request artifacts and never performs network, device, model, or notification
calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

REPLAY_COMPARE_VERSION = "11.0.0-replay-compare-v1"
_COMPARE_FIELDS = (
    "classification",
    "selected_playbook",
    "policy",
    "evidence_status",
    "command_summary",
    "review_summary",
    "notification_summary",
    "quality_flags",
    "learning_signals",
    "proposals",
    "safety",
)


def _json_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _json_value(child) for key, child in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_value(child) for child in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    value = _json_value(value)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        if not value and prefix:
            result[prefix] = {}
        for key in sorted(value):
            path = f"{prefix}.{key}" if prefix else str(key)
            result.update(_flatten(value[key], path))
        return result
    if isinstance(value, list):
        if not value:
            return {prefix: []}
        result: dict[str, Any] = {}
        for index, child in enumerate(value):
            result.update(_flatten(child, f"{prefix}[{index}]"))
        return result
    return {prefix: value}


def compare_snapshots(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    """Return a bounded, deterministic structural diff for governed fields."""

    before_view = {field: _json_value(before.get(field)) for field in _COMPARE_FIELDS}
    after_view = {field: _json_value(after.get(field)) for field in _COMPARE_FIELDS}
    before_flat = _flatten(before_view)
    after_flat = _flatten(after_view)
    paths = sorted(set(before_flat) | set(after_flat))
    changes = [
        {
            "path": path,
            "before": before_flat.get(path),
            "after": after_flat.get(path),
        }
        for path in paths
        if before_flat.get(path) != after_flat.get(path)
    ]
    changed_roots = sorted({item["path"].split(".", 1)[0].split("[", 1)[0] for item in changes})
    return {
        "compare_version": REPLAY_COMPARE_VERSION,
        "changed": bool(changes),
        "change_count": len(changes),
        "changed_fields": changed_roots,
        "changes": changes,
    }


def _int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _status(value: Any) -> str:
    if isinstance(value, Enum):
        return str(value.value)
    return str(value or "").strip().lower()


def _flag_set(snapshot: Mapping[str, Any]) -> set[str]:
    value = snapshot.get("quality_flags")
    if not isinstance(value, (list, tuple, set, frozenset)):
        return set()
    return {str(item).strip() for item in value if str(item).strip()}


def quality_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Calculate a transparent quality score from compact replay fields."""

    flags = _flag_set(snapshot)
    penalised_flags = {
        "classification_fallback": 10,
        "playbook_missing": 10,
        "policy_blocked": 20,
        "prometheus_not_configured": 6,
        "prometheus_no_data": 6,
        "prometheus_failed": 12,
        "command_failed": 12,
        "cli_hard_error": 15,
        "review_missing_evidence": 10,
        "notification_failed": 10,
        "runner_false_negative": 12,
        "model_parse_failed": 15,
    }
    penalties: dict[str, int] = {
        f"flag:{flag}": points for flag, points in penalised_flags.items() if flag in flags
    }

    command = snapshot.get("command_summary")
    command = command if isinstance(command, Mapping) else {}
    failed = _int(command.get("failed"))
    hard_errors = _int(command.get("hard_error_count"))
    if failed:
        penalties["command_failed_count"] = min(20, failed * 4)
    if hard_errors:
        penalties["cli_hard_error_count"] = min(20, hard_errors * 5)

    evidence = snapshot.get("evidence_status")
    evidence = evidence if isinstance(evidence, Mapping) else {}
    evidence_success = 0
    evidence_gap = 0
    for source, raw in evidence.items():
        status = _status(raw)
        if status in {"success", "ok", "completed", "found"}:
            evidence_success += 1
        elif status in {"failed", "error"}:
            evidence_gap += 1
            penalties[f"evidence:{source}:failed"] = 8
        elif status in {"partial", "warning"}:
            evidence_gap += 1
            penalties[f"evidence:{source}:partial"] = 2
        elif status in {"no_data", "not_configured", "missing", "skipped"}:
            evidence_gap += 1
            penalties[f"evidence:{source}:{status}"] = 4
        elif status == "not_available":
            # Logs not_available is an environment coverage state, not a failure.
            continue

    score = max(0, 100 - sum(penalties.values()))
    return {
        "score": score,
        "penalties": dict(sorted(penalties.items())),
        "penalty_total": sum(penalties.values()),
        "quality_flags": sorted(flags),
        "non_environment_issue_count": len(flags - {"logs_not_available"}),
        "evidence_success_count": evidence_success,
        "evidence_gap_count": evidence_gap,
        "command_failed_count": failed,
        "cli_hard_error_count": hard_errors,
    }


def compare_quality(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    before_quality = quality_snapshot(before)
    after_quality = quality_snapshot(after)
    delta = after_quality["score"] - before_quality["score"]
    before_flags = set(before_quality["quality_flags"])
    after_flags = set(after_quality["quality_flags"])
    return {
        "before": before_quality,
        "after": after_quality,
        "score_delta": delta,
        "outcome": "improved" if delta > 0 else "regressed" if delta < 0 else "unchanged",
        "resolved_flags": sorted(before_flags - after_flags),
        "introduced_flags": sorted(after_flags - before_flags),
    }


def safety_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    safety = snapshot.get("safety")
    safety = safety if isinstance(safety, Mapping) else {}
    calls = safety.get("external_calls")
    calls = calls if isinstance(calls, Mapping) else {}
    enabled_calls = sorted(str(key) for key, value in calls.items() if bool(value))
    readonly_only = bool(safety.get("readonly_only", False))
    auto_apply_count = _int(safety.get("proposal_auto_apply_count"))
    violations: list[str] = []
    if enabled_calls:
        violations.extend(f"external_call:{name}" for name in enabled_calls)
    if not readonly_only:
        violations.append("readonly_only_false")
    if auto_apply_count:
        violations.append("proposal_auto_apply_enabled")
    score = max(0, 100 - len(enabled_calls) * 50 - (0 if readonly_only else 40) - auto_apply_count * 100)
    return {
        "safe": not violations,
        "score": score,
        "violations": violations,
        "external_calls_enabled": enabled_calls,
        "readonly_only": readonly_only,
        "proposal_auto_apply_count": auto_apply_count,
    }


def compare_safety(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    before_safety = safety_snapshot(before)
    after_safety = safety_snapshot(after)
    before_violations = set(before_safety["violations"])
    after_violations = set(after_safety["violations"])
    introduced = sorted(after_violations - before_violations)
    resolved = sorted(before_violations - after_violations)
    score_delta = after_safety["score"] - before_safety["score"]
    return {
        "before": before_safety,
        "after": after_safety,
        "score_delta": score_delta,
        "regression": bool(introduced or score_delta < 0),
        "introduced_violations": introduced,
        "resolved_violations": resolved,
    }


def build_replay_comparison(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "diff": compare_snapshots(before, after),
        "quality_delta": compare_quality(before, after),
        "safety_delta": compare_safety(before, after),
    }


__all__ = [
    "REPLAY_COMPARE_VERSION",
    "build_replay_comparison",
    "compare_quality",
    "compare_safety",
    "compare_snapshots",
    "quality_snapshot",
    "safety_snapshot",
]
