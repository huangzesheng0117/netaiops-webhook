"""Deterministic quality gates for v12 sanitized historical replay."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .report_renderer import CURRENT_CARD_KEYS
from .schema_validator import parse_contract_ref

QUALITY_GATE_VERSION = "v12-historical-replay-gates-1"
HIGH_CONFIDENCE_THRESHOLD = 0.8
MINIMUM_SCENARIO_COUNT = 14
REQUIRED_CATEGORIES = frozenset(
    {
        "interface_status",
        "interface_utilization",
        "traffic_spike",
        "traffic_drop",
        "dci",
        "hardware",
        "bgp",
        "ospf",
        "bfd",
        "f5",
        "fortigate",
        "partial_evidence",
        "no_data",
        "not_available",
    }
)
_MISSING_STATUSES = frozenset(
    {"partial", "no_data", "failed", "skipped", "not_available"}
)
_UNSUPPORTED_NORMAL_CLAIMS = (
    "logs are normal",
    "logs normal",
    "no log anomalies",
    "no abnormal logs",
    "日志正常",
    "日志无异常",
    "未发现日志异常",
    "metrics are normal",
    "metrics normal",
    "no metric anomalies",
    "指标正常",
    "指标无异常",
    "未发现指标异常",
)


def _strings(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [str(item) for item in value if item is not None]


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _violation(
    code: str,
    message: str,
    *,
    scenario_id: str | None = None,
) -> dict[str, str | None]:
    return {
        "code": code,
        "scenario_id": scenario_id,
        "message": message,
    }


def _candidate_confidences(case: Mapping[str, Any]) -> list[float]:
    rca = _mapping(case.get("rca"))
    return [
        _float(item.get("confidence"))
        for item in rca.get("candidates", [])
        if isinstance(item, Mapping)
    ]


def _candidate_statements(case: Mapping[str, Any]) -> list[str]:
    rca = _mapping(case.get("rca"))
    return [
        str(item.get("statement") or "")
        for item in rca.get("candidates", [])
        if isinstance(item, Mapping)
    ]


def _missing_from_judge(case: Mapping[str, Any]) -> set[str]:
    judge = _mapping(case.get("judge"))
    return {
        *_strings(judge.get("missing_required_sources")),
        *_strings(judge.get("missing_optional_sources")),
    }


def evaluate_quality_gates(
    cases: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Evaluate frozen Batch O gates without external calls."""

    case_list = [dict(case) for case in cases]
    violations: list[dict[str, str | None]] = []
    observed_categories = {
        str(case.get("category") or "")
        for case in case_list
        if case.get("category")
    }
    scenario_ids = [str(case.get("scenario_id") or "") for case in case_list]

    if len(case_list) < MINIMUM_SCENARIO_COUNT:
        violations.append(
            _violation(
                "scenario_count_below_minimum",
                f"expected at least {MINIMUM_SCENARIO_COUNT} scenarios, got {len(case_list)}",
            )
        )

    missing_categories = sorted(REQUIRED_CATEGORIES - observed_categories)
    if missing_categories:
        violations.append(
            _violation(
                "required_categories_missing",
                "missing categories: " + ", ".join(missing_categories),
            )
        )

    if len(scenario_ids) != len(set(scenario_ids)):
        violations.append(
            _violation(
                "duplicate_scenario_id",
                "scenario_id values must be unique",
            )
        )

    for case in case_list:
        scenario_id = str(case.get("scenario_id") or "")
        request_id = str(case.get("request_id") or "")
        expected = _mapping(case.get("expected"))
        judge = _mapping(case.get("judge"))
        rca = _mapping(case.get("rca"))
        report = _mapping(case.get("report"))
        source_statuses = _mapping(case.get("source_statuses"))
        source_required = _mapping(case.get("source_required"))

        if case.get("execution_error"):
            violations.append(
                _violation(
                    "replay_execution_error",
                    str(case.get("execution_error")),
                    scenario_id=scenario_id,
                )
            )
            continue

        if not bool(case.get("deterministic", False)):
            violations.append(
                _violation(
                    "replay_not_deterministic",
                    "same fixture produced different replay results",
                    scenario_id=scenario_id,
                )
            )

        if str(judge.get("status") or "") != str(expected.get("judge_status") or ""):
            violations.append(
                _violation(
                    "judge_status_mismatch",
                    f"expected {expected.get('judge_status')}, got {judge.get('status')}",
                    scenario_id=scenario_id,
                )
            )

        if str(rca.get("status") or "") != str(expected.get("rca_status") or ""):
            violations.append(
                _violation(
                    "rca_status_mismatch",
                    f"expected {expected.get('rca_status')}, got {rca.get('status')}",
                    scenario_id=scenario_id,
                )
            )

        for reference in _strings(case.get("all_refs")):
            try:
                parsed = parse_contract_ref(reference)
            except Exception as exc:
                violations.append(
                    _violation(
                        "reference_not_parseable",
                        f"{reference!r}: {type(exc).__name__}",
                        scenario_id=scenario_id,
                    )
                )
                continue
            if parsed["request_id"] != request_id:
                violations.append(
                    _violation(
                        "reference_request_id_mismatch",
                        reference,
                        scenario_id=scenario_id,
                    )
                )

        required_missing = [
            source
            for source, required in source_required.items()
            if bool(required)
            and str(source_statuses.get(source) or "") in _MISSING_STATUSES
        ]
        max_confidence = max(_candidate_confidences(case), default=0.0)
        if required_missing and max_confidence >= HIGH_CONFIDENCE_THRESHOLD:
            violations.append(
                _violation(
                    "required_missing_high_confidence",
                    "required sources missing: "
                    + ", ".join(sorted(required_missing))
                    + f"; max confidence={max_confidence}",
                    scenario_id=scenario_id,
                )
            )

        inherited_missing = _missing_from_judge(case)
        rca_missing = set(_strings(rca.get("missing_evidence")))
        if not inherited_missing.issubset(rca_missing):
            violations.append(
                _violation(
                    "rca_missing_evidence_not_inherited",
                    "RCA top-level missing_evidence does not inherit Judge missing sources",
                    scenario_id=scenario_id,
                )
            )

        for candidate in rca.get("candidates", []):
            if not isinstance(candidate, Mapping):
                continue
            candidate_missing = set(_strings(candidate.get("missing_evidence")))
            if not inherited_missing.issubset(candidate_missing):
                violations.append(
                    _violation(
                        "candidate_missing_evidence_not_inherited",
                        "candidate omits Judge missing sources",
                        scenario_id=scenario_id,
                    )
                )
            if not _strings(candidate.get("uncertainties")):
                violations.append(
                    _violation(
                        "candidate_uncertainties_empty",
                        "candidate uncertainties must not be empty",
                        scenario_id=scenario_id,
                    )
                )

        unavailable_sources = {
            source
            for source, status in source_statuses.items()
            if str(status) in {"no_data", "not_available"}
        }
        if unavailable_sources:
            for statement in _candidate_statements(case):
                normalized = " ".join(statement.lower().split())
                if any(token in normalized for token in _UNSUPPORTED_NORMAL_CLAIMS):
                    violations.append(
                        _violation(
                            "unavailable_source_claimed_normal",
                            statement,
                            scenario_id=scenario_id,
                        )
                    )

        comparison = _mapping(case.get("legacy")).get("comparison_status")
        if comparison not in {"matched", "not_comparable_due_to_evidence"}:
            violations.append(
                _violation(
                    "legacy_comparison_failed",
                    str(comparison),
                    scenario_id=scenario_id,
                )
            )

        # render_report() rejects field-order drift before AgentOutcome.
        # AgentOutcome sanitization sorts nested mapping keys, so serialized
        # replay output can only preserve key membership and cardinality.
        card_keys = tuple(_strings(report.get("compatibility_card_keys")))
        expected_card_keys = tuple(CURRENT_CARD_KEYS)
        if (
            len(card_keys) != len(expected_card_keys)
            or set(card_keys) != set(expected_card_keys)
        ):
            violations.append(
                _violation(
                    "compatibility_card_key_drift",
                    (
                        f"expected={expected_card_keys}; "
                        f"actual={card_keys}"
                    ),
                    scenario_id=scenario_id,
                )
            )

        notification = _mapping(report.get("notification_plan"))
        if (
            bool(notification.get("send_notification", False))
            or int(notification.get("notification_count", 0)) != 0
            or bool(notification.get("second_card_sent", False))
            or bool(notification.get("production_card_replaced", False))
        ):
            violations.append(
                _violation(
                    "notification_side_effect_detected",
                    str(dict(notification)),
                    scenario_id=scenario_id,
                )
            )

        external = _mapping(case.get("external_calls"))
        forbidden_true = sorted(
            key
            for key, value in external.items()
            if key != "mock_glm" and bool(value)
        )
        if forbidden_true:
            violations.append(
                _violation(
                    "external_call_detected",
                    ", ".join(forbidden_true),
                    scenario_id=scenario_id,
                )
            )

    violations.sort(
        key=lambda item: (
            str(item["scenario_id"] or ""),
            str(item["code"]),
            str(item["message"]),
        )
    )
    return {
        "schema_version": "v12-replay-gate-report-1",
        "quality_gate_version": QUALITY_GATE_VERSION,
        "status": "passed" if not violations else "failed",
        "case_count": len(case_list),
        "required_categories": sorted(REQUIRED_CATEGORIES),
        "observed_categories": sorted(observed_categories),
        "violation_count": len(violations),
        "violations": violations,
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


__all__ = [
    "HIGH_CONFIDENCE_THRESHOLD",
    "MINIMUM_SCENARIO_COUNT",
    "QUALITY_GATE_VERSION",
    "REQUIRED_CATEGORIES",
    "evaluate_quality_gates",
]
