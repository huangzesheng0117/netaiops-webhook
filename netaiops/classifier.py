from typing import Any, Dict

from netaiops.context_catalog import classify_event_by_catalog
from netaiops.family_registry import classify_family, to_legacy_classification


def _safe_lower(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def classify_event_from_family_result(
    event: Dict[str, Any],
    family_result: Dict[str, Any],
) -> Dict[str, Any]:
    """Build legacy-compatible classification from one canonical family result.

    V13 Triage owns the sole Family Registry call. Legacy callers may still
    use ``classify_event`` which computes the family once and delegates here.

    The returned shape must preserve both legacy ``playbook_type`` and the
    canonical-family compatibility field ``legacy_playbook_type`` even when
    the context catalog has no matching rule.
    """

    if not isinstance(family_result, dict) or not family_result.get("family"):
        raise ValueError("family_result must contain the canonical family")

    legacy_result = to_legacy_classification(family_result, event)
    legacy_playbook_type = (
        family_result.get("legacy_playbook_type")
        or legacy_result.get("playbook_type")
        or "generic_network_readonly"
    )
    legacy_result["legacy_playbook_type"] = legacy_playbook_type

    catalog_result = classify_event_by_catalog(event)
    if not catalog_result:
        return legacy_result

    merged = dict(catalog_result)

    merged.setdefault("vendor", _safe_lower(event.get("vendor")))
    merged.setdefault("source", _safe_lower(event.get("source")))
    merged.setdefault(
        "alarm_type",
        _safe_lower(event.get("alarm_type") or event.get("event_type")),
    )
    merged.setdefault("severity", _safe_lower(event.get("severity")))
    merged.setdefault("metric_name", _safe_lower(event.get("metric_name")))
    merged.setdefault("object_type", _safe_lower(event.get("object_type")))
    merged.setdefault("object_name", _safe_lower(event.get("object_name")))

    if family_result.get("legacy_playbook_type"):
        merged["playbook_type"] = family_result.get("legacy_playbook_type")

    merged["prompt_profile"] = legacy_result.get(
        "prompt_profile",
        merged.get("prompt_profile", "quick"),
    )
    merged["auto_execute_allowed"] = bool(
        merged.get(
            "auto_execute_allowed",
            legacy_result.get("auto_execute_allowed", False),
        )
    )
    merged["classification_confidence"] = merged.get(
        "classification_confidence",
        legacy_result.get("classification_confidence", "low"),
    )
    merged["match_reason"] = (
        merged.get("match_reason")
        or legacy_result.get("match_reason", "")
    )
    merged["family"] = family_result.get(
        "family",
        "generic_network_readonly",
    )
    merged["legacy_playbook_type"] = legacy_playbook_type

    return merged


def classify_event(event: Dict[str, Any]) -> Dict[str, Any]:
    family_result = classify_family(event)
    return classify_event_from_family_result(event, family_result)
