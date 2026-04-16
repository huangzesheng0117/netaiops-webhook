from typing import Any, Dict

from netaiops.context_catalog import classify_event_by_catalog

def _safe_lower(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()

def classify_event(event: Dict[str, Any]) -> Dict[str, Any]:
    catalog_result = classify_event_by_catalog(event)
    if catalog_result:
        return catalog_result

    vendor = _safe_lower(event.get("vendor"))
    alarm_type = _safe_lower(event.get("alarm_type") or event.get("event_type"))
    severity = _safe_lower(event.get("severity"))
    metric_name = _safe_lower(event.get("metric_name"))
    source = _safe_lower(event.get("source"))

    object_type = _safe_lower(event.get("object_type"))
    object_name = _safe_lower(event.get("object_name"))
    raw_text = _safe_lower(event.get("raw_text"))
    status = _safe_lower(event.get("status"))

    playbook_type = "generic_network_readonly"
    confidence = "low"
    auto_execute_allowed = False
    prompt_profile = "quick"
    match_reason = "default_generic"

    if "bgp" in alarm_type and ("down" in alarm_type or "peer" in alarm_type):
        playbook_type = "bgp_neighbor_down"
        confidence = "high"
        auto_execute_allowed = True
        match_reason = "matched_alarm_type_bgp_neighbor_down"

    elif "ospf" in alarm_type and "down" in alarm_type:
        playbook_type = "ospf_neighbor_down"
        confidence = "high"
        auto_execute_allowed = True
        match_reason = "matched_alarm_type_ospf_neighbor_down"

    elif "bfd" in alarm_type and ("down" in alarm_type or "neighbor" in alarm_type):
        playbook_type = "routing_neighbor_down"
        confidence = "high"
        auto_execute_allowed = True
        match_reason = "matched_alarm_type_bfd_neighbor_down"

    elif "interface" in alarm_type and ("flap" in alarm_type or "down" in alarm_type):
        playbook_type = "interface_flap"
        confidence = "medium"
        auto_execute_allowed = True
        match_reason = "matched_alarm_type_interface_flap"

    elif "pool" in alarm_type and "down" in alarm_type:
        playbook_type = "f5_pool_member_down"
        confidence = "medium"
        auto_execute_allowed = True
        match_reason = "matched_alarm_type_f5_pool_member_down"

    elif "bgp" in raw_text and ("idle" in raw_text or "down" in raw_text):
        playbook_type = "bgp_neighbor_down"
        confidence = "medium"
        auto_execute_allowed = True
        match_reason = "matched_raw_text_bgp_neighbor_down"

    elif "ospf" in raw_text and ("down" in raw_text or "neighbor" in raw_text):
        playbook_type = "ospf_neighbor_down"
        confidence = "medium"
        auto_execute_allowed = True
        match_reason = "matched_raw_text_ospf"

    elif "interface" in raw_text and ("down" in raw_text or "flap" in raw_text):
        playbook_type = "interface_flap"
        confidence = "medium"
        auto_execute_allowed = True
        match_reason = "matched_raw_text_interface"

    elif "pool member" in raw_text and "down" in raw_text:
        playbook_type = "f5_pool_member_down"
        confidence = "medium"
        auto_execute_allowed = True
        match_reason = "matched_raw_text_pool_member_down"

    if status == "resolved":
        auto_execute_allowed = False
        match_reason = f"{match_reason}_resolved"

    if severity in ("critical", "major", "error"):
        prompt_profile = "detailed"
    elif severity in ("warning", "minor"):
        prompt_profile = "quick"

    return {
        "vendor": vendor,
        "source": source,
        "alarm_type": alarm_type,
        "severity": severity,
        "metric_name": metric_name,
        "object_type": object_type,
        "object_name": object_name,
        "playbook_type": playbook_type,
        "prompt_profile": prompt_profile,
        "auto_execute_allowed": auto_execute_allowed,
        "classification_confidence": confidence,
        "match_reason": match_reason,
    }
