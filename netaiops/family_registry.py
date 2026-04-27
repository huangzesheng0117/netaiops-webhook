from typing import Any, Dict, List


FAMILY_DEFAULTS: Dict[str, Dict[str, Any]] = {
    "routing_neighbor_down": {
        "legacy_playbook_type": "routing_neighbor_down",
        "target_kind": "neighbor",
        "auto_execute_allowed": True,
        "default_capabilities": [
            "show_bgp_peer_detail",
            "show_route_to_peer",
            "ping_peer",
            "show_interface_brief",
            "show_bgp_config_snippet",
        ],
    },
    "bgp_neighbor_down": {
        "legacy_playbook_type": "bgp_neighbor_down",
        "target_kind": "neighbor",
        "auto_execute_allowed": True,
        "default_capabilities": [
            "show_bgp_peer_detail",
            "show_route_to_peer",
            "ping_peer",
            "show_interface_brief",
            "show_bgp_config_snippet",
        ],
    },
    "ospf_neighbor_down": {
        "legacy_playbook_type": "ospf_neighbor_down",
        "target_kind": "neighbor",
        "auto_execute_allowed": True,
        "default_capabilities": [
            "show_ospf_peer_detail",
            "show_interface_brief",
            "show_recent_logs",
        ],
    },
    "interface_or_link_utilization_high": {
        "legacy_playbook_type": "interface_or_link_utilization_high",
        "target_kind": "interface",
        "auto_execute_allowed": True,
        "default_capabilities": [
            "show_interface_detail",
            "show_interface_error_counters",
            "show_portchannel_summary",
        ],
    },
    "interface_or_link_traffic_drop": {
        "legacy_playbook_type": "interface_or_link_traffic_drop",
        "target_kind": "interface",
        "auto_execute_allowed": True,
        "default_capabilities": [
            "show_interface_detail",
            "show_interface_error_counters",
            "show_portchannel_summary",
            "show_lacp_neighbor",
        ],
    },
    "interface_packet_loss_or_discards_high": {
        "legacy_playbook_type": "interface_packet_loss_or_discards_high",
        "target_kind": "interface",
        "auto_execute_allowed": True,
        "default_capabilities": [
            "show_interface_detail",
            "show_interface_error_counters",
            "show_portchannel_summary",
        ],
    },
    "interface_status_or_flap": {
        "legacy_playbook_type": "interface_flap",
        "target_kind": "interface",
        "auto_execute_allowed": True,
        "default_capabilities": [
            "show_interface_detail",
            "show_interface_error_counters",
            "show_recent_logs",
        ],
    },
    "device_cpu_high": {
        "legacy_playbook_type": "device_cpu_high",
        "target_kind": "device",
        "auto_execute_allowed": True,
        "default_capabilities": [
            "show_device_cpu",
            "show_recent_logs",
        ],
    },
    "device_memory_high": {
        "legacy_playbook_type": "device_memory_high",
        "target_kind": "device",
        "auto_execute_allowed": True,
        "default_capabilities": [
            "show_device_memory",
            "show_recent_logs",
        ],
    },
    "f5_pool_member_down": {
        "legacy_playbook_type": "f5_pool_member_down",
        "target_kind": "pool_member",
        "auto_execute_allowed": True,
        "default_capabilities": [
            "show_f5_pool_list",
            "show_f5_pool_members",
            "show_f5_pool_config",
            "show_f5_connections",
            "show_f5_performance",
        ],
    },
    "generic_network_readonly": {
        "legacy_playbook_type": "generic_network_readonly",
        "target_kind": "generic",
        "auto_execute_allowed": False,
        "default_capabilities": [
            "show_recent_logs",
        ],
    },
}

FAMILY_ALIASES: Dict[str, str] = {
    "interface_flap": "interface_status_or_flap",
    "interface_flap_or_down": "interface_status_or_flap",
    "pool_member_down": "f5_pool_member_down",
    "bfd_neighbor_down": "routing_neighbor_down",
}


def _safe_lower(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _first_non_empty(*values: Any) -> str:
    for value in values:
        text = str(value).strip() if value is not None else ""
        if text:
            return text
    return ""


def _split_interfaces(value: Any) -> List[str]:
    if not value:
        return []
    if isinstance(value, list):
        out: List[str] = []
        for item in value:
            out.extend(_split_interfaces(item))
        return out

    text = str(value).replace("|", ",")
    return [x.strip() for x in text.split(",") if x.strip()]


def _canonicalize_family(family: str) -> str:
    family_l = _safe_lower(family)
    if not family_l:
        return "generic_network_readonly"
    return FAMILY_ALIASES.get(family_l, family_l)


def _infer_family_from_fields(event: Dict[str, Any]) -> str:
    alarm_type = _safe_lower(event.get("alarm_type") or event.get("event_type"))
    raw_text = _safe_lower(event.get("raw_text"))
    metric_name = _safe_lower(event.get("metric_name"))
    object_type = _safe_lower(event.get("object_type"))

    merged = " | ".join([alarm_type, raw_text, metric_name, object_type])

    if "bgp" in merged and ("down" in merged or "peer" in merged or "neighbor" in merged):
        return "bgp_neighbor_down"
    if "ospf" in merged and ("down" in merged or "peer" in merged or "neighbor" in merged):
        return "ospf_neighbor_down"
    if "bfd" in merged and ("down" in merged or "peer" in merged or "neighbor" in merged):
        return "routing_neighbor_down"
    if ("pool" in merged and "down" in merged) or ("pool member" in merged and "down" in merged):
        return "f5_pool_member_down"
    if "cpu" in merged and ("high" in merged or "usage" in merged):
        return "device_cpu_high"
    if "memory" in merged and ("high" in merged or "usage" in merged):
        return "device_memory_high"
    if "discard" in merged or "packet loss" in merged or "crc" in merged:
        return "interface_packet_loss_or_discards_high"
    if "traffic drop" in merged or "drop" in merged:
        return "interface_or_link_traffic_drop"
    if "utilization" in merged or "bandwidth" in merged or "bps" in merged:
        return "interface_or_link_utilization_high"
    if "interface" in merged and ("flap" in merged or "down" in merged or "status" in merged):
        return "interface_status_or_flap"

    return "generic_network_readonly"


def classify_family(event: Dict[str, Any]) -> Dict[str, Any]:
    family = _first_non_empty(
        event.get("family"),
        event.get("playbook_type_hint"),
        event.get("catalog_family"),
    )
    match_source = "event_field"

    if not family:
        family = _infer_family_from_fields(event)
        match_source = "heuristic"

    family = _canonicalize_family(family)
    default_cfg = FAMILY_DEFAULTS.get(family, FAMILY_DEFAULTS["generic_network_readonly"])

    status = _safe_lower(event.get("status"))
    auto_execute_allowed = bool(default_cfg.get("auto_execute_allowed", False))
    if status == "resolved":
        auto_execute_allowed = False

    confidence = "high" if match_source == "event_field" else "medium"
    if family == "generic_network_readonly":
        confidence = "low"

    target_scope = {
        "vendor": event.get("vendor", ""),
        "platform": event.get("platform", ""),
        "hostname": event.get("hostname", ""),
        "device_ip": event.get("device_ip", "") or event.get("ip", "") or event.get("host_ip", ""),
        "site": event.get("site", ""),
        "interface": event.get("interface", "") or event.get("object_name", ""),
        "interfaces": _split_interfaces(event.get("interfaces") or event.get("interface")),
        "peer_ip": event.get("peer_ip", "") or event.get("object_id", ""),
        "pool_member": event.get("pool_member", "") or event.get("object_id", ""),
        "related_devices": event.get("related_devices", []) or [],
    }

    return {
        "family": family,
        "family_confidence": confidence,
        "match_source": match_source,
        "match_reason": event.get("catalog_rule_id", "") or f"{match_source}:{family}",
        "catalog_rule_id": event.get("catalog_rule_id", ""),
        "legacy_playbook_type": default_cfg.get("legacy_playbook_type", family),
        "target_kind": default_cfg.get("target_kind", "generic"),
        "auto_execute_allowed": auto_execute_allowed,
        "default_capabilities": list(default_cfg.get("default_capabilities", [])),
        "target_scope": target_scope,
    }


def to_legacy_classification(family_result: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
    severity = _safe_lower(event.get("severity"))
    prompt_profile = "quick"
    if severity in ("critical", "major", "error"):
        prompt_profile = "detailed"

    return {
        "vendor": _safe_lower(event.get("vendor")),
        "source": _safe_lower(event.get("source")),
        "alarm_type": _safe_lower(event.get("alarm_type") or event.get("event_type")),
        "severity": severity,
        "metric_name": _safe_lower(event.get("metric_name")),
        "object_type": _safe_lower(event.get("object_type")),
        "object_name": _safe_lower(event.get("object_name")),
        "playbook_type": family_result.get("legacy_playbook_type", "generic_network_readonly"),
        "prompt_profile": prompt_profile,
        "auto_execute_allowed": bool(family_result.get("auto_execute_allowed", False)),
        "classification_confidence": family_result.get("family_confidence", "low"),
        "match_reason": family_result.get("match_reason", ""),
        "family": family_result.get("family", "generic_network_readonly"),
    }
