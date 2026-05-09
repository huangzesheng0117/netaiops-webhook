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

# ===== v5 prometheus rule expanded families begin =====
# 说明：
# 这批 family 来自 Prometheus rules 全量覆盖分析。
# 目标是把风扇、电源、温度、板卡、光功率、磁盘、DNS、F5连接数、HA/CIMC 等告警
# 先统一归并到 canonical family，后续再补 capability 和平台命令矩阵。

try:
    _v5_original_classify_family = classify_family
except NameError:
    _v5_original_classify_family = None


V5_ADDITIONAL_FAMILY_META = {
    "hardware_fan_abnormal": {
        "target_kind": "hardware",
        "legacy_playbook_type": "hardware_fan_abnormal",
        "auto_execute_allowed": True,
    },
    "hardware_power_abnormal": {
        "target_kind": "hardware",
        "legacy_playbook_type": "hardware_power_abnormal",
        "auto_execute_allowed": True,
    },
    "hardware_temperature_high": {
        "target_kind": "hardware",
        "legacy_playbook_type": "hardware_temperature_high",
        "auto_execute_allowed": True,
    },
    "chassis_slot_or_module_abnormal": {
        "target_kind": "module",
        "legacy_playbook_type": "chassis_slot_or_module_abnormal",
        "auto_execute_allowed": True,
    },
    "optical_power_abnormal": {
        "target_kind": "interface",
        "legacy_playbook_type": "optical_power_abnormal",
        "auto_execute_allowed": True,
    },
    "device_disk_high": {
        "target_kind": "device",
        "legacy_playbook_type": "device_disk_high",
        "auto_execute_allowed": True,
    },
    "dns_request_rate_anomaly": {
        "target_kind": "service",
        "legacy_playbook_type": "dns_request_rate_anomaly",
        "auto_execute_allowed": False,
    },
    "dns_response_rate_anomaly": {
        "target_kind": "service",
        "legacy_playbook_type": "dns_response_rate_anomaly",
        "auto_execute_allowed": False,
    },
    "f5_connection_rate_anomaly": {
        "target_kind": "device",
        "legacy_playbook_type": "f5_connection_rate_anomaly",
        "auto_execute_allowed": True,
    },
    "ha_or_cluster_state_abnormal": {
        "target_kind": "cluster",
        "legacy_playbook_type": "ha_or_cluster_state_abnormal",
        "auto_execute_allowed": True,
    },
    "cimc_hardware_abnormal": {
        "target_kind": "hardware",
        "legacy_playbook_type": "cimc_hardware_abnormal",
        "auto_execute_allowed": False,
    },
}


V5_ADDITIONAL_FAMILY_KEYWORDS = {
    "hardware_fan_abnormal": [
        "风扇",
        "fan",
        "fantray",
        "cefcfantrayoperstatus",
        "syschassisfanstatus",
    ],
    "hardware_power_abnormal": [
        "电源",
        "power",
        "powersupply",
        "psu",
        "cefcfrupoweroperstatus",
        "syschassispowersupplystatus",
    ],
    "hardware_temperature_high": [
        "温度",
        "temperature",
        "temp",
        "entphyssensortemperature",
        "高温",
    ],
    "chassis_slot_or_module_abnormal": [
        "板卡",
        "slot",
        "module",
        "chassis",
        "linecard",
        "supervisor",
        "syschassisslot",
    ],
    "optical_power_abnormal": [
        "光功率",
        "transceiver",
        "ddm",
        "rxpower",
        "txpower",
        "rxdbm",
        "txdbm",
        "receive power",
        "transmit power",
        "entsensorvalue",
    ],
    "device_disk_high": [
        "磁盘",
        "disk",
        "filesystem",
        "flash",
        "bootflash",
        "存储空间",
    ],
    "dns_request_rate_anomaly": [
        "dns请求",
        "dns每秒请求",
        "dns请求率",
        "gtmstatrequests",
        "dns request",
        "dns qps",
    ],
    "dns_response_rate_anomaly": [
        "dns响应",
        "dns解析率",
        "dns优选解析率",
        "gtmstatresolutions",
        "gtmstatpreferred",
        "dns response",
    ],
    "f5_connection_rate_anomaly": [
        "f5连接",
        "f5活跃连接",
        "active connection",
        "sysclientcurconns",
        "connection spike",
        "连接数突增",
        "连接数突降",
    ],
    "ha_or_cluster_state_abnormal": [
        "主备",
        "ha",
        "cluster",
        "failover",
        "traffic-group",
        "standby",
        "active",
        "双机",
    ],
    "cimc_hardware_abnormal": [
        "cimc",
        "主板",
        "motherboard",
        "processor",
        "storage controller",
        "storagecontroller",
        "cpu status",
        "controller",
    ],
}


def _v5_family_text(event):
    if event is None:
        return ""

    parts = []

    if isinstance(event, dict):
        for key in (
            "family",
            "playbook_type_hint",
            "alarm_type",
            "raw_text",
            "summary",
            "description",
            "object_type",
            "object_name",
            "vendor",
            "job",
            "expr",
            "query",
        ):
            value = event.get(key)
            if value is not None:
                parts.append(str(value))

        labels = event.get("labels")
        if isinstance(labels, dict):
            parts.append(str(labels))

        annotations = event.get("annotations")
        if isinstance(annotations, dict):
            parts.append(str(annotations))

    else:
        parts.append(str(event))

    return " ".join(parts).lower()


def _v5_detect_additional_family(event):
    text = _v5_family_text(event)

    if not text:
        return ""

    # DNS 的判断要放在普通利用率之前，避免 DNS 请求率被误归到接口利用率。
    family_order = [
        "dns_request_rate_anomaly",
        "dns_response_rate_anomaly",
        "f5_connection_rate_anomaly",
        "hardware_fan_abnormal",
        "hardware_power_abnormal",
        "hardware_temperature_high",
        "chassis_slot_or_module_abnormal",
        "optical_power_abnormal",
        "device_disk_high",
        "ha_or_cluster_state_abnormal",
        "cimc_hardware_abnormal",
    ]

    for family in family_order:
        keywords = V5_ADDITIONAL_FAMILY_KEYWORDS.get(family, [])
        for keyword in keywords:
            if str(keyword).lower() in text:
                return family

    return ""


def _v5_build_family_result(event, family):
    meta = V5_ADDITIONAL_FAMILY_META.get(family, {}) or {}

    target_scope = {}
    if isinstance(event, dict):
        for key in (
            "device_ip",
            "hostname",
            "instance",
            "interface",
            "ifName",
            "ifAlias",
            "object_name",
            "alarm_type",
        ):
            value = event.get(key)
            if value:
                if key == "ifName":
                    target_scope["interface"] = value
                else:
                    target_scope[key] = value

    return {
        "family": family,
        "family_confidence": "high",
        "match_source": "v5_prometheus_rule_expanded_keywords",
        "match_reason": "matched expanded Prometheus rule family keywords",
        "catalog_rule_id": "",
        "legacy_playbook_type": meta.get("legacy_playbook_type", family),
        "target_kind": meta.get("target_kind", "generic"),
        "auto_execute_allowed": bool(meta.get("auto_execute_allowed", True)),
        "default_capabilities": [],
        "target_scope": target_scope,
    }


if _v5_original_classify_family is not None:
    def classify_family(event):
        original = _v5_original_classify_family(event)
        if not isinstance(original, dict):
            original = {}

        detected = _v5_detect_additional_family(event)
        original_family = str(original.get("family") or "").strip()

        # 已有核心 family 不覆盖；generic 或空 family 时，使用新增 family。
        if detected and original_family in ("", "generic", "generic_network", "generic_network_readonly"):
            return _v5_build_family_result(event, detected)

        # 如果原始分类明显误归 generic 以外但文本强命中硬件/DNS/F5连接类，也允许新增 family 接管。
        if detected and detected in V5_ADDITIONAL_FAMILY_META:
            if original_family not in (
                "interface_or_link_utilization_high",
                "interface_or_link_traffic_drop",
                "interface_packet_loss_or_discards_high",
                "interface_status_or_flap",
                "bgp_neighbor_down",
                "ospf_neighbor_down",
                "routing_neighbor_down",
                "device_cpu_high",
                "device_memory_high",
                "f5_pool_member_down",
            ):
                return _v5_build_family_result(event, detected)

        return original
# ===== v5 prometheus rule expanded families end =====
