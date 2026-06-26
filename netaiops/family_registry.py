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

# ===== v5 PromQL interface utilization family final classifier begin =====
# 修复场景：
# alert: WG88互联网线路_电信_100M_利用率-出向
# expr: sum(irate(ifHCOutOctets{ip=~"10.189.250.8",ifName=~"Te1/0/1|Te2/0/1"}[2m]))*8 > 80000000
#
# 之前这类告警可能被误归到 generic_network_readonly，导致只生成 show_recent_logs，
# 进而无法对 Te1/0/1 和 Te2/0/1 做多接口 MCP 取证。
#
# 这里做最终兜底：只要文本/PromQL 明确包含 ifHCInOctets/ifHCOutOctets + ifName/接口 + 利用率/阈值，
# 就归类为 interface_or_link_utilization_high。

import json as _v16f_json
import re as _v16f_re
import urllib.parse as _v16f_urlparse


try:
    _v16f_original_classify_family = classify_family
except NameError:
    _v16f_original_classify_family = None


def _v16f_safe_text(value):
    if value is None:
        return ""

    if isinstance(value, (dict, list, tuple, set)):
        try:
            return _v16f_json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)

    return str(value).strip()


def _v16f_walk_text(obj, max_depth=5):
    parts = []

    def walk(value, depth=0):
        if depth > max_depth:
            return

        if value is None:
            return

        if isinstance(value, dict):
            for k, v in value.items():
                parts.append(_v16f_safe_text(k))
                walk(v, depth + 1)
            return

        if isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item, depth + 1)
            return

        parts.append(_v16f_safe_text(value))

    walk(obj)
    return _v16f_urlparse.unquote(" ".join(x for x in parts if x))


def _v16f_extract_interface_from_promql(text):
    patterns = [
        r'ifName\s*=~\s*"([^"]+)"',
        r"ifName\s*=~\s*'([^']+)'",
        r'ifDescr\s*=~\s*"([^"]+)"',
        r"ifDescr\s*=~\s*'([^']+)'",
        r'interface\s*=~\s*"([^"]+)"',
        r"interface\s*=~\s*'([^']+)'",
    ]

    for pattern in patterns:
        m = _v16f_re.search(pattern, text or "", flags=_v16f_re.IGNORECASE)
        if not m:
            continue

        expr = m.group(1).strip()

        # 多接口时取第一个作为 primary interface，后续 platform_command_matrix 会展开全部接口。
        first = expr.split("|")[0].strip()

        if _v16f_re.match(r"^[A-Za-z][A-Za-z0-9_\-./]+$", first):
            return first

    return ""


def _v16f_is_promql_interface_utilization(event):
    text = _v16f_walk_text(event)
    lower = text.lower()

    has_octets = (
        "ifhcoutoctets" in lower
        or "ifhcinoc­tets" in lower
        or "ifhcinoctets" in lower
        or "ifoutoctets" in lower
        or "ifinoctets" in lower
    )

    has_interface = (
        "ifname" in lower
        or "ifdescr" in lower
        or "interface" in lower
        or "端口" in text
        or "接口" in text
    )

    has_utilization_text = (
        "利用率" in text
        or "带宽" in text
        or "超过80" in text
        or "> 80000000" in text
        or ">80000000" in text
        or "irate(" in lower
        or "rate(" in lower
    )

    if has_octets and has_interface and has_utilization_text:
        return True

    # 针对告警名本身已经明确写“线路_100M_利用率-入/出向”的情况兜底。
    if ("利用率" in text and ("入向" in text or "出向" in text) and ("线路" in text or "接口" in text or "端口" in text)):
        return True

    return False


def _v16f_build_interface_utilization_family(event, original=None):
    text = _v16f_walk_text(event)
    original = original if isinstance(original, dict) else {}

    interface = ""

    if isinstance(event, dict):
        for key in ("interface", "ifName", "if_name", "port", "object_name"):
            value = _v16f_safe_text(event.get(key))
            if value:
                interface = value
                break

        if not interface:
            labels = event.get("labels")
            if isinstance(labels, dict):
                for key in ("interface", "ifName", "if_name", "port"):
                    value = _v16f_safe_text(labels.get(key))
                    if value:
                        interface = value
                        break

    if not interface:
        interface = _v16f_extract_interface_from_promql(text)

    target_scope = dict(original.get("target_scope") or {})

    if isinstance(event, dict):
        for key in (
            "device_ip",
            "hostname",
            "instance",
            "vendor",
            "platform",
            "os_family",
            "job",
            "alarm_type",
            "raw_text",
            "query",
            "expr",
        ):
            value = event.get(key)
            if value and key not in target_scope:
                target_scope[key] = value

    if interface:
        target_scope["interface"] = interface

    return {
        "family": "interface_or_link_utilization_high",
        "family_confidence": "high",
        "match_source": "v5_promql_interface_utilization_classifier",
        "match_reason": "matched PromQL/interface utilization pattern",
        "catalog_rule_id": original.get("catalog_rule_id", ""),
        "legacy_playbook_type": "interface_or_link_utilization_high",
        "target_kind": "interface",
        "auto_execute_allowed": True,
        "default_capabilities": original.get("default_capabilities", []),
        "target_scope": target_scope,
    }


if _v16f_original_classify_family is not None:
    def classify_family(event):
        original = _v16f_original_classify_family(event)

        original_family = ""
        if isinstance(original, dict):
            original_family = _v16f_safe_text(original.get("family"))

        if _v16f_is_promql_interface_utilization(event):
            if original_family in ("", "generic", "generic_network", "generic_network_readonly", "unknown"):
                return _v16f_build_interface_utilization_family(event, original)

        return original
# ===== v5 PromQL interface utilization family final classifier end =====

# ===== v7.8 optical power final classifier begin =====
# 目标：
# - “NXOS光功率 / 光功率异常 / transceiver / Rx Power / Tx Power” 必须优先归类为 optical_power_abnormal。
# - 避免因为文本里含 power / 功率 被误归到 hardware_power_abnormal。
# - 尽量从告警文本、object_name、labels、annotations 中提取 Ethernet1/10 等接口名。
import json as _v78_json
import re as _v78_re
import urllib.parse as _v78_urlparse

try:
    _v78_original_classify_family = classify_family
except NameError:
    _v78_original_classify_family = None


def _v78_safe_text(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        try:
            return _v78_json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)
    return str(value).strip()


def _v78_walk_text(obj, max_depth=5):
    parts = []

    def walk(value, depth=0):
        if depth > max_depth or value is None:
            return

        if isinstance(value, dict):
            for k, v in value.items():
                parts.append(_v78_safe_text(k))
                walk(v, depth + 1)
            return

        if isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item, depth + 1)
            return

        parts.append(_v78_safe_text(value))

    walk(obj)
    return _v78_urlparse.unquote(" ".join(x for x in parts if x))


def _v78_normalize_interface(value):
    text = _v78_safe_text(value).replace(" ", "")
    if not text:
        return ""

    lower = text.lower()

    replacements = [
        ("ethernet", "Ethernet"),
        ("eth", "Ethernet"),
        ("tengigabitethernet", "TenGigabitEthernet"),
        ("te", "TenGigabitEthernet"),
        ("gigabitethernet", "GigabitEthernet"),
        ("gi", "GigabitEthernet"),
    ]

    for prefix, full in replacements:
        if lower.startswith(prefix):
            return full + text[len(prefix):]

    return text


def _v78_extract_interface(event, original=None):
    candidates = []

    if isinstance(original, dict):
        scope = original.get("target_scope")
        if isinstance(scope, dict):
            for key in ("interface", "object_name", "ifName", "if_name", "port"):
                candidates.append(scope.get(key))

    if isinstance(event, dict):
        for key in ("interface", "object_name", "ifName", "if_name", "port"):
            candidates.append(event.get(key))

        labels = event.get("labels")
        if isinstance(labels, dict):
            for key in ("interface", "object_name", "ifName", "if_name", "port"):
                candidates.append(labels.get(key))

        annotations = event.get("annotations")
        if isinstance(annotations, dict):
            for key in ("interface", "object_name", "ifName", "if_name", "port"):
                candidates.append(annotations.get(key))

    for item in candidates:
        iface = _v78_normalize_interface(item)
        if _v78_re.match(r"^(Ethernet|Eth|TenGigabitEthernet|Te|GigabitEthernet|Gi)\d+(?:/\d+)+$", iface, flags=_v78_re.I):
            return iface

    text = _v78_walk_text(event) + " " + _v78_walk_text(original)
    patterns = [
        r"\b(Ethernet\s*\d+(?:/\d+)+)\b",
        r"\b(Eth\s*\d+(?:/\d+)+)\b",
        r"\b(TenGigabitEthernet\s*\d+(?:/\d+)+)\b",
        r"\b(Te\s*\d+(?:/\d+)+)\b",
        r"\b(GigabitEthernet\s*\d+(?:/\d+)+)\b",
        r"\b(Gi\s*\d+(?:/\d+)+)\b",
    ]

    for pattern in patterns:
        m = _v78_re.search(pattern, text, flags=_v78_re.I)
        if m:
            return _v78_normalize_interface(m.group(1))

    return ""


def _v78_is_optical_power_alert(event):
    text = _v78_walk_text(event)
    lower = text.lower()

    strong_keywords = [
        "光功率",
        "收光",
        "发光",
        "光模块",
        "transceiver",
        "rx power",
        "tx power",
        "rxpower",
        "txpower",
        "rxdbm",
        "txdbm",
        "receive power",
        "transmit power",
        "ddm",
    ]

    return any(k in lower or k in text for k in strong_keywords)


if _v78_original_classify_family is not None:
    def classify_family(event):
        original = _v78_original_classify_family(event)
        if not isinstance(original, dict):
            original = {}

        if not _v78_is_optical_power_alert(event):
            return original

        target_scope = dict(original.get("target_scope") or {})

        if isinstance(event, dict):
            for key in (
                "device_ip",
                "hostname",
                "instance",
                "vendor",
                "platform",
                "os_family",
                "job",
                "alarm_type",
                "raw_text",
                "summary",
                "description",
                "object_name",
            ):
                value = event.get(key)
                if value and key not in target_scope:
                    target_scope[key] = value

        interface = _v78_extract_interface(event, original)
        if interface:
            target_scope["interface"] = interface
            target_scope["interfaces"] = [interface]

        return {
            "family": "optical_power_abnormal",
            "family_confidence": "high",
            "match_source": "v7_8_optical_power_final_classifier",
            "match_reason": "matched optical/transceiver/RxPower/TxPower keywords; override hardware power classification",
            "catalog_rule_id": original.get("catalog_rule_id", ""),
            "legacy_playbook_type": "optical_power_abnormal",
            "target_kind": "interface",
            "auto_execute_allowed": True,
            "default_capabilities": [
                "show_interface_transceiver",
                "show_interface_detail",
            ],
            "target_scope": target_scope,
        }
# ===== v7.8 optical power final classifier end =====

# ===== v9 cisco hardware component classifier begin =====
# 目标：
# - “硬件部件故障 / Cisco Hardware Component Fault / Hardware Fault”等泛硬件告警，
#   即使没有明确 fan/power/temp/module 关键词，也不要落到 generic_network_readonly。
# - 若能从文本中识别风扇/电源/温度/模块，则优先归入已有硬件 family，复用现有 evidence parser。
import json as _v9_hw_json
import re as _v9_hw_re

try:
    _v9_hw_original_classify_family = classify_family
except NameError:
    _v9_hw_original_classify_family = None


def _v9_hw_safe_text(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        try:
            return _v9_hw_json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)
    return str(value).strip()


def _v9_hw_walk_text(obj, max_depth=5):
    parts = []

    def walk(value, depth=0):
        if depth > max_depth or value is None:
            return
        if isinstance(value, dict):
            for k, v in value.items():
                parts.append(_v9_hw_safe_text(k))
                walk(v, depth + 1)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item, depth + 1)
            return
        parts.append(_v9_hw_safe_text(value))

    walk(obj)
    return " ".join([p for p in parts if p]).lower()


def _v9_hw_pick_family(text):
    if _v9_hw_re.search(r"风扇|fan|fantray", text, flags=_v9_hw_re.I):
        return "hardware_fan_abnormal"
    if _v9_hw_re.search(r"电源|power|powersupply|psu|supply|input lost|capacity", text, flags=_v9_hw_re.I):
        return "hardware_power_abnormal"
    if _v9_hw_re.search(r"温度|temperature|temp|thermal|overheat|高温", text, flags=_v9_hw_re.I):
        return "hardware_temperature_high"
    if _v9_hw_re.search(r"模块|板卡|线卡|module|linecard|supervisor|sup|slot|fabric|fex|stack|poe|ilpower|fru|oir", text, flags=_v9_hw_re.I):
        return "chassis_slot_or_module_abnormal"
    return "chassis_slot_or_module_abnormal"


def _v9_hw_should_handle(text):
    if not text:
        return False
    return bool(_v9_hw_re.search(
        r"硬件部件故障|硬件故障|硬件异常|hardware component fault|hardware fault|cisco hardware|fru|传感器|sensor",
        text,
        flags=_v9_hw_re.I,
    ))


if _v9_hw_original_classify_family is not None:
    def classify_family(event):
        original = _v9_hw_original_classify_family(event)

        original_family = ""
        if isinstance(original, dict):
            original_family = _v9_hw_safe_text(original.get("family"))

        # 已经被更精确的 fan/power/temp/module family 命中时，不覆盖。
        if original_family not in ("", "generic", "generic_network", "generic_network_readonly", "unknown"):
            return original

        text = _v9_hw_walk_text(event)
        if not _v9_hw_should_handle(text):
            return original

        family = _v9_hw_pick_family(text)
        base = dict(original or {}) if isinstance(original, dict) else {}

        target_scope = dict(base.get("target_scope") or {})
        if isinstance(event, dict):
            labels = event.get("labels") if isinstance(event.get("labels"), dict) else {}
            for key in ("device_ip", "ip", "hostname", "sysName", "instance", "vendor", "platform", "alarm_type", "alertname", "object_name"):
                value = event.get(key)
                if value in (None, "", [], {}):
                    value = labels.get(key)
                if value not in (None, "", [], {}):
                    mapped_key = "device_ip" if key in ("ip", "instance") and not target_scope.get("device_ip") else key
                    if mapped_key == "sysName":
                        mapped_key = "hostname"
                    if mapped_key == "alertname":
                        mapped_key = "alarm_type"
                    target_scope[mapped_key] = str(value).strip()

        base.update({
            "family": family,
            "family_confidence": "high",
            "match_source": "v9_cisco_hardware_component_classifier",
            "match_reason": "matched generic Cisco hardware component fault wording",
            "legacy_playbook_type": family,
            "target_kind": "hardware",
            "auto_execute_allowed": True,
            "target_scope": target_scope,
        })
        return base
# ===== v9 cisco hardware component classifier end =====

# ===== v9 interface traffic anomaly classifier begin =====
# 将骨干网/互联网/接口链路流量突增突降类告警兜底归入 interface_traffic_anomaly。
import json as _v9_it_json
import re as _v9_it_re

try:
    _v9_it_original_classify_family = classify_family
except NameError:
    _v9_it_original_classify_family = None


def _v9_it_safe_text(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        try:
            return _v9_it_json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)
    return str(value).strip()


def _v9_it_walk_text(obj, max_depth=5):
    parts = []

    def walk(value, depth=0):
        if depth > max_depth or value is None:
            return
        if isinstance(value, dict):
            for k, v in value.items():
                parts.append(_v9_it_safe_text(k))
                walk(v, depth + 1)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item, depth + 1)
            return
        parts.append(_v9_it_safe_text(value))

    walk(obj)
    return " ".join([p for p in parts if p])


def _v9_it_should_handle(text):
    if not text:
        return False
    return bool(_v9_it_re.search(
        r"(接口.?链路.?流量.?突增|接口.?链路.?流量.?突降|接口.?链路.?流量.?突增.?突降|骨干网.*流量.*突增|骨干网.*流量.*突降|互联网.*流量.*突增|互联网.*流量.*突降|骨干.*利用率.*突增|骨干.*利用率.*突降|互联网.*利用率.*突增|互联网.*利用率.*突降|Traffic.*Spike|Traffic.*Drop|Traffic.*Anomaly)",
        text,
        flags=_v9_it_re.I,
    ))


def _v9_it_pick_direction(text):
    if _v9_it_re.search(r"(入向|入口|inbound|input|in_bps|ifHCInOctets)", text, flags=_v9_it_re.I):
        return "in"
    if _v9_it_re.search(r"(出向|出口|outbound|output|out_bps|ifHCOutOctets)", text, flags=_v9_it_re.I):
        return "out"
    return ""


def _v9_it_pick_change_type(text):
    if _v9_it_re.search(r"(突增|升高|超过|高于|spike|increase|high)", text, flags=_v9_it_re.I):
        return "spike"
    if _v9_it_re.search(r"(突降|下降|降低|归零|drop|decrease|low)", text, flags=_v9_it_re.I):
        return "drop"
    return "anomaly"


if _v9_it_original_classify_family is not None:
    def classify_family(event):
        original = _v9_it_original_classify_family(event)

        original_family = ""
        if isinstance(original, dict):
            original_family = _v9_it_safe_text(original.get("family"))

        if original_family in ("interface_traffic_anomaly", "interface_traffic_drop", "interface_utilization_high"):
            return original

        text = _v9_it_walk_text(event)
        if not _v9_it_should_handle(text):
            return original

        base = dict(original or {}) if isinstance(original, dict) else {}
        target_scope = dict(base.get("target_scope") or {})

        if isinstance(event, dict):
            labels = event.get("labels") if isinstance(event.get("labels"), dict) else {}
            annotations = event.get("annotations") if isinstance(event.get("annotations"), dict) else {}
            for key in ("device_ip", "ip", "instance", "hostname", "sysName", "interface", "ifName", "if_name", "object_name", "direction", "alarm_type", "alertname"):
                value = event.get(key)
                if value in (None, "", [], {}):
                    value = labels.get(key)
                if value in (None, "", [], {}):
                    value = annotations.get(key)
                if value not in (None, "", [], {}):
                    mapped = key
                    if key in ("ip", "instance") and not target_scope.get("device_ip"):
                        mapped = "device_ip"
                    if key == "sysName":
                        mapped = "hostname"
                    if key in ("ifName", "if_name", "object_name") and not target_scope.get("interface"):
                        mapped = "interface"
                    if key == "alertname":
                        mapped = "alarm_type"
                    target_scope[mapped] = str(value).strip()

        direction = _v9_it_pick_direction(text)
        if direction and not target_scope.get("direction"):
            target_scope["direction"] = direction

        target_scope["traffic_change_type"] = _v9_it_pick_change_type(text)

        base.update({
            "family": "interface_traffic_anomaly",
            "family_confidence": "high",
            "match_source": "v9_interface_traffic_anomaly_classifier",
            "match_reason": "matched backbone/internet/interface traffic spike/drop wording",
            "legacy_playbook_type": "interface_traffic_anomaly",
            "target_kind": "interface",
            "auto_execute_allowed": True,
            "target_scope": target_scope,
        })
        return base
# ===== v9 interface traffic anomaly classifier end =====

# ===== v9.5 interface utilization high classifier begin =====
# Cisco 接口/链路利用率高类告警兜底归类。
# 特别支持 WG88互联网线路_电信_100M_利用率：Te1/0/1 + Te2/0/1 聚合，容量100M。
import json as _v95_iu_json
import re as _v95_iu_re

try:
    _v95_iu_original_classify_family = classify_family
except NameError:
    _v95_iu_original_classify_family = None


def _v95_iu_safe_text(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        try:
            return _v95_iu_json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)
    return str(value).strip()


def _v95_iu_walk_text(obj, max_depth=5):
    parts = []

    def walk(value, depth=0):
        if depth > max_depth or value is None:
            return
        if isinstance(value, dict):
            for k, v in value.items():
                parts.append(_v95_iu_safe_text(k))
                walk(v, depth + 1)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item, depth + 1)
            return
        parts.append(_v95_iu_safe_text(value))

    walk(obj)
    return " ".join([p for p in parts if p])


def _v95_iu_match(text):
    if not text:
        return False
    return bool(_v95_iu_re.search(
        r"(接口.?链路.?利用率高|接口.?利用率高|链路.?利用率高|利用率超过|利用率高|带宽利用率|"
        r"WG88互联网线路_电信_100M_利用率|bandwidth.*utilization.*high|utilization.*high)",
        text,
        flags=_v95_iu_re.I,
    ))


def _v95_iu_direction(text):
    if _v95_iu_re.search(r"(出向|出口|outbound|output|out_bps|ifHCOutOctets)", text, flags=_v95_iu_re.I):
        return "out"
    if _v95_iu_re.search(r"(入向|入口|inbound|input|in_bps|ifHCInOctets)", text, flags=_v95_iu_re.I):
        return "in"
    return ""


def _v95_iu_capacity_bps(text):
    # 优先从类似 100M / 10G / 500K 的告警名称中解析逻辑链路容量。
    m = _v95_iu_re.search(r"(?<!\d)(\d+(?:\.\d+)?)\s*([KMG])\s*(?:_|-|线路|带宽|利用率|$)", text, flags=_v95_iu_re.I)
    if not m:
        m = _v95_iu_re.search(r"(?<!\d)(\d+(?:\.\d+)?)\s*([KMG])", text, flags=_v95_iu_re.I)
    if not m:
        return ""
    value = float(m.group(1))
    unit = m.group(2).upper()
    factor = {"K": 1000, "M": 1000 * 1000, "G": 1000 * 1000 * 1000}[unit]
    return str(int(value * factor))


def _v95_iu_extract_interface(text):
    m = _v95_iu_re.search(r"\b(Te\d+/\d+/\d+|TenGigabitEthernet\d+/\d+/\d+|Gi\d+/\d+/\d+|GigabitEthernet\d+/\d+/\d+|Eth\d+/\d+|Ethernet\d+/\d+)\b", text)
    if m:
        return m.group(1)
    return ""


def _v95_iu_enrich_scope(scope, text):
    if not isinstance(scope, dict):
        scope = {}

    direction = _v95_iu_direction(text)
    if direction:
        scope["direction"] = direction
        scope["traffic_direction"] = direction

    capacity = _v95_iu_capacity_bps(text)
    if capacity:
        scope["capacity_bps"] = capacity
        scope["link_capacity_bps"] = capacity

    # 特殊固定映射：WG88互联网线路_电信_100M_利用率
    if "WG88互联网线路_电信_100M_利用率" in text or "WG88互联网线路_电信_100M" in text:
        scope.update({
            "hostname": scope.get("hostname") or "WG404-H0304-C95-INT-ACC",
            "device_ip": scope.get("device_ip") or "10.189.250.8",
            "ip": scope.get("ip") or scope.get("device_ip") or "10.189.250.8",
            "instance": scope.get("instance") or scope.get("device_ip") or "10.189.250.8",
            "interfaces": ["Te1/0/1", "Te2/0/1"],
            "interface": "Te1/0/1|Te2/0/1",
            "if_name": "Te1/0/1|Te2/0/1",
            "ifName": "Te1/0/1|Te2/0/1",
            "interface_name": "Te1/0/1|Te2/0/1",
            "object_name": "WG88互联网线路_电信_100M",
            "interface_regex": "Te1/0/1|Te2/0/1",
            "capacity_bps": "100000000",
            "link_capacity_bps": "100000000",
            "link_name": "WG88互联网线路_电信_100M",
            "aggregate_circuit": True,
            "interface_count": 2,
        })
        if "出向" in text:
            scope["direction"] = "out"
            scope["traffic_direction"] = "out"
        return scope

    iface = _v95_iu_extract_interface(text)
    if iface and not scope.get("interface"):
        scope["interface"] = iface
        scope["if_name"] = iface
        scope["ifName"] = iface
        scope["interface_name"] = iface
        scope["interfaces"] = [iface]
        scope["interface_regex"] = iface
        scope["interface_count"] = 1

    if scope.get("interfaces") and not scope.get("interface_regex"):
        items = scope.get("interfaces")
        if isinstance(items, (list, tuple)):
            scope["interface_regex"] = "|".join(str(x).strip() for x in items if str(x).strip())
            scope["interface"] = scope.get("interface") or scope["interface_regex"]
            scope["if_name"] = scope.get("if_name") or scope["interface_regex"]
            scope["ifName"] = scope.get("ifName") or scope["interface_regex"]
            scope["interface_count"] = len([x for x in items if str(x).strip()])

    if scope.get("interface") and not scope.get("interface_regex"):
        scope["interface_regex"] = str(scope.get("interface"))

    return scope


if _v95_iu_original_classify_family is not None:
    def classify_family(event):
        original = _v95_iu_original_classify_family(event)
        original_family = ""
        if isinstance(original, dict):
            original_family = _v95_iu_safe_text(original.get("family"))

        text = _v95_iu_walk_text(event)
        if not _v95_iu_match(text):
            return original

        base = dict(original or {}) if isinstance(original, dict) else {}
        target_scope = dict(base.get("target_scope") or {})

        if isinstance(event, dict):
            labels = event.get("labels") if isinstance(event.get("labels"), dict) else {}
            annotations = event.get("annotations") if isinstance(event.get("annotations"), dict) else {}
            for key in ("device_ip", "ip", "instance", "hostname", "sysName", "interface", "ifName", "if_name", "object_name", "direction", "alarm_type", "alertname", "capacity_bps"):
                value = event.get(key)
                if value in (None, "", [], {}):
                    value = labels.get(key)
                if value in (None, "", [], {}):
                    value = annotations.get(key)
                if value not in (None, "", [], {}):
                    mapped = key
                    if key in ("ip", "instance") and not target_scope.get("device_ip"):
                        mapped = "device_ip"
                    if key == "sysName":
                        mapped = "hostname"
                    if key in ("ifName", "if_name") and not target_scope.get("interface"):
                        mapped = "interface"
                    if key == "alertname":
                        mapped = "alarm_type"
                    target_scope[mapped] = str(value).strip()

        target_scope = _v95_iu_enrich_scope(target_scope, text)

        base.update({
            "family": "interface_or_link_utilization_high",
            "family_confidence": "high",
            "match_source": "v9_5_interface_utilization_high_classifier",
            "match_reason": "matched Cisco interface/link utilization high wording",
            "legacy_playbook_type": "cisco_interface_utilization_high",
            "target_kind": "interface",
            "auto_execute_allowed": True,
            "target_scope": target_scope,
        })
        return base
# ===== v9.5 interface utilization high classifier end =====
