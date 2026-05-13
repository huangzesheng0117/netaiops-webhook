from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List

import yaml


BASE_DIR = Path("/opt/netaiops-webhook")
CATALOG_DIR = BASE_DIR / "catalogs" / "three_layer"
INVENTORY_PATH = CATALOG_DIR / "device_inventory.normalized.yaml"
TARGET_LOOKUP_PATH = CATALOG_DIR / "target_lookup.yaml"


PLATFORM_ALIASES: Dict[str, str] = {
    "nx-os": "cisco_nxos",
    "nxos": "cisco_nxos",
    "nexus": "cisco_nxos",
    "n9k": "cisco_nxos",
    "aci": "cisco_nxos",
    "apic": "cisco_nxos",

    "ios-xe": "cisco_iosxe",
    "iosxe": "cisco_iosxe",
    "ios xe": "cisco_iosxe",
    "ios": "cisco_iosxe",

    "vrp": "huawei_vrp",
    "huawei": "huawei_vrp",
    "huawei_vrp": "huawei_vrp",

    "comware": "h3c_comware",
    "h3c": "h3c_comware",
    "h3c_comware": "h3c_comware",

    "tmsh": "f5_tmsh",
    "f5": "f5_tmsh",
    "big-ip": "f5_tmsh",
    "bigip": "f5_tmsh",

    "fortigate": "fortigate_fortios",
    "fortios": "fortigate_fortios",
    "fortinet": "fortigate_fortios",
    "fg": "fortigate_fortios",
    "fgt": "fortigate_fortios",

    "hillstone": "hillstone_stoneos",
    "stoneos": "hillstone_stoneos",
    "sg6000": "hillstone_stoneos",
}


PLATFORM_COMMAND_MATRIX: Dict[str, Dict[str, str]] = {
    "cisco_nxos": {
        "show_interface_detail": "show interface {interface}",
        "show_interface_error_counters": "show interface {interface} counters errors",
        "show_interface_brief": "show interface brief",
        "show_portchannel_summary": "show port-channel summary",
        "show_lacp_neighbor": "show lacp neighbor",
        "show_recent_logs": "show logging last 50",

        "show_bgp_peer_detail": "show bgp ipv4 unicast neighbors {peer_ip}",
        "show_route_to_peer": "show ip route {peer_ip}",
        "ping_peer": "ping {peer_ip}",
        "show_bgp_config_snippet": "show running-config bgp",
        "show_ospf_peer_detail": "show ip ospf neighbors",

        "show_device_cpu": "show system resources",
        "show_device_memory": "show system resources",
    },

    "cisco_iosxe": {
        "show_interface_detail": "show interfaces {interface}",
        "show_interface_error_counters": "show interfaces {interface} counters errors",
        "show_interface_brief": "show ip interface brief",
        "show_portchannel_summary": "show etherchannel summary",
        "show_lacp_neighbor": "show lacp neighbor",
        "show_recent_logs": "show logging",

        "show_bgp_peer_detail": "show bgp ipv4 unicast neighbors {peer_ip}",
        "show_route_to_peer": "show ip route {peer_ip}",
        "ping_peer": "ping {peer_ip}",
        "show_bgp_config_snippet": "show running-config | section bgp",
        "show_ospf_peer_detail": "show ip ospf neighbor",

        "show_device_cpu": "show processes cpu sorted",
        "show_device_memory": "show processes memory sorted",
    },

    "huawei_vrp": {
        "show_interface_detail": "display interface {interface}",
        "show_interface_error_counters": "display interface {interface}",
        "show_interface_brief": "display interface brief",
        "show_portchannel_summary": "display eth-trunk",
        "show_lacp_neighbor": "display lacp peer",
        "show_recent_logs": "display logbuffer",

        "show_bgp_peer_detail": "display bgp peer {peer_ip} verbose",
        "show_route_to_peer": "display ip routing-table {peer_ip}",
        "ping_peer": "ping {peer_ip}",
        "show_bgp_config_snippet": "display current-configuration | include bgp",
        "show_ospf_peer_detail": "display ospf peer",

        "show_device_cpu": "display cpu-usage",
        "show_device_memory": "display memory-usage",
    },

    "h3c_comware": {
        "show_interface_detail": "display interface {interface}",
        "show_interface_error_counters": "display interface {interface}",
        "show_interface_brief": "display interface brief",
        "show_portchannel_summary": "display link-aggregation summary",
        "show_lacp_neighbor": "display link-aggregation verbose",
        "show_recent_logs": "display logbuffer",

        "show_bgp_peer_detail": "display bgp peer {peer_ip} verbose",
        "show_route_to_peer": "display ip routing-table {peer_ip}",
        "ping_peer": "ping {peer_ip}",
        "show_bgp_config_snippet": "display current-configuration | include bgp",
        "show_ospf_peer_detail": "display ospf peer",

        "show_device_cpu": "display cpu-usage",
        "show_device_memory": "display memory",
    },

    "fortigate_fortios": {
        "show_interface_detail": "diagnose hardware deviceinfo nic {interface}",
        "show_interface_error_counters": "diagnose hardware deviceinfo nic {interface}",
        "show_interface_brief": "get system interface physical",
        "show_portchannel_summary": "diagnose netlink aggregate list",
        "show_lacp_neighbor": "diagnose netlink aggregate list",
        "show_recent_logs": "get log event",

        "show_bgp_peer_detail": "get router info bgp neighbors {peer_ip}",
        "show_route_to_peer": "get router info routing-table details {peer_ip}",
        "show_bgp_config_snippet": "show router bgp",
        "show_ospf_peer_detail": "get router info ospf neighbor",

        "show_device_cpu": "get system performance status",
        "show_device_memory": "get system performance status",
    },

    "hillstone_stoneos": {
        "show_interface_detail": "show interface {interface}",
        "show_interface_error_counters": "show interface {interface}",
        "show_interface_brief": "show interface",
        "show_portchannel_summary": "show link-aggregation",
        "show_lacp_neighbor": "show lacp",
        "show_recent_logs": "show log event",

        "show_bgp_peer_detail": "show ip bgp neighbors {peer_ip}",
        "show_route_to_peer": "show ip route {peer_ip}",
        "ping_peer": "ping {peer_ip}",
        "show_bgp_config_snippet": "show configuration bgp",
        "show_ospf_peer_detail": "show ip ospf neighbor",

        "show_device_cpu": "show cpu",
        "show_device_memory": "show memory",
    },

    "f5_tmsh": {
        "show_recent_logs": "tmsh show sys log",
        "show_f5_pool_list": "tmsh show ltm pool",
        "show_f5_pool_members": "tmsh show ltm pool members",
        "show_f5_pool_config": "tmsh list ltm pool",
        "show_f5_connections": "tmsh show sys connection",
        "show_f5_performance": "tmsh show sys performance system",

        "show_device_cpu": "tmsh show sys performance system",
        "show_device_memory": "tmsh show sys memory",
    },

    "generic_network": {
        "show_recent_logs": "show logging",
        "show_interface_detail": "show interface {interface}",
        "show_interface_error_counters": "show interface {interface}",
        "show_interface_brief": "show ip interface brief",
        "show_device_cpu": "show processes cpu",
        "show_device_memory": "show processes memory",
    },
}


def _safe_lower(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


@lru_cache(maxsize=1)
def _load_yaml_file(path: str):
    p = Path(path)
    if not p.exists():
        return []

    data = yaml.safe_load(p.read_text(encoding="utf-8")) or []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("devices", "items", "records", "targets"):
            value = data.get(key)
            if isinstance(value, list):
                return value
    return []


def _iter_inventory_records() -> List[Dict[str, Any]]:
    records = []
    for item in _load_yaml_file(str(INVENTORY_PATH)):
        if isinstance(item, dict):
            records.append(item)
    for item in _load_yaml_file(str(TARGET_LOOKUP_PATH)):
        if isinstance(item, dict):
            records.append(item)
    return records


def _platform_from_value(value: Any) -> str:
    text = _safe_lower(value)
    if not text:
        return ""

    if text in PLATFORM_ALIASES:
        return PLATFORM_ALIASES[text]

    if "aci" in text or "nx-os" in text or "nxos" in text or "nexus" in text or "n9k" in text:
        return "cisco_nxos"
    if "ios-xe" in text or "iosxe" in text or "ios xe" in text:
        return "cisco_iosxe"
    if "huawei" in text or "vrp" in text:
        return "huawei_vrp"
    if "h3c" in text or "comware" in text:
        return "h3c_comware"
    if "f5" in text or "tmsh" in text or "big-ip" in text or "bigip" in text:
        return "f5_tmsh"
    if "fortigate" in text or "fortinet" in text or "fortios" in text:
        return "fortigate_fortios"
    if "hillstone" in text or "stoneos" in text or "sg6000" in text:
        return "hillstone_stoneos"

    return ""


def _match_inventory_record(event: Dict[str, Any]) -> Dict[str, Any]:
    device_ip = _safe_lower(event.get("device_ip") or event.get("ip") or event.get("host_ip"))
    hostname = _safe_lower(event.get("hostname"))
    instance = _safe_lower(event.get("instance"))

    for record in _iter_inventory_records():
        record_ip_values = [
            _safe_lower(record.get("device_ip")),
            _safe_lower(record.get("ip")),
            _safe_lower(record.get("instance")),
            _safe_lower(record.get("mgmt_ip")),
        ]
        record_name_values = [
            _safe_lower(record.get("hostname")),
            _safe_lower(record.get("sysname")),
            _safe_lower(record.get("name")),
            _safe_lower(record.get("device_name")),
        ]

        if device_ip and device_ip in record_ip_values:
            return record
        if hostname and hostname in record_name_values:
            return record
        if instance and instance in record_ip_values + record_name_values:
            return record

    return {}


def detect_platform(event: Dict[str, Any]) -> str:
    explicit_candidates = [
        event.get("platform"),
        event.get("os_family"),
        event.get("vendor_os"),
        event.get("netmiko_device_type"),
    ]

    for value in explicit_candidates:
        platform_key = _platform_from_value(value)
        if platform_key:
            return platform_key

    record = _match_inventory_record(event)
    for key in ("os_family", "platform", "os", "vendor_os", "netmiko_device_type"):
        platform_key = _platform_from_value(record.get(key))
        if platform_key:
            return platform_key

    combined = " ".join(
        [
            _safe_text(event.get("vendor")),
            _safe_text(event.get("job")),
            _safe_text(event.get("object_type")),
            _safe_text(event.get("hostname")),
            _safe_text(event.get("if_alias")),
            _safe_text(event.get("raw_text")),
            _safe_text(record.get("hostname")),
            _safe_text(record.get("sysname")),
            _safe_text(record.get("os_family")),
            _safe_text(record.get("platform")),
        ]
    ).lower()

    platform_key = _platform_from_value(combined)
    if platform_key:
        return platform_key

    vendor = _safe_lower(event.get("vendor") or record.get("vendor"))

    if "cisco" in vendor:
        return "cisco_iosxe"
    if "huawei" in vendor:
        return "huawei_vrp"
    if "h3c" in vendor:
        return "h3c_comware"
    if "f5" in vendor:
        return "f5_tmsh"
    if "fortigate" in vendor or "fortinet" in vendor:
        return "fortigate_fortios"
    if "hillstone" in vendor:
        return "hillstone_stoneos"

    return "generic_network"


def _render_template(template: str, arguments: Dict[str, Any]) -> str:
    try:
        return template.format(**arguments).strip()
    except Exception:
        return template.strip()


def resolve_execution_candidates(
    event: Dict[str, Any],
    family_result: Dict[str, Any],
    capability_plan: Dict[str, Any],
) -> List[Dict[str, Any]]:
    platform_key = detect_platform(event)
    platform_map = PLATFORM_COMMAND_MATRIX.get(platform_key, PLATFORM_COMMAND_MATRIX["generic_network"])

    results: List[Dict[str, Any]] = []
    order = 1

    for item in capability_plan.get("selected_capabilities", []) or []:
        capability = item.get("capability", "")
        template = platform_map.get(capability)
        if not template:
            continue

        arguments = dict(item.get("arguments", {}) or {})
        command = _render_template(template, arguments)
        if not command:
            continue

        results.append(
            {
                "order": order,
                "capability": capability,
                "command": command,
                "arguments": arguments,
                "reason": item.get("reason", "family_default"),
                "platform": platform_key,
                "judge_profile": item.get("judge_profile", "network_cli_generic"),
                "readonly": bool(item.get("readonly", True)),
                "risk": "low" if item.get("readonly", True) else "unknown",
                "family": family_result.get("family", ""),
            }
        )
        order += 1

    return results

# ===== v5 expanded family platform commands begin =====
# 说明：
# 为第六批新增的 Prometheus rule family 补平台命令矩阵。
# query_prometheus_metric_window / query_elastic_related_logs 属于内置证据能力，
# 不渲染为 MCP 设备命令，避免被 runner 当作设备命令执行。

V5_EXPANDED_PLATFORM_COMMANDS = {
    "cisco_nxos": {
        "show_device_environment": "show environment",
        "show_fan_status": "show environment fan",
        "show_power_status": "show environment power",
        "show_environment_temperature": "show environment temperature",
        "show_chassis_status": "show module",
        "show_module_status": "show module",
        "show_inventory": "show inventory",
        "show_interface_transceiver": "show interface {interface} transceiver details",
        "show_device_disk": "show file systems",
        "show_ha_state": "show system redundancy status",
        "show_cimc_hardware_status": "show inventory",
    },

    "cisco_iosxe": {
        "show_device_environment": "show environment all",
        "show_fan_status": "show environment all",
        "show_power_status": "show environment all",
        "show_environment_temperature": "show environment all",
        "show_chassis_status": "show platform",
        "show_module_status": "show platform",
        "show_inventory": "show inventory",
        "show_interface_transceiver": "show interfaces {interface} transceiver detail",
        "show_device_disk": "show file systems",
        "show_ha_state": "show redundancy states",
        "show_cimc_hardware_status": "show inventory",
    },

    "huawei_vrp": {
        "show_device_environment": "display environment",
        "show_fan_status": "display fan",
        "show_power_status": "display power",
        "show_environment_temperature": "display temperature all",
        "show_chassis_status": "display device",
        "show_module_status": "display device",
        "show_inventory": "display device manuinfo",
        "show_interface_transceiver": "display transceiver interface {interface} verbose",
        "show_device_disk": "display storage",
        "show_ha_state": "display device",
        "show_cimc_hardware_status": "display device manuinfo",
    },

    "h3c_comware": {
        "show_device_environment": "display environment",
        "show_fan_status": "display fan",
        "show_power_status": "display power",
        "show_environment_temperature": "display environment",
        "show_chassis_status": "display device",
        "show_module_status": "display device",
        "show_inventory": "display device manuinfo",
        "show_interface_transceiver": "display transceiver interface {interface} verbose",
        "show_device_disk": "display storage",
        "show_ha_state": "display irf",
        "show_cimc_hardware_status": "display device manuinfo",
    },

    "f5_tmsh": {
        "show_device_environment": "tmsh show sys hardware",
        "show_fan_status": "tmsh show sys hardware",
        "show_power_status": "tmsh show sys hardware",
        "show_environment_temperature": "tmsh show sys hardware",
        "show_chassis_status": "tmsh show sys hardware",
        "show_module_status": "tmsh show sys hardware",
        "show_inventory": "tmsh show sys hardware",
        "show_device_disk": "tmsh show sys disk",
        "show_ha_state": "tmsh show sys failover",
        "show_cimc_hardware_status": "tmsh show sys hardware",
    },

    "fortigate_fortios": {
        "show_device_environment": "get system status",
        "show_fan_status": "get system status",
        "show_power_status": "get system status",
        "show_environment_temperature": "get system performance status",
        "show_chassis_status": "get system status",
        "show_module_status": "get system status",
        "show_inventory": "get system status",
        "show_interface_transceiver": "diagnose hardware deviceinfo nic {interface}",
        "show_device_disk": "get system status",
        "show_ha_state": "get system ha status",
        "show_cimc_hardware_status": "get system status",
    },

    "hillstone_stoneos": {
        "show_device_environment": "show environment",
        "show_fan_status": "show fan",
        "show_power_status": "show power",
        "show_environment_temperature": "show temperature",
        "show_chassis_status": "show hardware",
        "show_module_status": "show hardware",
        "show_inventory": "show hardware",
        "show_interface_transceiver": "show interface {interface}",
        "show_device_disk": "show storage",
        "show_ha_state": "show ha",
        "show_cimc_hardware_status": "show hardware",
    },

    "generic_network": {
        "show_device_environment": "show environment",
        "show_fan_status": "show environment",
        "show_power_status": "show environment",
        "show_environment_temperature": "show environment",
        "show_chassis_status": "show inventory",
        "show_module_status": "show inventory",
        "show_inventory": "show inventory",
        "show_interface_transceiver": "show interface {interface} transceiver details",
        "show_device_disk": "show file systems",
        "show_ha_state": "show redundancy",
        "show_cimc_hardware_status": "show inventory",
    },
}


for _v5_platform, _v5_commands in V5_EXPANDED_PLATFORM_COMMANDS.items():
    PLATFORM_COMMAND_MATRIX.setdefault(_v5_platform, {})
    PLATFORM_COMMAND_MATRIX[_v5_platform].update(_v5_commands)
# ===== v5 expanded family platform commands end =====

# ===== v5 multi-interface PromQL command expansion begin =====
# 支持 PromQL 多接口聚合告警：
# 例如：
# sum(irate(ifHCOutOctets{ip=~"10.189.250.8",ifName=~"Te1/0/1|Te2/0/1"}[2m]))*8 > 80000000
#
# 过去只会对 Te1/0/1 执行 MCP 取证。
# 现在会把接口类 capability 展开成：
# show interface Te1/0/1
# show interface Te2/0/1
# show interface Te1/0/1 counters errors
# show interface Te2/0/1 counters errors

import copy as _v16_copy
import json as _v16_json
import re as _v16_re
import urllib.parse as _v16_urlparse
from pathlib import Path as _V16Path


try:
    _v16_original_resolve_execution_candidates = resolve_execution_candidates
except NameError:
    _v16_original_resolve_execution_candidates = None


V16_INTERFACE_EXPAND_CAPABILITIES = {
    "show_interface_detail",
    "show_interface_error_counters",
    "show_interface_transceiver",
    "show_interface_state",
    "show_interface_traffic_rate",
}


V16_RULE_FILES = [
    _V16Path("/opt/netaiops-webhook/input/prometheus_rules.txt"),
    _V16Path("/opt/netaiops-webhook/input/rules.txt"),
    _V16Path("/opt/netaiops-webhook/rules.txt"),
]


def _v16_safe_text(value):
    if value is None:
        return ""

    if isinstance(value, (dict, list, tuple, set)):
        try:
            return _v16_json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)

    return str(value).strip()


def _v16_walk_text(obj, max_depth=5):
    parts = []

    def walk(value, depth):
        if depth > max_depth:
            return

        if value is None:
            return

        if isinstance(value, dict):
            for key, item in value.items():
                parts.append(_v16_safe_text(key))
                walk(item, depth + 1)
            return

        if isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item, depth + 1)
            return

        parts.append(_v16_safe_text(value))

    walk(obj, 0)

    raw = " ".join(x for x in parts if x)
    decoded = _v16_urlparse.unquote(raw)

    return raw + " " + decoded


def _v16_event_tokens_for_rule_lookup(event):
    text = _v16_walk_text(event)

    tokens = set()

    for m in _v16_re.finditer(r"[A-Za-z0-9_\-\u4e00-\u9fff]+(?:_[A-Za-z0-9_\-\u4e00-\u9fff]+)+", text):
        token = m.group(0).strip()
        if len(token) >= 8:
            tokens.add(token)

    if isinstance(event, dict):
        labels = event.get("labels") or {}
        annotations = event.get("annotations") or {}

        for obj in (event, labels, annotations):
            if not isinstance(obj, dict):
                continue

            for key in ("alertname", "alarm_type", "summary", "description", "raw_text"):
                value = _v16_safe_text(obj.get(key))
                if value and len(value) >= 8:
                    tokens.add(value)

    return sorted(tokens, key=len, reverse=True)[:20]


def _v16_rule_context_from_event(event):
    tokens = _v16_event_tokens_for_rule_lookup(event)

    if not tokens:
        return ""

    contexts = []

    for path in V16_RULE_FILES:
        if not path.exists():
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        for token in tokens:
            pos = text.find(token)
            if pos < 0:
                continue

            start = max(0, pos - 2500)
            end = min(len(text), pos + 4500)
            contexts.append(text[start:end])

            if len(contexts) >= 5:
                break

        if len(contexts) >= 5:
            break

    return "\n".join(contexts)


def _v16_text_blob(event, family_result, plan):
    parts = [
        _v16_walk_text(event),
        _v16_walk_text(family_result),
        _v16_walk_text(plan),
        _v16_rule_context_from_event(event),
    ]

    text = "\n".join(x for x in parts if x)
    return _v16_urlparse.unquote(text)


def _v16_is_plain_interface_token(value):
    value = _v16_safe_text(value)

    if not value:
        return False

    if len(value) > 80:
        return False

    # 排除明显正则表达式，而保留 Te1/0/1、Eth1/1、port-channel27、Ten-GigabitEthernet1/0/1。
    if any(ch in value for ch in ("*", "+", "?", "^", "$", "[", "]", "(", ")", "{", "}")):
        return False

    return bool(_v16_re.match(r"^[A-Za-z][A-Za-z0-9_\-./]+$", value))


def _v16_split_interface_regex(expr):
    expr = _v16_safe_text(expr).strip().strip('"').strip("'")

    if "|" not in expr:
        return []

    items = []

    for item in expr.split("|"):
        item = item.strip().strip('"').strip("'")
        if _v16_is_plain_interface_token(item):
            items.append(item)

    result = []
    seen = set()

    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)

    if len(result) >= 2:
        return result

    return []


def _v16_extract_multi_interfaces(event, family_result, plan):
    text = _v16_text_blob(event, family_result, plan)

    patterns = [
        r'ifName\s*=~\s*"([^"]+\|[^"]+)"',
        r"ifName\s*=~\s*'([^']+\|[^']+)'",
        r'ifDescr\s*=~\s*"([^"]+\|[^"]+)"',
        r"ifDescr\s*=~\s*'([^']+\|[^']+)'",
        r'interface\s*=~\s*"([^"]+\|[^"]+)"',
        r"interface\s*=~\s*'([^']+\|[^']+)'",
        r'port\s*[:=]\s*"?(?P<ports>[A-Za-z][A-Za-z0-9_\-./]+(?:\|[A-Za-z][A-Za-z0-9_\-./]+)+)"?',
    ]

    for pattern in patterns:
        m = _v16_re.search(pattern, text, flags=_v16_re.IGNORECASE)
        if not m:
            continue

        expr = m.groupdict().get("ports") or m.group(1)
        interfaces = _v16_split_interface_regex(expr)

        if len(interfaces) >= 2:
            return interfaces

    return []


def _v16_get_primary_interface(event, family_result, plan, commands):
    candidates = []

    for obj in (
        event,
        family_result,
        (family_result or {}).get("target_scope") if isinstance(family_result, dict) else {},
        plan,
        (plan or {}).get("target_scope") if isinstance(plan, dict) else {},
    ):
        if not isinstance(obj, dict):
            continue

        for key in ("interface", "ifName", "if_name", "port", "object_name"):
            value = _v16_safe_text(obj.get(key))
            if _v16_is_plain_interface_token(value):
                candidates.append(value)

        labels = obj.get("labels")
        if isinstance(labels, dict):
            for key in ("interface", "ifName", "if_name", "port"):
                value = _v16_safe_text(labels.get(key))
                if _v16_is_plain_interface_token(value):
                    candidates.append(value)

    for command in commands:
        cmd = _v16_safe_text(command)
        for m in _v16_re.finditer(r"\b((?:Te|Gi|Eth|Ethernet|TenGigabitEthernet|GigabitEthernet|port-channel|Port-channel|Po)[A-Za-z0-9_\-./]+)\b", cmd):
            value = m.group(1)
            if _v16_is_plain_interface_token(value):
                candidates.append(value)

    for item in candidates:
        if item:
            return item

    return ""


def _v16_expand_interface_candidates(candidates, interfaces, primary_interface):
    if not interfaces or len(interfaces) < 2:
        return candidates

    expanded = []
    seen = set()

    for item in candidates or []:
        if not isinstance(item, dict):
            continue

        capability = _v16_safe_text(item.get("capability"))
        command = _v16_safe_text(item.get("command"))

        if capability not in V16_INTERFACE_EXPAND_CAPABILITIES:
            key = (capability, command)
            if key not in seen:
                seen.add(key)
                expanded.append(item)
            continue

        base_interface = primary_interface

        if base_interface and base_interface not in command:
            base_interface = ""

        if not base_interface:
            for iface in interfaces:
                if iface in command:
                    base_interface = iface
                    break

        if not base_interface:
            key = (capability, command)
            if key not in seen:
                seen.add(key)
                expanded.append(item)
            continue

        for iface in interfaces:
            new_item = _v16_copy.deepcopy(item)
            new_item["command"] = command.replace(base_interface, iface)
            new_item["interface"] = iface
            new_item["multi_interface_expanded"] = True
            new_item["multi_interface_source"] = "promql_ifName_regex"
            new_item["multi_interfaces"] = interfaces

            arguments = dict(new_item.get("arguments") or {})
            arguments["interface"] = iface
            arguments["interfaces"] = interfaces
            new_item["arguments"] = arguments

            key = (capability, new_item["command"])

            if key in seen:
                continue

            seen.add(key)
            expanded.append(new_item)

    for idx, item in enumerate(expanded, start=1):
        if isinstance(item, dict):
            item["order"] = idx

    return expanded


if _v16_original_resolve_execution_candidates is not None:
    def resolve_execution_candidates(event, family_result, plan):
        candidates = _v16_original_resolve_execution_candidates(event, family_result, plan)

        interfaces = _v16_extract_multi_interfaces(event, family_result, plan)

        if len(interfaces) < 2:
            return candidates

        primary_interface = _v16_get_primary_interface(
            event,
            family_result,
            plan,
            [x.get("command") for x in candidates if isinstance(x, dict)],
        )

        expanded = _v16_expand_interface_candidates(candidates, interfaces, primary_interface)

        return expanded
# ===== v5 multi-interface PromQL command expansion end =====

# ===== v5 Cisco IOS-XE interface command normalization begin =====
# 修复场景：
# Cisco IOS-XE C9500 上 show interfaces Te1/0/1 作为接口详情命令失败。
# 改为更稳妥的 show interface TenGigabitEthernet1/0/1。
#
# 同时保留 counters errors 和 etherchannel summary 的 IOS-XE 命令形态。

import copy as _v17_copy
import re as _v17_re


try:
    _v17_original_resolve_execution_candidates = resolve_execution_candidates
except NameError:
    _v17_original_resolve_execution_candidates = None


def _v17_safe_text(value):
    if value is None:
        return ""
    return str(value).strip()


def _v17_iosxe_full_interface_name(interface):
    value = _v17_safe_text(interface)

    if not value:
        return value

    m = _v17_re.match(r"^Te(\d+/\d+/\d+)$", value, flags=_v17_re.IGNORECASE)
    if m:
        return "TenGigabitEthernet" + m.group(1)

    m = _v17_re.match(r"^Gi(\d+/\d+/\d+)$", value, flags=_v17_re.IGNORECASE)
    if m:
        return "GigabitEthernet" + m.group(1)

    m = _v17_re.match(r"^Fo(\d+/\d+/\d+)$", value, flags=_v17_re.IGNORECASE)
    if m:
        return "FortyGigabitEthernet" + m.group(1)

    m = _v17_re.match(r"^Hu(\d+/\d+/\d+)$", value, flags=_v17_re.IGNORECASE)
    if m:
        return "HundredGigE" + m.group(1)

    m = _v17_re.match(r"^Twe(\d+/\d+/\d+)$", value, flags=_v17_re.IGNORECASE)
    if m:
        return "TwentyFiveGigE" + m.group(1)

    m = _v17_re.match(r"^Po(\d+)$", value, flags=_v17_re.IGNORECASE)
    if m:
        return "Port-channel" + m.group(1)

    return value


def _v17_iosxe_command_normalize(command):
    command = _v17_safe_text(command)

    if not command:
        return command

    # 接口详情命令：show interfaces Te1/0/1 -> show interface TenGigabitEthernet1/0/1
    m = _v17_re.match(
        r"^show\s+interfaces\s+(\S+)\s*$",
        command,
        flags=_v17_re.IGNORECASE,
    )
    if m:
        return "show interface " + _v17_iosxe_full_interface_name(m.group(1))

    # 接口详情命令：show interface Te1/0/1 -> show interface TenGigabitEthernet1/0/1
    m = _v17_re.match(
        r"^show\s+interface\s+(\S+)\s*$",
        command,
        flags=_v17_re.IGNORECASE,
    )
    if m:
        return "show interface " + _v17_iosxe_full_interface_name(m.group(1))

    # 计数器命令保留 show interfaces ... counters errors 形态，但展开接口全名。
    m = _v17_re.match(
        r"^show\s+interfaces\s+(\S+)\s+counters\s+errors\s*$",
        command,
        flags=_v17_re.IGNORECASE,
    )
    if m:
        return "show interfaces " + _v17_iosxe_full_interface_name(m.group(1)) + " counters errors"

    # 兜底替换命令中的短接口名。
    def repl(match):
        return _v17_iosxe_full_interface_name(match.group(0))

    command = _v17_re.sub(
        r"\b(?:Te|Gi|Fo|Hu|Twe|Po)\d+(?:/\d+/\d+)?\b",
        repl,
        command,
        flags=_v17_re.IGNORECASE,
    )

    return command


def _v17_is_iosxe_event(event):
    try:
        platform = detect_platform(event)
    except Exception:
        platform = ""

    platform = _v17_safe_text(platform).lower()

    if platform == "cisco_iosxe":
        return True

    if isinstance(event, dict):
        text = " ".join(
            [
                _v17_safe_text(event.get("vendor")),
                _v17_safe_text(event.get("platform")),
                _v17_safe_text(event.get("os_family")),
                _v17_safe_text(event.get("job")),
            ]
        ).lower()

        if "ios-xe" in text or "iosxe" in text or "cat9k" in text or "c9500" in text:
            return True

    return False


if _v17_original_resolve_execution_candidates is not None:
    def resolve_execution_candidates(event, family_result, plan):
        candidates = _v17_original_resolve_execution_candidates(event, family_result, plan)

        if not _v17_is_iosxe_event(event):
            return candidates

        normalized = []
        seen = set()

        for item in candidates or []:
            if not isinstance(item, dict):
                continue

            new_item = _v17_copy.deepcopy(item)
            old_command = _v17_safe_text(new_item.get("command"))
            new_command = _v17_iosxe_command_normalize(old_command)

            new_item["command"] = new_command

            if old_command != new_command:
                new_item["iosxe_command_normalized"] = True
                new_item["original_command"] = old_command

            args = dict(new_item.get("arguments") or {})
            iface = _v17_safe_text(args.get("interface") or new_item.get("interface"))
            if iface:
                args["interface"] = _v17_iosxe_full_interface_name(iface)
                new_item["interface"] = args["interface"]

            new_item["arguments"] = args

            key = (_v17_safe_text(new_item.get("capability")), new_command)

            if key in seen:
                continue

            seen.add(key)
            normalized.append(new_item)

        for index, item in enumerate(normalized, start=1):
            item["order"] = index

        return normalized


try:
    PLATFORM_COMMAND_MATRIX.setdefault("cisco_iosxe", {})
    PLATFORM_COMMAND_MATRIX["cisco_iosxe"]["show_interface_detail"] = "show interface {interface}"
    PLATFORM_COMMAND_MATRIX["cisco_iosxe"]["show_interface_error_counters"] = "show interfaces {interface} counters errors"
    PLATFORM_COMMAND_MATRIX["cisco_iosxe"]["show_portchannel_summary"] = "show etherchannel summary"
except Exception:
    pass
# ===== v5 Cisco IOS-XE interface command normalization end =====

# ===== v5 real multi-interface interface-group final override begin =====
# 最终修复目标：
# 1. 真实 Alertmanager 告警未携带 PromQL 时，仍可通过 config/interface_groups.yaml 识别业务线路聚合接口。
# 2. WG88互联网线路_电信_100M -> Te1/0/1 + Te2/0/1。
# 3. Cisco IOS-XE C9500 接口详情命令统一使用：
#    show interfaces TenGigabitEthernet1/0/1
#    而不是 show interface TenGigabitEthernet1/0/1。
# 4. 对接口详情、接口错误计数类 capability 按接口组展开。

import copy as _v18_copy
import json as _v18_json
import re as _v18_re
import urllib.parse as _v18_urlparse
from pathlib import Path as _V18Path

try:
    import yaml as _v18_yaml
except Exception:
    _v18_yaml = None

try:
    _v18_original_resolve_execution_candidates = resolve_execution_candidates
except NameError:
    _v18_original_resolve_execution_candidates = None


V18_INTERFACE_GROUP_FILE = _V18Path("/opt/netaiops-webhook/config/interface_groups.yaml")

V18_INTERFACE_EXPAND_CAPABILITIES = {
    "show_interface_detail",
    "show_interface_error_counters",
    "show_interface_transceiver",
    "show_interface_state",
    "show_interface_traffic_rate",
}


def _v18_safe_text(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        try:
            return _v18_json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)
    return str(value).strip()


def _v18_walk_text(obj, max_depth=6):
    parts = []

    def walk(value, depth=0):
        if depth > max_depth:
            return
        if value is None:
            return
        if isinstance(value, dict):
            for k, v in value.items():
                parts.append(_v18_safe_text(k))
                walk(v, depth + 1)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item, depth + 1)
            return
        parts.append(_v18_safe_text(value))

    walk(obj)
    return _v18_urlparse.unquote(" ".join(x for x in parts if x))


def _v18_event_text(event, family_result=None, plan=None):
    return "\n".join(
        [
            _v18_walk_text(event),
            _v18_walk_text(family_result),
            _v18_walk_text(plan),
        ]
    )


def _v18_load_interface_groups():
    if not V18_INTERFACE_GROUP_FILE.exists() or _v18_yaml is None:
        return []

    try:
        data = _v18_yaml.safe_load(V18_INTERFACE_GROUP_FILE.read_text(encoding="utf-8")) or {}
    except Exception:
        return []

    groups = data.get("interface_groups", [])
    if not isinstance(groups, list):
        return []

    return [x for x in groups if isinstance(x, dict)]


def _v18_get_event_device_ip(event, family_result=None, plan=None):
    for obj in (event, family_result, plan):
        if not isinstance(obj, dict):
            continue

        for key in ("device_ip", "ip", "instance"):
            value = _v18_safe_text(obj.get(key))
            if value:
                # instance 可能是 10.189.250.8:9116
                m = _v18_re.search(r"(\d+\.\d+\.\d+\.\d+)", value)
                if m:
                    return m.group(1)

        labels = obj.get("labels")
        if isinstance(labels, dict):
            for key in ("device_ip", "ip", "instance"):
                value = _v18_safe_text(labels.get(key))
                if value:
                    m = _v18_re.search(r"(\d+\.\d+\.\d+\.\d+)", value)
                    if m:
                        return m.group(1)

    return ""


def _v18_interfaces_from_config(event, family_result=None, plan=None):
    text = _v18_event_text(event, family_result, plan)
    device_ip = _v18_get_event_device_ip(event, family_result, plan)

    for group in _v18_load_interface_groups():
        group_device_ip = _v18_safe_text(group.get("device_ip"))

        if group_device_ip and device_ip and group_device_ip != device_ip:
            continue

        keywords = group.get("match_keywords") or []
        if isinstance(keywords, str):
            keywords = [keywords]

        matched = False
        for keyword in keywords:
            keyword = _v18_safe_text(keyword)
            if keyword and keyword in text:
                matched = True
                break

        if not matched:
            continue

        interfaces = group.get("interfaces") or []
        if not isinstance(interfaces, list):
            continue

        result = []
        seen = set()

        for iface in interfaces:
            iface = _v18_safe_text(iface)
            if iface and iface not in seen:
                seen.add(iface)
                result.append(iface)

        if len(result) >= 2:
            return result

    return []


def _v18_interfaces_from_promql_text(event, family_result=None, plan=None):
    text = _v18_event_text(event, family_result, plan)

    patterns = [
        r'ifName\s*=~\s*"([^"]+\|[^"]+)"',
        r"ifName\s*=~\s*'([^']+\|[^']+)'",
        r'ifDescr\s*=~\s*"([^"]+\|[^"]+)"',
        r"ifDescr\s*=~\s*'([^']+\|[^']+)'",
    ]

    for pattern in patterns:
        m = _v18_re.search(pattern, text, flags=_v18_re.IGNORECASE)
        if not m:
            continue

        items = []
        seen = set()

        for item in m.group(1).split("|"):
            item = item.strip().strip('"').strip("'")
            if not _v18_re.match(r"^[A-Za-z][A-Za-z0-9_\-./]+$", item):
                continue
            if item in seen:
                continue
            seen.add(item)
            items.append(item)

        if len(items) >= 2:
            return items

    return []


def _v18_get_family(family_result):
    if isinstance(family_result, dict):
        return _v18_safe_text(family_result.get("family"))
    return ""


def _v18_is_interface_traffic_family(family_result):
    return _v18_get_family(family_result) in {
        "interface_or_link_utilization_high",
        "interface_or_link_traffic_drop",
    }


def _v18_is_iosxe_event(event):
    try:
        platform = _v18_safe_text(detect_platform(event)).lower()
        if platform == "cisco_iosxe":
            return True
    except Exception:
        pass

    text = _v18_walk_text(event).lower()

    return (
        "ios-xe" in text
        or "iosxe" in text
        or "cat9k" in text
        or "c9500" in text
        or "cisco_iosxe" in text
    )


def _v18_full_iosxe_interface(interface):
    value = _v18_safe_text(interface)

    if not value:
        return value

    m = _v18_re.match(r"^Te(\d+/\d+/\d+)$", value, flags=_v18_re.IGNORECASE)
    if m:
        return "TenGigabitEthernet" + m.group(1)

    m = _v18_re.match(r"^TenGigabitEthernet(\d+/\d+/\d+)$", value, flags=_v18_re.IGNORECASE)
    if m:
        return "TenGigabitEthernet" + m.group(1)

    m = _v18_re.match(r"^Gi(\d+/\d+/\d+)$", value, flags=_v18_re.IGNORECASE)
    if m:
        return "GigabitEthernet" + m.group(1)

    m = _v18_re.match(r"^GigabitEthernet(\d+/\d+/\d+)$", value, flags=_v18_re.IGNORECASE)
    if m:
        return "GigabitEthernet" + m.group(1)

    m = _v18_re.match(r"^Fo(\d+/\d+/\d+)$", value, flags=_v18_re.IGNORECASE)
    if m:
        return "FortyGigabitEthernet" + m.group(1)

    m = _v18_re.match(r"^FortyGigabitEthernet(\d+/\d+/\d+)$", value, flags=_v18_re.IGNORECASE)
    if m:
        return "FortyGigabitEthernet" + m.group(1)

    m = _v18_re.match(r"^Hu(\d+/\d+/\d+)$", value, flags=_v18_re.IGNORECASE)
    if m:
        return "HundredGigE" + m.group(1)

    m = _v18_re.match(r"^Po(\d+)$", value, flags=_v18_re.IGNORECASE)
    if m:
        return "Port-channel" + m.group(1)

    return value


def _v18_interface_aliases(interface):
    value = _v18_safe_text(interface)

    if not value:
        return []

    aliases = {value}

    full = _v18_full_iosxe_interface(value)
    if full:
        aliases.add(full)

    m = _v18_re.match(r"^TenGigabitEthernet(\d+/\d+/\d+)$", full, flags=_v18_re.IGNORECASE)
    if m:
        aliases.add("Te" + m.group(1))

    m = _v18_re.match(r"^GigabitEthernet(\d+/\d+/\d+)$", full, flags=_v18_re.IGNORECASE)
    if m:
        aliases.add("Gi" + m.group(1))

    m = _v18_re.match(r"^FortyGigabitEthernet(\d+/\d+/\d+)$", full, flags=_v18_re.IGNORECASE)
    if m:
        aliases.add("Fo" + m.group(1))

    m = _v18_re.match(r"^Port-channel(\d+)$", full, flags=_v18_re.IGNORECASE)
    if m:
        aliases.add("Po" + m.group(1))

    return sorted(aliases, key=len, reverse=True)


def _v18_target_alias_like(source_alias, target_interface):
    source_alias = _v18_safe_text(source_alias)
    target_interface = _v18_safe_text(target_interface)

    if source_alias.lower().startswith("tengigabitethernet"):
        return _v18_full_iosxe_interface(target_interface)

    if source_alias.lower().startswith("gigabitethernet"):
        return _v18_full_iosxe_interface(target_interface)

    if source_alias.lower().startswith("fortygigabitethernet"):
        return _v18_full_iosxe_interface(target_interface)

    if source_alias.lower().startswith("port-channel"):
        return _v18_full_iosxe_interface(target_interface)

    return target_interface


def _v18_replace_interface(command, base_interface, target_interface):
    command = _v18_safe_text(command)

    for alias in _v18_interface_aliases(base_interface):
        if alias and alias in command:
            return command.replace(alias, _v18_target_alias_like(alias, target_interface))

    return command


def _v18_get_base_interface(event, family_result, plan, candidates, interfaces):
    candidates_text = _v18_walk_text(candidates)

    for iface in interfaces:
        for alias in _v18_interface_aliases(iface):
            if alias and alias in candidates_text:
                return iface

    for obj in (event, family_result, plan):
        if not isinstance(obj, dict):
            continue

        for key in ("interface", "ifName", "if_name", "port", "object_name"):
            value = _v18_safe_text(obj.get(key))
            if value:
                return value

        labels = obj.get("labels")
        if isinstance(labels, dict):
            for key in ("interface", "ifName", "if_name", "port"):
                value = _v18_safe_text(labels.get(key))
                if value:
                    return value

    return interfaces[0] if interfaces else ""


def _v18_normalize_iosxe_command(command):
    command = _v18_safe_text(command)

    m = _v18_re.match(
        r"^show\s+interface(?:s)?\s+(\S+)\s+counters\s+errors\s*$",
        command,
        flags=_v18_re.IGNORECASE,
    )
    if m:
        return "show interfaces " + _v18_full_iosxe_interface(m.group(1)) + " counters errors"

    m = _v18_re.match(
        r"^show\s+interface(?:s)?\s+(\S+)\s*$",
        command,
        flags=_v18_re.IGNORECASE,
    )
    if m:
        return "show interfaces " + _v18_full_iosxe_interface(m.group(1))

    return command


def _v18_expand_candidates(candidates, interfaces, base_interface, is_iosxe):
    expanded = []
    seen = set()

    for item in candidates or []:
        if not isinstance(item, dict):
            continue

        capability = _v18_safe_text(item.get("capability"))
        command = _v18_safe_text(item.get("command"))

        if capability not in V18_INTERFACE_EXPAND_CAPABILITIES:
            new_item = _v18_copy.deepcopy(item)

            if is_iosxe:
                new_item["command"] = _v18_normalize_iosxe_command(command)

            key = (capability, new_item.get("command"))

            if key not in seen:
                seen.add(key)
                expanded.append(new_item)

            continue

        for iface in interfaces:
            new_item = _v18_copy.deepcopy(item)

            new_command = _v18_replace_interface(command, base_interface, iface)

            if is_iosxe:
                new_command = _v18_normalize_iosxe_command(new_command)

            new_item["command"] = new_command
            new_item["interface"] = _v18_full_iosxe_interface(iface) if is_iosxe else iface
            new_item["multi_interface_expanded"] = True
            new_item["multi_interface_source"] = "interface_group_or_promql"
            new_item["multi_interfaces"] = interfaces

            args = dict(new_item.get("arguments") or {})
            args["interface"] = new_item["interface"]
            args["interfaces"] = interfaces
            new_item["arguments"] = args

            key = (capability, new_command)

            if key in seen:
                continue

            seen.add(key)
            expanded.append(new_item)

    for idx, item in enumerate(expanded, start=1):
        if isinstance(item, dict):
            item["order"] = idx

    return expanded


if _v18_original_resolve_execution_candidates is not None:
    def resolve_execution_candidates(event, family_result, plan):
        candidates = _v18_original_resolve_execution_candidates(event, family_result, plan)

        is_iosxe = _v18_is_iosxe_event(event)

        # IOS-XE 即便不是多接口，也要统一修正 show interface(s) 命令格式。
        if is_iosxe and not _v18_is_interface_traffic_family(family_result):
            fixed = []
            for item in candidates or []:
                if not isinstance(item, dict):
                    continue
                new_item = _v18_copy.deepcopy(item)
                new_item["command"] = _v18_normalize_iosxe_command(new_item.get("command"))
                fixed.append(new_item)
            return fixed

        if not _v18_is_interface_traffic_family(family_result):
            return candidates

        interfaces = (
            _v18_interfaces_from_config(event, family_result, plan)
            or _v18_interfaces_from_promql_text(event, family_result, plan)
        )

        if len(interfaces) < 2:
            if is_iosxe:
                fixed = []
                for item in candidates or []:
                    if not isinstance(item, dict):
                        continue
                    new_item = _v18_copy.deepcopy(item)
                    new_item["command"] = _v18_normalize_iosxe_command(new_item.get("command"))
                    fixed.append(new_item)
                return fixed

            return candidates

        base_interface = _v18_get_base_interface(event, family_result, plan, candidates, interfaces)

        return _v18_expand_candidates(candidates, interfaces, base_interface, is_iosxe)


try:
    PLATFORM_COMMAND_MATRIX.setdefault("cisco_iosxe", {})
    PLATFORM_COMMAND_MATRIX["cisco_iosxe"]["show_interface_detail"] = "show interfaces {interface}"
    PLATFORM_COMMAND_MATRIX["cisco_iosxe"]["show_interface_error_counters"] = "show interfaces {interface} counters errors"
    PLATFORM_COMMAND_MATRIX["cisco_iosxe"]["show_portchannel_summary"] = "show etherchannel summary"
except Exception:
    pass
# ===== v5 real multi-interface interface-group final override end =====

# ===== v5 interface group best-match final override begin =====
# 修复场景：
# 同一 device_ip 下存在多条线路：
# - WG88互联网线路_电信_100M -> Te1/0/1 + Te2/0/1
# - WG88互联网线路_电信BGP_200M -> Te1/0/2 + Te2/0/2
#
# 旧逻辑只要命中宽泛关键词 “WG88互联网线路_电信” 就返回第一个 group，
# 导致 BGP_200M 被错误匹配到 100M 线路组。
#
# 新逻辑：
# 1. source_rules 完整命中优先级最高。
# 2. match_keywords 按命中关键词长度计分，越具体优先级越高。
# 3. 同分时 source_rules / keywords 更长的 group 优先。
# 4. 仍然要求 device_ip 匹配。

import json as _v19_json
import re as _v19_re
import urllib.parse as _v19_urlparse
from pathlib import Path as _V19Path

try:
    import yaml as _v19_yaml
except Exception:
    _v19_yaml = None

V19_INTERFACE_GROUP_FILE = _V19Path("/opt/netaiops-webhook/config/interface_groups.yaml")


def _v19_safe_text(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        try:
            return _v19_json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)
    return str(value).strip()


def _v19_walk_text(obj, max_depth=6):
    parts = []

    def walk(value, depth=0):
        if depth > max_depth:
            return
        if value is None:
            return
        if isinstance(value, dict):
            for k, v in value.items():
                parts.append(_v19_safe_text(k))
                walk(v, depth + 1)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item, depth + 1)
            return
        parts.append(_v19_safe_text(value))

    walk(obj)
    return _v19_urlparse.unquote(" ".join(x for x in parts if x))


def _v19_event_text(event, family_result=None, plan=None):
    return "\n".join(
        [
            _v19_walk_text(event),
            _v19_walk_text(family_result),
            _v19_walk_text(plan),
        ]
    )


def _v19_load_interface_groups():
    if not V19_INTERFACE_GROUP_FILE.exists() or _v19_yaml is None:
        return []

    try:
        data = _v19_yaml.safe_load(V19_INTERFACE_GROUP_FILE.read_text(encoding="utf-8")) or {}
    except Exception:
        return []

    groups = data.get("interface_groups", [])
    if not isinstance(groups, list):
        return []

    return [x for x in groups if isinstance(x, dict)]


def _v19_get_event_device_ip(event, family_result=None, plan=None):
    for obj in (event, family_result, plan):
        if not isinstance(obj, dict):
            continue

        for key in ("device_ip", "ip", "instance"):
            value = _v19_safe_text(obj.get(key))
            if value:
                m = _v19_re.search(r"(\d+\.\d+\.\d+\.\d+)", value)
                if m:
                    return m.group(1)

        labels = obj.get("labels")
        if isinstance(labels, dict):
            for key in ("device_ip", "ip", "instance"):
                value = _v19_safe_text(labels.get(key))
                if value:
                    m = _v19_re.search(r"(\d+\.\d+\.\d+\.\d+)", value)
                    if m:
                        return m.group(1)

    return ""


def _v19_group_interfaces(group):
    interfaces = group.get("interfaces") or []
    if not isinstance(interfaces, list):
        return []

    result = []
    seen = set()

    for iface in interfaces:
        iface = _v19_safe_text(iface)
        if iface and iface not in seen:
            seen.add(iface)
            result.append(iface)

    return result


def _v19_score_group(group, text):
    score = 0
    matched_terms = []

    source_rules = group.get("source_rules") or []
    if isinstance(source_rules, str):
        source_rules = [source_rules]

    # 完整 rule name 命中最高优先级。
    for rule in source_rules:
        rule = _v19_safe_text(rule)
        if not rule:
            continue
        if rule in text:
            score += 100000 + len(rule) * 100
            matched_terms.append(("source_rule", rule))

    keywords = group.get("match_keywords") or []
    if isinstance(keywords, str):
        keywords = [keywords]

    for keyword in keywords:
        keyword = _v19_safe_text(keyword)
        if not keyword:
            continue
        if keyword in text:
            score += 1000 + len(keyword) * 10
            matched_terms.append(("keyword", keyword))

    name = _v19_safe_text(group.get("name"))
    if name and name in text:
        score += 5000 + len(name) * 20
        matched_terms.append(("name", name))

    description = _v19_safe_text(group.get("description"))
    if description and description in text:
        score += 3000 + len(description) * 10
        matched_terms.append(("description", description))

    return score, matched_terms


def _v19_interfaces_from_config_best_match(event, family_result=None, plan=None):
    text = _v19_event_text(event, family_result, plan)
    device_ip = _v19_get_event_device_ip(event, family_result, plan)

    candidates = []

    for group in _v19_load_interface_groups():
        group_device_ip = _v19_safe_text(group.get("device_ip"))

        if group_device_ip and device_ip and group_device_ip != device_ip:
            continue

        interfaces = _v19_group_interfaces(group)
        if len(interfaces) < 2:
            continue

        score, matched_terms = _v19_score_group(group, text)

        if score <= 0:
            continue

        candidates.append(
            {
                "score": score,
                "group": group,
                "interfaces": interfaces,
                "matched_terms": matched_terms,
                "max_term_len": max([len(x[1]) for x in matched_terms] or [0]),
            }
        )

    if not candidates:
        return []

    candidates.sort(
        key=lambda x: (
            x["score"],
            x["max_term_len"],
            len(_v19_safe_text(x["group"].get("name"))),
        ),
        reverse=True,
    )

    best = candidates[0]

    try:
        print(
            "V19_INTERFACE_GROUP_MATCH:",
            "group=" + _v19_safe_text(best["group"].get("name")),
            "device_ip=" + _v19_safe_text(best["group"].get("device_ip")),
            "interfaces=" + ",".join(best["interfaces"]),
            "score=" + str(best["score"]),
            "matched=" + ";".join([f"{a}:{b}" for a, b in best["matched_terms"][:5]]),
        )
    except Exception:
        pass

    return best["interfaces"]


# 覆盖 v18 中的同名函数；resolve_execution_candidates 运行时会引用全局最新定义。
def _v18_interfaces_from_config(event, family_result=None, plan=None):
    return _v19_interfaces_from_config_best_match(event, family_result, plan)
# ===== v5 interface group best-match final override end =====
