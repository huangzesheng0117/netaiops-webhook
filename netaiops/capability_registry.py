from typing import Any, Dict, List


CAPABILITY_REGISTRY: Dict[str, Dict[str, Any]] = {
    "show_interface_detail": {
        "category": "device_cli",
        "required_args": [],
        "readonly": True,
        "judge_profile": "network_cli_generic",
    },
    "show_interface_error_counters": {
        "category": "device_cli",
        "required_args": [],
        "readonly": True,
        "judge_profile": "network_cli_generic",
    },
    "show_interface_brief": {
        "category": "device_cli",
        "required_args": [],
        "readonly": True,
        "judge_profile": "network_cli_generic",
    },
    "show_portchannel_summary": {
        "category": "device_cli",
        "required_args": [],
        "readonly": True,
        "judge_profile": "network_cli_generic",
    },
    "show_lacp_neighbor": {
        "category": "device_cli",
        "required_args": [],
        "readonly": True,
        "judge_profile": "network_cli_generic",
    },
    "show_recent_logs": {
        "category": "device_cli",
        "required_args": [],
        "readonly": True,
        "judge_profile": "network_cli_generic",
    },
    "show_bgp_peer_detail": {
        "category": "device_cli",
        "required_args": ["peer_ip"],
        "readonly": True,
        "judge_profile": "network_cli_generic",
    },
    "show_route_to_peer": {
        "category": "device_cli",
        "required_args": ["peer_ip"],
        "readonly": True,
        "judge_profile": "network_cli_generic",
    },
    "ping_peer": {
        "category": "device_cli",
        "required_args": ["peer_ip"],
        "readonly": True,
        "judge_profile": "network_cli_generic",
    },
    "show_bgp_config_snippet": {
        "category": "device_cli",
        "required_args": [],
        "readonly": True,
        "judge_profile": "network_cli_generic",
    },
    "show_ospf_peer_detail": {
        "category": "device_cli",
        "required_args": [],
        "readonly": True,
        "judge_profile": "network_cli_generic",
    },
    "show_device_cpu": {
        "category": "device_cli",
        "required_args": [],
        "readonly": True,
        "judge_profile": "network_cli_generic",
    },
    "show_device_memory": {
        "category": "device_cli",
        "required_args": [],
        "readonly": True,
        "judge_profile": "network_cli_generic",
    },
    "show_f5_pool_list": {
        "category": "device_cli",
        "required_args": [],
        "readonly": True,
        "judge_profile": "f5_tmsh",
    },
    "show_f5_pool_members": {
        "category": "device_cli",
        "required_args": [],
        "readonly": True,
        "judge_profile": "f5_tmsh",
    },
    "show_f5_pool_config": {
        "category": "device_cli",
        "required_args": [],
        "readonly": True,
        "judge_profile": "f5_tmsh",
    },
    "show_f5_connections": {
        "category": "device_cli",
        "required_args": [],
        "readonly": True,
        "judge_profile": "f5_tmsh",
    },
    "show_f5_performance": {
        "category": "device_cli",
        "required_args": [],
        "readonly": True,
        "judge_profile": "f5_tmsh",
    },
}


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


def get_capability(capability: str) -> Dict[str, Any]:
    return CAPABILITY_REGISTRY.get(capability, {})


def _build_argument_map(event: Dict[str, Any]) -> Dict[str, Any]:
    interfaces = _split_interfaces(event.get("interfaces") or event.get("interface"))
    return {
        "device_ip": event.get("device_ip", "") or event.get("ip", "") or event.get("host_ip", ""),
        "hostname": event.get("hostname", ""),
        "peer_ip": event.get("peer_ip", "") or event.get("object_id", ""),
        "interface": event.get("interface", "") or event.get("object_name", ""),
        "interfaces": interfaces,
        "if_alias": event.get("if_alias", "") or event.get("ifAlias", ""),
        "job": event.get("job", ""),
        "carrier": event.get("carrier", ""),
        "link_name": event.get("link_name", ""),
        "pool_member": event.get("pool_member", "") or event.get("object_id", ""),
    }


def build_capability_plan(event: Dict[str, Any], family_result: Dict[str, Any]) -> Dict[str, Any]:
    selected_capabilities: List[Dict[str, Any]] = []
    arg_map = _build_argument_map(event)
    default_capabilities = family_result.get("default_capabilities", []) or []

    order = 1
    for capability in default_capabilities:
        meta = get_capability(capability)
        if not meta:
            continue

        required_args = meta.get("required_args", []) or []
        missing_required = [
            arg_name for arg_name in required_args if not str(arg_map.get(arg_name, "")).strip()
        ]
        if missing_required:
            continue

        selected_capabilities.append(
            {
                "order": order,
                "capability": capability,
                "arguments": arg_map,
                "reason": "family_default",
                "judge_profile": meta.get("judge_profile", "network_cli_generic"),
                "readonly": bool(meta.get("readonly", True)),
            }
        )
        order += 1

    return {
        "mode": "registry_v1",
        "family": family_result.get("family", "generic_network_readonly"),
        "selected_capabilities": selected_capabilities,
        "readonly_only": all(item.get("readonly", True) for item in selected_capabilities) if selected_capabilities else True,
        "auto_execute_allowed": bool(family_result.get("auto_execute_allowed", False)),
    }

# ===== v5 prometheus rule expanded capabilities begin =====
# 说明：
# 本段为新增 Prometheus rule family 提供 capability 规划。
# 下一批会继续把这些 capability 映射到不同平台的具体命令。

V5_ADDITIONAL_CAPABILITY_REGISTRY = {
    "query_prometheus_metric_window": {
        "description": "查询 Prometheus 告警时间窗口指标",
        "readonly": True,
        "required_args": [],
        "judge_profile": "prometheus",
        "category": "metric",
    },
    "query_elastic_related_logs": {
        "description": "查询 Elastic 告警相关时间窗口日志",
        "readonly": True,
        "required_args": [],
        "judge_profile": "elastic",
        "category": "log",
    },
    "show_device_environment": {
        "description": "查看设备环境状态汇总",
        "readonly": True,
        "required_args": [],
        "judge_profile": "network_cli_generic",
        "category": "hardware",
    },
    "show_fan_status": {
        "description": "查看风扇状态",
        "readonly": True,
        "required_args": [],
        "judge_profile": "network_cli_generic",
        "category": "hardware",
    },
    "show_power_status": {
        "description": "查看电源状态",
        "readonly": True,
        "required_args": [],
        "judge_profile": "network_cli_generic",
        "category": "hardware",
    },
    "show_environment_temperature": {
        "description": "查看设备温度状态",
        "readonly": True,
        "required_args": [],
        "judge_profile": "network_cli_generic",
        "category": "hardware",
    },
    "show_chassis_status": {
        "description": "查看机框/机箱状态",
        "readonly": True,
        "required_args": [],
        "judge_profile": "network_cli_generic",
        "category": "hardware",
    },
    "show_module_status": {
        "description": "查看板卡/模块状态",
        "readonly": True,
        "required_args": [],
        "judge_profile": "network_cli_generic",
        "category": "hardware",
    },
    "show_inventory": {
        "description": "查看硬件资产和模块清单",
        "readonly": True,
        "required_args": [],
        "judge_profile": "network_cli_generic",
        "category": "hardware",
    },
    "show_interface_transceiver": {
        "description": "查看接口光模块与光功率信息",
        "readonly": True,
        "required_args": ["interface"],
        "judge_profile": "network_cli_generic",
        "category": "interface",
    },
    "show_device_disk": {
        "description": "查看设备磁盘/文件系统空间",
        "readonly": True,
        "required_args": [],
        "judge_profile": "network_cli_generic",
        "category": "resource",
    },
    "show_ha_state": {
        "description": "查看设备 HA / 主备 / 集群状态",
        "readonly": True,
        "required_args": [],
        "judge_profile": "network_cli_generic",
        "category": "ha",
    },
    "show_cimc_hardware_status": {
        "description": "查看 CIMC 硬件健康状态",
        "readonly": True,
        "required_args": [],
        "judge_profile": "network_cli_generic",
        "category": "hardware",
    },
}


V5_ADDITIONAL_FAMILY_CAPABILITY_MAP = {
    "hardware_fan_abnormal": [
        "show_device_environment",
        "show_fan_status",
        "query_prometheus_metric_window",
    ],
    "hardware_power_abnormal": [
        "show_device_environment",
        "show_power_status",
        "query_prometheus_metric_window",
    ],
    "hardware_temperature_high": [
        "show_device_environment",
        "show_environment_temperature",
        "query_prometheus_metric_window",
    ],
    "chassis_slot_or_module_abnormal": [
        "show_chassis_status",
        "show_module_status",
        "show_inventory",
        "query_prometheus_metric_window",
    ],
    "optical_power_abnormal": [
        "show_interface_transceiver",
        "show_interface_detail",
        "query_prometheus_metric_window",
    ],
    "device_disk_high": [
        "show_device_disk",
        "query_prometheus_metric_window",
    ],
    "dns_request_rate_anomaly": [
        "query_prometheus_metric_window",
        "query_elastic_related_logs",
    ],
    "dns_response_rate_anomaly": [
        "query_prometheus_metric_window",
        "query_elastic_related_logs",
    ],
    "f5_connection_rate_anomaly": [
        "show_f5_connections",
        "show_f5_performance",
        "query_prometheus_metric_window",
    ],
    "ha_or_cluster_state_abnormal": [
        "show_ha_state",
        "query_prometheus_metric_window",
        "query_elastic_related_logs",
    ],
    "cimc_hardware_abnormal": [
        "show_cimc_hardware_status",
        "query_prometheus_metric_window",
    ],
}


try:
    CAPABILITY_REGISTRY.update(V5_ADDITIONAL_CAPABILITY_REGISTRY)
except NameError:
    CAPABILITY_REGISTRY = dict(V5_ADDITIONAL_CAPABILITY_REGISTRY)


try:
    _v5_original_build_capability_plan = build_capability_plan
except NameError:
    _v5_original_build_capability_plan = None


def _v5_get_arg(event, *keys):
    if not isinstance(event, dict):
        return ""

    for key in keys:
        value = event.get(key)
        if value:
            return value

    labels = event.get("labels")
    if isinstance(labels, dict):
        for key in keys:
            value = labels.get(key)
            if value:
                return value

    annotations = event.get("annotations")
    if isinstance(annotations, dict):
        for key in keys:
            value = annotations.get(key)
            if value:
                return value

    return ""


def _v5_build_capability_item(capability, event, order):
    meta = CAPABILITY_REGISTRY.get(capability, {}) or {}
    required_args = meta.get("required_args", []) or []

    arguments = {
        "interface": _v5_get_arg(event, "interface", "ifName", "if_name", "object_name"),
        "peer_ip": _v5_get_arg(event, "peer_ip", "neighbor", "neighbor_ip"),
        "pool": _v5_get_arg(event, "pool", "pool_name"),
        "pool_member": _v5_get_arg(event, "pool_member", "member"),
        "device_ip": _v5_get_arg(event, "device_ip", "ip"),
        "hostname": _v5_get_arg(event, "hostname", "instance"),
    }

    arguments = {k: v for k, v in arguments.items() if v}

    return {
        "order": order,
        "capability": capability,
        "readonly": bool(meta.get("readonly", True)),
        "required_args": required_args,
        "arguments": arguments,
        "judge_profile": meta.get("judge_profile", "network_cli_generic"),
        "reason": "v5_prometheus_rule_expanded_family_default",
    }


if _v5_original_build_capability_plan is not None:
    def build_capability_plan(event, family_result):
        family = ""
        if isinstance(family_result, dict):
            family = str(family_result.get("family") or "").strip()

        if family in V5_ADDITIONAL_FAMILY_CAPABILITY_MAP:
            capabilities = V5_ADDITIONAL_FAMILY_CAPABILITY_MAP.get(family, []) or []
            selected = [
                _v5_build_capability_item(capability, event, index)
                for index, capability in enumerate(capabilities, start=1)
            ]

            return {
                "family": family,
                "plan_source": "v5_prometheus_rule_expanded_capability_registry",
                "readonly_only": all(item.get("readonly", True) for item in selected),
                "selected_capabilities": selected,
                "capability_count": len(selected),
            }

        return _v5_original_build_capability_plan(event, family_result)
# ===== v5 prometheus rule expanded capabilities end =====

# ===== v5 PromQL interface utilization capability final planner begin =====
# 修复场景：
# family 已被修正为 interface_or_link_utilization_high，
# 但 build_capability_plan 仍返回 ['show_recent_logs']，导致 MCP 只执行 show logging。
#
# 这里做最终兜底：
# 只要是 PromQL / 告警文本明确表达接口利用率类告警，
# 且原 plan 为空或只包含 show_recent_logs，就强制生成接口利用率取证能力集合。

import json as _v16c_json
import re as _v16c_re
import urllib.parse as _v16c_urlparse


try:
    _v16c_original_build_capability_plan = build_capability_plan
except NameError:
    _v16c_original_build_capability_plan = None


V16C_INTERFACE_UTILIZATION_CAPABILITIES = [
    "show_interface_detail",
    "show_interface_error_counters",
    "show_portchannel_summary",
    "query_prometheus_metric_window",
]


def _v16c_safe_text(value):
    if value is None:
        return ""

    if isinstance(value, (dict, list, tuple, set)):
        try:
            return _v16c_json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)

    return str(value).strip()


def _v16c_walk_text(obj, max_depth=5):
    parts = []

    def walk(value, depth=0):
        if depth > max_depth:
            return

        if value is None:
            return

        if isinstance(value, dict):
            for k, v in value.items():
                parts.append(_v16c_safe_text(k))
                walk(v, depth + 1)
            return

        if isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item, depth + 1)
            return

        parts.append(_v16c_safe_text(value))

    walk(obj)
    return _v16c_urlparse.unquote(" ".join(x for x in parts if x))


def _v16c_get_family(family_result):
    if not isinstance(family_result, dict):
        return ""
    return _v16c_safe_text(family_result.get("family"))


def _v16c_get_interface(event, family_result):
    for obj in (event, family_result, (family_result or {}).get("target_scope") if isinstance(family_result, dict) else {}):
        if not isinstance(obj, dict):
            continue

        for key in ("interface", "ifName", "if_name", "port", "object_name"):
            value = _v16c_safe_text(obj.get(key))
            if value:
                return value

        labels = obj.get("labels")
        if isinstance(labels, dict):
            for key in ("interface", "ifName", "if_name", "port"):
                value = _v16c_safe_text(labels.get(key))
                if value:
                    return value

    text = _v16c_walk_text(event)

    for pattern in (
        r'ifName\s*=~\s*"([^"]+)"',
        r"ifName\s*=~\s*'([^']+)'",
        r'ifDescr\s*=~\s*"([^"]+)"',
        r"ifDescr\s*=~\s*'([^']+)'",
    ):
        m = _v16c_re.search(pattern, text, flags=_v16c_re.IGNORECASE)
        if not m:
            continue

        first = m.group(1).split("|")[0].strip()

        if first:
            return first

    return ""


def _v16c_is_promql_interface_utilization(event, family_result):
    family = _v16c_get_family(family_result)

    if family != "interface_or_link_utilization_high":
        return False

    text = _v16c_walk_text(event) + " " + _v16c_walk_text(family_result)
    lower = text.lower()

    if "利用率" in text and ("入向" in text or "出向" in text):
        return True

    if (
        ("ifhcoutoctets" in lower or "ifhcinoctets" in lower or "ifoutoctets" in lower or "ifinoctets" in lower)
        and ("ifname" in lower or "ifdescr" in lower)
        and ("irate(" in lower or "rate(" in lower or "> 80000000" in text or ">80000000" in text)
    ):
        return True

    return False


def _v16c_plan_is_generic_logs_only(plan):
    if not isinstance(plan, dict):
        return True

    items = plan.get("selected_capabilities", []) or []

    if not items:
        return True

    capabilities = [
        _v16c_safe_text(item.get("capability"))
        for item in items
        if isinstance(item, dict)
    ]

    if not capabilities:
        return True

    return set(capabilities).issubset({"show_recent_logs"})


def _v16c_build_capability_item(capability, event, family_result, order):
    meta = {}
    try:
        meta = CAPABILITY_REGISTRY.get(capability, {}) or {}
    except Exception:
        meta = {}

    interface = _v16c_get_interface(event, family_result)

    required_args = meta.get("required_args", []) or []

    if capability in ("show_interface_detail", "show_interface_error_counters", "show_interface_transceiver", "show_interface_state", "show_interface_traffic_rate"):
        if "interface" not in required_args:
            required_args = list(required_args) + ["interface"]

    arguments = {}

    if interface:
        arguments["interface"] = interface

    if isinstance(event, dict):
        for key in ("device_ip", "hostname", "vendor", "platform", "os_family", "job"):
            value = event.get(key)
            if value:
                arguments[key] = value

    return {
        "order": order,
        "capability": capability,
        "readonly": bool(meta.get("readonly", True)),
        "required_args": required_args,
        "arguments": arguments,
        "judge_profile": meta.get("judge_profile", "network_cli_generic"),
        "reason": "v16_promql_interface_utilization_forced_capability_plan",
    }


def _v16c_build_forced_interface_utilization_plan(event, family_result, original_plan=None):
    selected = [
        _v16c_build_capability_item(capability, event, family_result, index)
        for index, capability in enumerate(V16C_INTERFACE_UTILIZATION_CAPABILITIES, start=1)
    ]

    return {
        "family": "interface_or_link_utilization_high",
        "plan_source": "v16_promql_interface_utilization_forced_capability_registry",
        "readonly_only": all(item.get("readonly", True) for item in selected),
        "selected_capabilities": selected,
        "capability_count": len(selected),
        "original_plan_source": (original_plan or {}).get("plan_source") if isinstance(original_plan, dict) else "",
        "original_capabilities": [
            item.get("capability")
            for item in ((original_plan or {}).get("selected_capabilities", []) if isinstance(original_plan, dict) else [])
            if isinstance(item, dict)
        ],
    }


if _v16c_original_build_capability_plan is not None:
    def build_capability_plan(event, family_result):
        original_plan = _v16c_original_build_capability_plan(event, family_result)

        if _v16c_is_promql_interface_utilization(event, family_result) and _v16c_plan_is_generic_logs_only(original_plan):
            return _v16c_build_forced_interface_utilization_plan(event, family_result, original_plan)

        return original_plan
# ===== v5 PromQL interface utilization capability final planner end =====
