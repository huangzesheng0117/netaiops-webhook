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
