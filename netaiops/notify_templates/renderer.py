from typing import Any, Dict, Callable, Optional

from netaiops.notify_templates.common import get_family
from netaiops.notify_templates import interface
from netaiops.notify_templates import routing
from netaiops.notify_templates import f5
from netaiops.notify_templates import device_resource
from netaiops.notify_templates import generic


INTERFACE_FAMILIES = {
    "interface_or_link_utilization_high",
    "interface_or_link_traffic_drop",
    "interface_packet_loss_or_discards_high",
    "interface_status_or_flap",
    "interface_flap",
}

ROUTING_FAMILIES = {
    "bgp_neighbor_down",
    "ospf_neighbor_down",
    "routing_neighbor_down",
}

DEVICE_RESOURCE_FAMILIES = {
    "device_cpu_high",
    "device_memory_high",
}

F5_FAMILIES = {
    "f5_pool_member_down",
}


def select_template_module(family: str):
    if family in INTERFACE_FAMILIES:
        return interface
    if family in ROUTING_FAMILIES:
        return routing
    if family in DEVICE_RESOURCE_FAMILIES:
        return device_resource
    if family in F5_FAMILIES:
        return f5
    return generic


def render_notification_text(
    payload: Dict[str, Any],
    fallback_renderer: Optional[Callable[[Dict[str, Any]], str]] = None,
) -> str:
    family = get_family(payload)
    module = select_template_module(family)

    try:
        text = module.render(payload, fallback_renderer=fallback_renderer)
        if text:
            return text
    except Exception:
        pass

    if fallback_renderer:
        return fallback_renderer(payload)

    return generic.render(payload, fallback_renderer=None)

# ===== v5 expanded family notify template router begin =====
# 为新增 family 增加通知模板路由。
# 当前模板保持原通知正文格式，后续可以在 hardware.py / dns.py / ha.py 内细化话术。

import importlib as _v8_importlib


V8_HARDWARE_TEMPLATE_FAMILIES = {
    "hardware_fan_abnormal",
    "hardware_power_abnormal",
    "hardware_temperature_high",
    "chassis_slot_or_module_abnormal",
    "optical_power_abnormal",
    "device_disk_high",
    "cimc_hardware_abnormal",
}

V8_DNS_TEMPLATE_FAMILIES = {
    "dns_request_rate_anomaly",
    "dns_response_rate_anomaly",
}

V8_HA_TEMPLATE_FAMILIES = {
    "ha_or_cluster_state_abnormal",
}

V8_F5_TEMPLATE_FAMILIES = {
    "f5_connection_rate_anomaly",
}


try:
    _v8_original_select_template_module = select_template_module
except NameError:
    _v8_original_select_template_module = None


def select_template_module(family: str):
    if family in V8_HARDWARE_TEMPLATE_FAMILIES:
        return _v8_importlib.import_module("netaiops.notify_templates.hardware")

    if family in V8_DNS_TEMPLATE_FAMILIES:
        return _v8_importlib.import_module("netaiops.notify_templates.dns")

    if family in V8_HA_TEMPLATE_FAMILIES:
        return _v8_importlib.import_module("netaiops.notify_templates.ha")

    if family in V8_F5_TEMPLATE_FAMILIES:
        return _v8_importlib.import_module("netaiops.notify_templates.f5")

    if _v8_original_select_template_module is not None:
        return _v8_original_select_template_module(family)

    return _v8_importlib.import_module("netaiops.notify_templates.generic")
# ===== v5 expanded family notify template router end =====
