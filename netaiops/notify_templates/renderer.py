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
