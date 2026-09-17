"""Deterministic allow-listed Logs Profile selection from event metadata."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .logs_contracts import ALLOWED_PROFILES


@dataclass(frozen=True, slots=True)
class ProfileDecision:
    profile_id: str | None
    reason: str


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _text(*values: Any) -> str:
    return " ".join(str(v or "").strip().lower() for v in values if str(v or "").strip())


def resolve_log_profile(event: Mapping[str, Any]) -> ProfileDecision:
    labels = _mapping(event.get("labels"))
    annotations = _mapping(event.get("annotations"))
    explicit = (
        labels.get("logs_profile_id") or annotations.get("logs_profile_id")
        or labels.get("log_profile_id") or annotations.get("log_profile_id")
    )
    if explicit:
        value = str(explicit).strip()
        if value in ALLOWED_PROFILES:
            return ProfileDecision(value, "explicit_allowlisted_profile")
        return ProfileDecision(None, "explicit_profile_not_allowlisted")

    vendor = _text(event.get("vendor"), labels.get("vendor"), labels.get("manufacturer"))
    context = _text(
        event.get("alarm_type"), event.get("object_type"), event.get("object_name"),
        labels.get("job"), labels.get("platform"), labels.get("device_type"),
        labels.get("fabric"), annotations.get("summary"),
    )
    if "fortigate" in vendor or "fortinet" in vendor:
        return ProfileDecision("fortigate_system_log", "vendor_fortinet")
    if "f5" in vendor or "big-ip" in vendor or "bigip" in vendor:
        return ProfileDecision("f5_system_log", "vendor_f5")
    if "cisco" in vendor or "cisco" in context:
        if any(token in context for token in ("aci", "apic", "application centric infrastructure")):
            return ProfileDecision("cisco_aci_system_log", "vendor_cisco_aci_context")
        if any(token in context for token in ("ios", "iosxe", "ios-xe", "nxos", "nx-os", "nexus", "switch", "catalyst")):
            return ProfileDecision("cisco_switch_system_log", "vendor_cisco_switch_context")
        return ProfileDecision(None, "cisco_profile_ambiguous_no_safe_guess")
    return ProfileDecision(None, "profile_unresolved_no_safe_guess")
