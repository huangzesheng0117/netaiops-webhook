"""v13 Evidence Capability foundation.

Batch V13-D1 only defines deterministic contracts, deduplication, and
checkpoint reuse. It does not change the production entry point and it does
not call GLM, Prometheus MCP, Netmiko MCP, Evidence MCP, or notification
transports.
"""

from .capability_broker import (
    CapabilityExecutionError,
    EvidenceCapabilityBroker,
)
from .capability_contracts import (
    CapabilityCheckpoint,
    CapabilityDecision,
    DeviceCapabilityRequest,
    MetricsCapabilityRequest,
    build_capability_dedup_key,
    build_plan_fingerprint,
    build_template_fingerprint,
)

__all__ = [
    "CapabilityCheckpoint",
    "CapabilityDecision",
    "CapabilityExecutionError",
    "DeviceCapabilityRequest",
    "EvidenceCapabilityBroker",
    "MetricsCapabilityRequest",
    "build_capability_dedup_key",
    "build_plan_fingerprint",
    "build_template_fingerprint",
]
