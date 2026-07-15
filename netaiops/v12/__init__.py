"""NetAIOps Webhook v12 controlled multi-agent namespace.

Batch A intentionally exposes metadata only. Importing this package must not
register routes, start agents, call external systems, or alter the v11 runtime.
"""

V12_TARGET_VERSION = "12.0.0-v12-controlled-multi-agent"
V12_CONFIG_SECTION = "v12_multi_agent"
V12_DEFAULT_MODE = "shadow"
V12_BATCH_ORDER = tuple("ABCDEFGHIJKLMNOPQ")

__all__ = [
    "V12_BATCH_ORDER",
    "V12_CONFIG_SECTION",
    "V12_DEFAULT_MODE",
    "V12_TARGET_VERSION",
]
