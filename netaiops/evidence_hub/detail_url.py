"""Evidence Hub URL configuration helpers for v10 Batch 4.

Detail URL design boundaries:
- no token / secret is read or written here
- environment variables override YAML config for emergency rollback
- existing external_base_url can be reused as the safe production default
- if no public base URL is configured, a local 127.0.0.1 URL is generated
- functions are pure and safe for unit tests
"""

from __future__ import annotations

import os
from typing import Any, Dict, Mapping, Optional

JsonDict = Dict[str, Any]


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _as_bool(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on", "enabled", "enable"}:
        return True
    if text in {"0", "false", "no", "n", "off", "disabled", "disable"}:
        return False
    return default


def _nested_mapping(config: Optional[Mapping[str, Any]], key: str) -> Mapping[str, Any]:
    if not isinstance(config, Mapping):
        return {}
    value = config.get(key)
    return value if isinstance(value, Mapping) else {}


def normalize_base_url(value: Any) -> str:
    """Return a normalized base URL without trailing slash."""
    text = _as_text(value)
    if not text:
        return ""
    return text.rstrip("/")


def evidence_hub_enabled(config: Optional[Mapping[str, Any]] = None) -> bool:
    """Return whether Evidence Hub automatic detail building is enabled."""
    env_value = os.environ.get("EVIDENCE_HUB_ENABLED")
    if env_value is not None:
        return _as_bool(env_value, default=True)

    section = _nested_mapping(config, "evidence_hub")
    candidates = [
        section.get("enabled"),
        section.get("auto_build_enabled"),
    ]
    if isinstance(config, Mapping):
        candidates.append(config.get("evidence_hub_enabled"))

    for value in candidates:
        if value is not None:
            return _as_bool(value, default=True)
    return True


def evidence_hub_default_to_local(config: Optional[Mapping[str, Any]] = None) -> bool:
    """Return whether a local URL should be generated when no public URL exists."""
    env_value = os.environ.get("EVIDENCE_HUB_DEFAULT_TO_LOCAL")
    if env_value is not None:
        return _as_bool(env_value, default=True)

    section = _nested_mapping(config, "evidence_hub")
    value = section.get("default_to_local")
    if value is not None:
        return _as_bool(value, default=True)
    return True


def _configured_base_url_candidates(config: Optional[Mapping[str, Any]] = None) -> list[Any]:
    section = _nested_mapping(config, "evidence_hub")
    candidates: list[Any] = [
        os.environ.get("EVIDENCE_HUB_BASE_URL"),
        os.environ.get("EVIDENCE_HUB_PUBLIC_BASE_URL"),
        section.get("base_url"),
        section.get("detail_base_url"),
        section.get("public_base_url"),
    ]
    if isinstance(config, Mapping):
        candidates.extend([
            config.get("evidence_hub_base_url"),
            config.get("detail_base_url"),
            config.get("public_base_url"),
            config.get("external_base_url"),
        ])
    return candidates


def get_default_local_base_url(config: Optional[Mapping[str, Any]] = None) -> str:
    """Build a safe local fallback URL such as http://127.0.0.1:18080."""
    port: Any = "18080"
    if isinstance(config, Mapping):
        port = config.get("listen_port") or port
    port_text = _as_text(port) or "18080"
    return f"http://127.0.0.1:{port_text}"


def get_evidence_hub_base_url(
    config: Optional[Mapping[str, Any]] = None,
    *,
    allow_default: bool = True,
) -> str:
    """Return the effective Evidence Hub base URL.

    Priority:
    1. EVIDENCE_HUB_BASE_URL / EVIDENCE_HUB_PUBLIC_BASE_URL
    2. evidence_hub.base_url / detail_base_url / public_base_url
    3. root evidence_hub_base_url / detail_base_url / public_base_url
    4. existing external_base_url
    5. http://127.0.0.1:<listen_port> when default_to_local is enabled
    """
    for value in _configured_base_url_candidates(config):
        text = normalize_base_url(value)
        if text:
            return text

    if allow_default and evidence_hub_default_to_local(config):
        return get_default_local_base_url(config)
    return ""


def build_detail_url(
    request_id: str,
    *,
    config: Optional[Mapping[str, Any]] = None,
    allow_default: bool = True,
) -> str:
    """Build /evidence-ui/<request_id> URL from effective base URL."""
    rid = _as_text(request_id)
    if not rid:
        return ""
    base_url = get_evidence_hub_base_url(config, allow_default=allow_default)
    if not base_url:
        return ""
    return f"{base_url}/evidence-ui/{rid}"


def evidence_hub_url_config_summary(config: Optional[Mapping[str, Any]] = None) -> JsonDict:
    """Return a non-secret summary for logs, tests and detail metadata."""
    section = _nested_mapping(config, "evidence_hub")
    base_url = get_evidence_hub_base_url(config)
    source = "default_local"
    if normalize_base_url(os.environ.get("EVIDENCE_HUB_BASE_URL")):
        source = "env:EVIDENCE_HUB_BASE_URL"
    elif normalize_base_url(os.environ.get("EVIDENCE_HUB_PUBLIC_BASE_URL")):
        source = "env:EVIDENCE_HUB_PUBLIC_BASE_URL"
    elif normalize_base_url(section.get("base_url")):
        source = "config:evidence_hub.base_url"
    elif normalize_base_url(section.get("detail_base_url")):
        source = "config:evidence_hub.detail_base_url"
    elif normalize_base_url(section.get("public_base_url")):
        source = "config:evidence_hub.public_base_url"
    elif isinstance(config, Mapping) and normalize_base_url(config.get("external_base_url")):
        source = "config:external_base_url"
    return {
        "enabled": evidence_hub_enabled(config),
        "base_url": base_url,
        "base_url_source": source,
        "default_to_local": evidence_hub_default_to_local(config),
    }


__all__ = [
    "build_detail_url",
    "evidence_hub_default_to_local",
    "evidence_hub_enabled",
    "evidence_hub_url_config_summary",
    "get_default_local_base_url",
    "get_evidence_hub_base_url",
    "normalize_base_url",
]
