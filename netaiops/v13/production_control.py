"""V13 production release-control state.

The control file lives under the ignored runtime data tree.  Code installation
therefore does not activate V13 ownership by itself.  Missing/invalid control
state is fail-closed to the existing legacy pipeline.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from netaiops.v12.schema_validator import sanitize_sensitive_data

from .triage_contracts import MIGRATED_FAMILIES


CONTROL_SCHEMA_VERSION = "v13-release-control-1"
CONTROL_MODES = frozenset({"disabled", "triage_only", "single_family", "three_family"})
DEFAULT_PROJECT_ROOT = Path("/opt/netaiops-webhook")


class V13ProductionControlError(ValueError):
    """Raised when runtime V13 release-control state is unsafe or invalid."""


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def control_path(project_root: str | Path = DEFAULT_PROJECT_ROOT) -> Path:
    return Path(project_root) / "data" / "v13" / "release_control.json"


def safe_default_control() -> dict[str, Any]:
    return {
        "schema_version": CONTROL_SCHEMA_VERSION,
        "activation_id": "disabled-default",
        "mode": "disabled",
        "single_family": None,
        "allowed_owner_families": [],
        "triage_mounted": False,
        "owner_real_calls_enabled": False,
        "fail_open_to_legacy": True,
        "notifications_use_v12": False,
        "logs_enabled": False,
        "knowledge_enabled": False,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "source": "safe_default_missing_control",
    }


def validate_release_control(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise V13ProductionControlError("release control root must be a mapping")
    data = sanitize_sensitive_data(dict(value))
    if not isinstance(data, dict):
        raise V13ProductionControlError("release control could not be sanitized")

    if _text(data.get("schema_version")) != CONTROL_SCHEMA_VERSION:
        raise V13ProductionControlError("unsupported release control schema_version")
    mode = _text(data.get("mode")).lower()
    if mode not in CONTROL_MODES:
        raise V13ProductionControlError("unsupported release control mode")
    activation_id = _text(data.get("activation_id"))
    if not activation_id:
        raise V13ProductionControlError("activation_id is required")

    if data.get("fail_open_to_legacy") is not True:
        raise V13ProductionControlError("fail_open_to_legacy must remain true in v13")
    if data.get("notifications_use_v12") is not False:
        raise V13ProductionControlError("notifications_use_v12 must remain false in v13")
    if data.get("logs_enabled") is not False:
        raise V13ProductionControlError("Logs Agent must remain disabled in v13")
    if data.get("knowledge_enabled") is not False:
        raise V13ProductionControlError("Knowledge Agent must remain disabled in v13")

    single_family = _text(data.get("single_family")) or None
    if single_family is not None and single_family not in MIGRATED_FAMILIES:
        raise V13ProductionControlError("single_family is not in the frozen v13 family set")

    if mode == "disabled":
        allowed = []
        triage_mounted = False
        owner_real_calls_enabled = False
        single_family = None
    elif mode == "triage_only":
        allowed = []
        triage_mounted = True
        owner_real_calls_enabled = False
        single_family = None
    elif mode == "single_family":
        if single_family is None:
            raise V13ProductionControlError("single_family mode requires single_family")
        allowed = [single_family]
        triage_mounted = True
        owner_real_calls_enabled = True
    else:
        allowed = list(MIGRATED_FAMILIES)
        triage_mounted = True
        owner_real_calls_enabled = True
        single_family = None

    declared = [str(x).strip() for x in (data.get("allowed_owner_families") or []) if str(x).strip()]
    if declared and declared != allowed:
        raise V13ProductionControlError("allowed_owner_families does not match mode")

    normalized = dict(data)
    normalized.update(
        {
            "schema_version": CONTROL_SCHEMA_VERSION,
            "activation_id": activation_id,
            "mode": mode,
            "single_family": single_family,
            "allowed_owner_families": allowed,
            "triage_mounted": triage_mounted,
            "owner_real_calls_enabled": owner_real_calls_enabled,
            "fail_open_to_legacy": True,
            "notifications_use_v12": False,
            "logs_enabled": False,
            "knowledge_enabled": False,
        }
    )
    return normalized


def load_release_control(
    project_root: str | Path = DEFAULT_PROJECT_ROOT,
    *,
    strict: bool = False,
) -> dict[str, Any]:
    path = control_path(project_root)
    if not path.exists():
        return safe_default_control()
    if path.is_symlink() or not path.is_file():
        if strict:
            raise V13ProductionControlError("release control must be a regular file")
        return safe_default_control()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return validate_release_control(payload)
    except Exception:
        if strict:
            raise
        return safe_default_control()


def triage_mounted(control: Mapping[str, Any] | None = None) -> bool:
    data = validate_release_control(control) if control is not None else load_release_control()
    return bool(data.get("triage_mounted"))


def owner_active_for_family(
    family: str,
    control: Mapping[str, Any] | None = None,
) -> bool:
    data = validate_release_control(control) if control is not None else load_release_control()
    return bool(
        data.get("owner_real_calls_enabled")
        and str(family or "").strip() in set(data.get("allowed_owner_families") or [])
    )
