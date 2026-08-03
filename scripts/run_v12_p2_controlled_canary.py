"""CLI for Batch P2-A control-plane validation.

This CLI validates local configuration only. It has no external client and
cannot make an MCP, GLM, HTTP, notification, or device call.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from netaiops.v12.p2_controlled_canary import (
    DEFAULT_RUNTIME_CONFIG,
    P2ContractError,
    load_p2_settings,
    offline_contract_report,
)


DEFAULT_EXAMPLE = (
    Path("/opt/netaiops-webhook")
    / "config"
    / "v12_p2_canary.example.yaml"
)


def _print(value: dict) -> None:
    print(
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )


def _load_required(path: Path):
    settings = load_p2_settings(path)
    if settings is None:
        raise P2ContractError(
            f"P2 config does not exist: {path}"
        )
    return settings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate the v12 Batch P2-A control plane"
    )
    parser.add_argument(
        "action",
        choices=(
            "validate-example",
            "status",
            "offline-gate",
        ),
    )
    parser.add_argument(
        "--config",
        default="",
        help="Config path; defaults by action",
    )
    args = parser.parse_args()

    try:
        if args.action == "validate-example":
            path = Path(args.config or DEFAULT_EXAMPLE)
            settings = _load_required(path)
            _print(
                {
                    "status": "pass",
                    "action": args.action,
                    "config": str(path),
                    "schema_version": settings.schema_version,
                    "enabled": settings.enabled,
                    "real_calls_enabled": (
                        settings.real_calls_enabled
                    ),
                    "allowed_families": list(
                        settings.allowed_families
                    ),
                }
            )
            return 0

        if args.action == "status":
            path = Path(args.config or DEFAULT_RUNTIME_CONFIG)
            settings = load_p2_settings(path)
            if settings is None:
                _print(
                    {
                        "status": "inactive",
                        "action": args.action,
                        "config": str(path),
                        "reason": "runtime_config_absent",
                        "external_calls": False,
                    }
                )
                return 0
            _print(
                {
                    "status": (
                        "active"
                        if settings.active_now
                        else "inactive"
                    ),
                    "action": args.action,
                    "config": str(path),
                    "activation_id": settings.activation_id,
                    "enabled": settings.enabled,
                    "active_now": settings.active_now,
                    "real_calls_enabled": (
                        settings.real_calls_enabled
                    ),
                    "external_calls": False,
                }
            )
            return 0

        path = Path(args.config or DEFAULT_EXAMPLE)
        report = offline_contract_report(
            _load_required(path)
        )
        _print(report)
        return 0
    except (P2ContractError, OSError, ValueError) as exc:
        _print(
            {
                "status": "failed",
                "action": args.action,
                "error_type": type(exc).__name__,
                "error": str(exc),
                "external_calls": False,
            }
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
