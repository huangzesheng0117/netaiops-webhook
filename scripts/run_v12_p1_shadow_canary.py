#!/usr/bin/env python3
"""Observe and gate the v12 Batch P1 artifact-reuse Shadow Canary."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from netaiops.v12.p1_shadow_canary import (
    DEFAULT_RUNTIME_CONFIG,
    DEFAULT_TRACE_ROOT,
    collect_p1_observations,
    evaluate_p1_gate,
    load_p1_settings,
)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Manage the read-only v12 Batch P1 canary."
    )
    value.add_argument(
        "action",
        choices=("status", "observe", "gate"),
    )
    value.add_argument(
        "--runtime-config",
        default=str(DEFAULT_RUNTIME_CONFIG),
    )
    value.add_argument(
        "--trace-root",
        default=str(DEFAULT_TRACE_ROOT),
    )
    value.add_argument(
        "--minimum-completed",
        type=int,
        default=0,
    )
    value.add_argument("--output", default="")
    return value


def _dump(value: object, output: str) -> None:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=str,
    ) + "\n"
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".p1.tmp")
        temporary.write_text(
            encoded,
            encoding="utf-8",
            newline="\n",
        )
        temporary.replace(path)
    print(encoded, end="")


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    settings = load_p1_settings(args.runtime_config)
    if settings is None:
        payload = {
            "status": "disabled",
            "runtime_config": args.runtime_config,
        }
        _dump(payload, args.output)
        return 0 if args.action == "status" else 1

    if args.action == "status":
        payload = {
            "status": "active" if settings.active_now else "inactive",
            "schema_version": settings.schema_version,
            "activation_id": settings.activation_id,
            "enabled": settings.enabled,
            "mode": settings.mode,
            "activated_at": settings.activated_at,
            "expires_at": settings.expires_at,
            "active_now": settings.active_now,
            "max_canary_requests": settings.max_canary_requests,
            "allowed_families": list(settings.allowed_families),
            "minimum_completed_for_gate": (
                settings.minimum_completed_for_gate
            ),
            "external_calls": False,
        }
        _dump(payload, args.output)
        return 0

    observations = collect_p1_observations(
        trace_root=args.trace_root,
        activation_id=settings.activation_id,
    )
    if args.action == "observe":
        _dump(observations, args.output)
        return 0

    minimum = (
        args.minimum_completed
        if args.minimum_completed > 0
        else settings.minimum_completed_for_gate
    )
    gate = evaluate_p1_gate(
        observations,
        minimum_completed=minimum,
    )
    payload = {
        "observations": observations,
        "gate": gate,
    }
    _dump(payload, args.output)
    return 0 if gate["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
