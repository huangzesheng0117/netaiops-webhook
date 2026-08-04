#!/usr/bin/env python3
"""Inspect or invoke the v12 controlled primary integration entry."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from netaiops.v12.primary_release import (  # noqa: E402
    DEFAULT_RUNTIME_CONFIG,
    load_primary_settings,
    run_v12_primary_after_legacy_safe,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)

    status = sub.add_parser("status")
    status.add_argument("--runtime-config", default=str(DEFAULT_RUNTIME_CONFIG))

    invoke = sub.add_parser("invoke")
    invoke.add_argument("--request-id", required=True)
    invoke.add_argument("--runtime-config", default=str(DEFAULT_RUNTIME_CONFIG))
    invoke.add_argument("--confirm-real-calls", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.action == "status":
        settings = load_primary_settings(args.runtime_config)
        payload = {
            "status": "ok",
            "runtime_config": args.runtime_config,
            "configured": settings is not None,
            "enabled": settings.enabled if settings else False,
            "mode": settings.mode if settings else None,
            "allowed_families": list(settings.allowed_families) if settings else [],
            "fail_open_to_legacy": (
                settings.fail_open_to_legacy if settings else None
            ),
            "notifications_use_v12": (
                settings.notifications_use_v12 if settings else None
            ),
            "logs_enabled": settings.logs_enabled if settings else None,
            "knowledge_enabled": settings.knowledge_enabled if settings else None,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    if not args.confirm_real_calls:
        raise SystemExit("invoke requires --confirm-real-calls")
    result = run_v12_primary_after_legacy_safe(
        request_id=args.request_id,
        runtime_config=args.runtime_config,
        notify_result={"ok": True, "sent_count": 1},
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("status") in {"completed", "fallback_legacy"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
