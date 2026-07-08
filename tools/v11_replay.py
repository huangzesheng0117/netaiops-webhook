#!/usr/bin/env python3
"""Run one v11 deterministic offline replay and write it outside production data."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_IMPORT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_IMPORT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_IMPORT_ROOT))

from netaiops.governance.replay_engine import (  # noqa: E402
    replay_safety_summary,
    run_offline_replay,
)
from netaiops.governance.store import GovernanceStore  # noqa: E402


def _safe_output_root(project_root: Path, output_root: Path) -> Path:
    project = project_root.expanduser().resolve(strict=True)
    output = output_root.expanduser().resolve(strict=False)
    production = (project / "data" / "governance").resolve(strict=False)
    if output == production or production in output.parents:
        raise ValueError("Batch 5 replay must not write production data/governance")
    if output == project or project in output.parents:
        raise ValueError("Batch 5 replay output must be outside the project tree")
    return output


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--mode", choices=("offline",), default="offline")
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--no-notify", action="store_true")
    parser.add_argument("--no-real-glm", action="store_true")
    parser.add_argument("--no-real-prometheus", action="store_true")
    parser.add_argument("--no-real-device", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    project_root = Path(args.project_root).expanduser().resolve(strict=True)
    output_root = _safe_output_root(project_root, Path(args.output_root))

    execution = run_offline_replay(
        str(project_root),
        args.request_id,
    )
    store = GovernanceStore(output_root)
    result = store.write(
        "replays",
        execution.record.replay_id,
        execution.record,
        overwrite=True,
    )
    safety = replay_safety_summary(execution)
    if not safety["safe"]:
        raise RuntimeError(f"offline replay safety check failed: {safety}")

    summary: dict[str, Any] = {
        **execution.summary(),
        "write_result": result.to_dict(),
        "safety": safety,
        "production_data_written": False,
        "network_calls_performed": False,
        "requested_disable_flags": {
            "notification": bool(args.no_notify),
            "glm": bool(args.no_real_glm),
            "prometheus": bool(args.no_real_prometheus),
            "device": bool(args.no_real_device),
        },
    }
    if args.json_out:
        json_out = Path(args.json_out).expanduser().resolve(strict=False)
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(
            json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
