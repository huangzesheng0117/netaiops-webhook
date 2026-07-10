#!/usr/bin/env python3
"""Bounded historical backfill for NetAIOps Webhook v11 Governance."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _bootstrap(project_root: Path) -> None:
    candidates = (Path(__file__).resolve().parents[1], project_root.resolve(strict=False))
    for candidate in reversed(candidates):
        value = str(candidate)
        if value not in sys.path:
            sys.path.insert(0, value)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", default="/opt/netaiops-webhook")
    parser.add_argument(
        "--output-root",
        default="/opt/netaiops-webhook/data/governance",
        help="Governance Store root; use /tmp for verification runs.",
    )
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--request-id", action="append", default=[])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--execute", action="store_true")
    parser.add_argument("--no-proposals", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--json-report", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    project_root = Path(args.project_root).expanduser().resolve(strict=False)
    output_root = Path(args.output_root).expanduser().resolve(strict=False)
    _bootstrap(project_root)

    from netaiops.governance.integration import run_backfill

    report = run_backfill(
        project_root=project_root,
        governance_root=output_root,
        request_ids=args.request_id or None,
        limit=args.limit,
        dry_run=bool(args.dry_run),
        include_proposals=not args.no_proposals,
        force=bool(args.force),
        persist_run_record=bool(args.execute),
    )
    target = Path(args.json_report).expanduser().resolve(strict=False)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(target)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
