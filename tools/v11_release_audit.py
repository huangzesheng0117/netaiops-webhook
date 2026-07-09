#!/usr/bin/env python3
"""Build one v11 Governance Release Audit JSON file without external calls."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_IMPORT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_IMPORT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_IMPORT_ROOT))

from netaiops.governance.release_audit import audit_safety_summary, build_release_audit  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--mode", choices=("development", "release"), default="development")
    parser.add_argument("--target-version", default="v11-governance")
    parser.add_argument("--governance-root")
    parser.add_argument("--json-out", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    project_root = Path(args.project_root).expanduser().resolve(strict=True)
    governance_root = Path(args.governance_root).expanduser().resolve(strict=False) if args.governance_root else None
    audit = build_release_audit(
        project_root,
        mode=args.mode,
        target_version=args.target_version,
        governance_root=governance_root,
        test_results={"status": "not_run", "reason": "external test runner provides final result"},
        replay_results={"status": "not_run", "reason": "batch 7 development audit only"},
        smoke_results={"status": "not_run", "reason": "no real smoke in batch 7"},
    )
    safety = audit_safety_summary(audit)
    if not safety["safe"]:
        raise RuntimeError(f"release audit safety check failed: {safety}")
    payload = {**audit.to_payload(), "safety": safety}
    output = Path(args.json_out).expanduser().resolve(strict=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
