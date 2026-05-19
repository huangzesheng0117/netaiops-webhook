#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netaiops.investigation_state import build_and_persist_investigation_session
from netaiops.adaptive_session_context import build_adaptive_evidence_context_for_session


def main() -> int:
    parser = argparse.ArgumentParser(description="Show v6.5 adaptive evidence context for an investigation session.")
    parser.add_argument("--rid", required=True)
    parser.add_argument("--base-dir", default=str(ROOT))
    parser.add_argument("--write-plan-file", action="store_true")
    args = parser.parse_args()

    session, session_file = build_and_persist_investigation_session(args.rid, args.base_dir)
    adaptive_context = build_adaptive_evidence_context_for_session(
        session=session,
        base_dir=args.base_dir,
        write_plan_file=args.write_plan_file,
    )

    result = {
        "status": "ok",
        "stage": "v6.5",
        "request_id": args.rid,
        "session_file": str(session_file),
        "adaptive_evidence_context": adaptive_context,
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    if adaptive_context.get("policy_violations"):
        return 1

    if adaptive_context.get("policy_verdict") != "pass":
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
