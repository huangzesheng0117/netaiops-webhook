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
from netaiops.skill_runtime_session_context import build_skill_runtime_context_for_session


def main() -> int:
    parser = argparse.ArgumentParser(description="Show v6.4 skill runtime context for an investigation session.")
    parser.add_argument("--rid", required=True)
    parser.add_argument("--base-dir", default=str(ROOT))
    parser.add_argument("--levels", default="metadata")
    args = parser.parse_args()

    levels = [x.strip() for x in args.levels.split(",") if x.strip()]

    session, session_file = build_and_persist_investigation_session(args.rid, args.base_dir)
    runtime_context = build_skill_runtime_context_for_session(
        session=session,
        base_dir=args.base_dir,
        levels=levels,
    )

    result = {
        "status": "ok",
        "stage": "v6.4",
        "request_id": args.rid,
        "session_file": str(session_file),
        "skill_runtime_context": runtime_context,
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    if runtime_context.get("matched") is not True:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
