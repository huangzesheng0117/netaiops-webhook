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
from netaiops.skill_session_context import compact_skill_context


def main() -> int:
    parser = argparse.ArgumentParser(description="Show v6.3 skill context for an investigation session.")
    parser.add_argument("--rid", required=True)
    parser.add_argument("--base-dir", default=str(ROOT))
    args = parser.parse_args()

    session, session_file = build_and_persist_investigation_session(args.rid, args.base_dir)
    context = session.get("skill_context") if isinstance(session.get("skill_context"), dict) else {}

    result = {
        "status": "ok",
        "stage": "v6.3",
        "request_id": args.rid,
        "session_file": str(session_file),
        "skill_context": compact_skill_context(context),
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    if context.get("violations"):
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
