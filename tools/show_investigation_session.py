#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netaiops.investigation_state import (
    build_and_persist_investigation_session,
    build_investigation_session,
    render_session_text,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Show or build NetAIOps v6.1 investigation session.")
    parser.add_argument("--rid", "--request-id", dest="request_id", required=True, help="NetAIOps request_id")
    parser.add_argument("--base-dir", default=str(ROOT), help="Project base directory")
    parser.add_argument("--build", action="store_true", help="Build and persist session JSON")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of text")
    args = parser.parse_args()

    if args.build:
        session, path = build_and_persist_investigation_session(args.request_id, args.base_dir)
    else:
        session = build_investigation_session(args.request_id, args.base_dir)
        path = None

    if args.json:
        print(json.dumps(session, ensure_ascii=False, indent=2))
    else:
        print(render_session_text(session))
        if path:
            print("")
            print(f"session_file: {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
