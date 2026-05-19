#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netaiops.execution_parser_enricher import enrich_execution_file


RID_RE = re.compile(r"(\d{8}_\d{6}_\d{6}_[0-9a-fA-F]+)")


def find_execution_file(base_dir: Path, rid: str) -> Path | None:
    d = base_dir / "data" / "execution"
    if not d.exists():
        return None

    files = [p for p in d.rglob("*.json") if rid in p.name]
    if not files:
        return None

    return sorted(files, key=lambda x: x.stat().st_mtime, reverse=True)[0]


def main() -> int:
    parser = argparse.ArgumentParser(description="Enrich execution command_results with v6.2 parsed facts.")
    parser.add_argument("--rid", required=True, help="NetAIOps request_id")
    parser.add_argument("--base-dir", default=str(ROOT))
    args = parser.parse_args()

    base = Path(args.base_dir)
    execution_file = find_execution_file(base, args.rid)

    if not execution_file:
        print(json.dumps({
            "ok": False,
            "stage": "v6.2",
            "error": "execution file not found",
            "request_id": args.rid,
        }, ensure_ascii=False, indent=2))
        return 1

    result = enrich_execution_file(execution_file)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
