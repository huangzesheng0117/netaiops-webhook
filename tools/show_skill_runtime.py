#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netaiops.skill_runtime import (
    build_runtime_context_for_family,
    build_skill_index,
    load_skill_runtime_context,
    validate_skill_runtime,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Show NetAIOps v6.4 Skill Runtime context.")
    parser.add_argument("--base-dir", default=str(ROOT))
    parser.add_argument("--skill", default="")
    parser.add_argument("--family", default="")
    parser.add_argument("--levels", default="metadata")
    parser.add_argument("--index", action="store_true")
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()

    levels = [x.strip() for x in args.levels.split(",") if x.strip()]

    if args.validate:
        result = validate_skill_runtime(args.base_dir)
    elif args.index:
        result = build_skill_index(args.base_dir)
    elif args.family:
        result = build_runtime_context_for_family(args.family, args.base_dir, levels)
    elif args.skill:
        result = load_skill_runtime_context(args.skill, args.base_dir, levels)
    else:
        result = build_skill_index(args.base_dir)

    print(json.dumps(result, ensure_ascii=False, indent=2))

    if isinstance(result, dict) and result.get("verdict") == "fail":
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
