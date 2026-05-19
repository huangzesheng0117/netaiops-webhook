#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netaiops.skill_registry import list_skills, validate_all_skills, validate_skill_package


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate NetAIOps v6.3 skills.")
    parser.add_argument("--base-dir", default=str(ROOT))
    parser.add_argument("--skill", default="")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()

    if args.list:
        print(json.dumps(list_skills(args.base_dir), ensure_ascii=False, indent=2))
        return 0

    if args.skill:
        result = validate_skill_package(args.skill, args.base_dir)
    else:
        result = validate_all_skills(args.base_dir)

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("verdict") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
