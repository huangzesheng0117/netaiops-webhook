#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netaiops.skill_binding_validator import (
    load_skill_binding_graph,
    validate_all_skill_bindings,
    validate_skill_binding,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate NetAIOps v6.3 skill bindings.")
    parser.add_argument("--base-dir", default=str(ROOT))
    parser.add_argument("--skill", default="")
    parser.add_argument("--graph", action="store_true")
    args = parser.parse_args()

    if args.graph:
        if not args.skill:
            print(json.dumps({
                "verdict": "fail",
                "error": "--graph requires --skill",
            }, ensure_ascii=False, indent=2))
            return 1

        result = load_skill_binding_graph(args.skill, args.base_dir)
    elif args.skill:
        result = validate_skill_binding(args.skill, args.base_dir)
    else:
        result = validate_all_skill_bindings(args.base_dir)

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("verdict", "pass") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
