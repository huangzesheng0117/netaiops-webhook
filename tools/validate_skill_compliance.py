#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netaiops.skill_compliance_validator import validate_request_skill_compliance


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate request execution/review against matched NetAIOps Skill.")
    parser.add_argument("--rid", required=True)
    parser.add_argument("--base-dir", default=str(ROOT))
    parser.add_argument("--strict-notification", action="store_true")
    args = parser.parse_args()

    result = validate_request_skill_compliance(
        request_id=args.rid,
        base_dir=args.base_dir,
        strict_notification=args.strict_notification,
    )

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("verdict") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
