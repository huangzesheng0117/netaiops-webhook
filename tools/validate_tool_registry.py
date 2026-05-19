#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netaiops.tool_registry import validate_tool_registry


def main() -> int:
    result = validate_tool_registry()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("verdict") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
