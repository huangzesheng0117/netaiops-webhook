#!/usr/bin/env python3
"""Run v12 sanitized historical replay and quality gates offline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from netaiops.v12.historical_replay import run_replay_suite_sync


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURES = PROJECT_ROOT / "tests/fixtures/v12/replay"


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description=(
            "Run Batch O sanitized historical replay without "
            "network or notification side effects."
        )
    )
    value.add_argument(
        "--fixtures",
        default=str(DEFAULT_FIXTURES),
        help="Directory containing sanitized replay JSON fixtures.",
    )
    value.add_argument(
        "--output",
        default="",
        help="Optional JSON report path.",
    )
    return value


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    report = run_replay_suite_sync(args.fixtures)
    encoded = json.dumps(
        report,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name(output.name + ".batch-o.tmp")
        temporary.write_text(encoded, encoding="utf-8", newline="\n")
        temporary.replace(output)
    print(encoded, end="")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
