#!/usr/bin/env python3
"""Generate one v11 Governance Learning Report in JSON and Markdown."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

PROJECT_IMPORT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_IMPORT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_IMPORT_ROOT))

from netaiops.governance.report_builder import (  # noqa: E402
    build_learning_report,
    render_learning_report_markdown,
    report_consistency_summary,
)


def _atomic_write(path: Path, content: str) -> None:
    target = path.expanduser().resolve(strict=False)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=str(target.parent),
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, 0o640)
        os.replace(temp_path, target)
        temp_path = None
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--governance-root", required=True)
    parser.add_argument("--period", choices=("daily", "weekly", "monthly"), required=True)
    parser.add_argument("--date", required=True, help="Anchor date in YYYY-MM-DD format")
    parser.add_argument("--json-out", required=True)
    parser.add_argument("--markdown-out", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = build_learning_report(
        Path(args.governance_root),
        period=args.period,
        anchor_date=args.date,
    )
    markdown = render_learning_report_markdown(report)
    consistency = report_consistency_summary(report, markdown)
    if not consistency["consistent"]:
        raise RuntimeError(f"JSON/Markdown report mismatch: {consistency}")

    json_path = Path(args.json_out)
    markdown_path = Path(args.markdown_out)
    _atomic_write(
        json_path,
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    _atomic_write(markdown_path, markdown)

    summary: dict[str, Any] = {
        "status": "ok",
        "report_id": report["report_id"],
        "period": report["period"],
        "window": report["window"],
        "summary": report["summary"],
        "json_out": str(json_path.expanduser().resolve(strict=False)),
        "markdown_out": str(markdown_path.expanduser().resolve(strict=False)),
        "consistency": consistency,
        "external_calls_performed": False,
        "production_data_written": False,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
