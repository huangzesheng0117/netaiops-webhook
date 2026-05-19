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

from netaiops.parser_registry import enrich_command_results_with_parsed, validate_parser_registry


RID_RE = re.compile(r"(\d{8}_\d{6}_\d{6}_[0-9a-fA-F]+)")


def find_latest_execution_file(base_dir: Path, rid: str | None = None) -> Path | None:
    d = base_dir / "data" / "execution"
    if not d.exists():
        return None

    files = []
    for p in d.rglob("*.json"):
        if rid and rid not in p.name:
            continue
        if not rid and not RID_RE.search(p.name):
            continue
        files.append(p)

    if not files:
        return None

    return sorted(files, key=lambda x: x.stat().st_mtime, reverse=True)[0]


def compact_facts(facts: dict) -> dict:
    keys = [
        "interface",
        "command_interface",
        "admin_status",
        "oper_status",
        "bandwidth_bps",
        "input_rate_bps",
        "output_rate_bps",
        "crc",
        "fcs_err",
        "rcv_err",
        "xmit_err",
        "out_discards",
        "output_discards",
        "output_errors",
        "output_drops",
        "input_utilization_percent_estimated",
        "output_utilization_percent_estimated",
        "channel_group_count",
        "aggregator_count",
        "port_channel_count",
        "member_count",
        "bundled_member_count",
        "down_member_count",
    ]
    return {k: facts.get(k) for k in keys if k in facts}


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate NetAIOps v6.2 parser registry.")
    parser.add_argument("--base-dir", default=str(ROOT))
    parser.add_argument("--rid", default="")
    parser.add_argument("--sample", action="store_true", help="Parse latest execution file as sample")
    args = parser.parse_args()

    result = validate_parser_registry()
    print("===== parser registry =====")
    print(json.dumps(result, ensure_ascii=False, indent=2))

    if result.get("verdict") != "pass":
        return 1

    if args.sample:
        base = Path(args.base_dir)
        f = find_latest_execution_file(base, args.rid or None)
        if not f:
            print("NO_EXECUTION_FILE_FOUND")
            return 1

        data = json.loads(f.read_text(encoding="utf-8"))
        enriched = enrich_command_results_with_parsed(data, force=True)

        print("===== sample file =====")
        print(f)

        for item in enriched.get("command_results", []) or []:
            if not isinstance(item, dict):
                continue
            parsed = item.get("parsed") if isinstance(item.get("parsed"), dict) else {}
            print("- command:", item.get("command"))
            print("  status:", parsed.get("status"))
            print("  parser:", parsed.get("parser"))
            facts = parsed.get("parsed") if isinstance(parsed.get("parsed"), dict) else {}
            if facts:
                print("  facts:", json.dumps(compact_facts(facts), ensure_ascii=False))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
