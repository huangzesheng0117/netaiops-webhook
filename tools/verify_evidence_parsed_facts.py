#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netaiops.review_builder import generate_review_for_request_id


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify evidence_facts parsed-first behavior.")
    parser.add_argument("--rid", required=True)
    args = parser.parse_args()

    result = generate_review_for_request_id(args.rid)
    review = result.get("review_data", {}) or {}
    es = review.get("evidence_summary", {}) or {}
    facts = es.get("facts", {}) or {}

    keep_keys = [
        "parsed_facts_enabled",
        "facts_source_preference",
        "parsed_fact_sources",
        "interface",
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
        "channel_group_count",
        "port_channel_count",
        "etherchannel_member_count",
        "etherchannel_bundled_member_count",
        "etherchannel_down_member_count",
    ]

    compact = {k: facts.get(k) for k in keep_keys if k in facts}

    print("review_file:", result.get("review_file"))
    print(json.dumps(compact, ensure_ascii=False, indent=2))

    if facts.get("parsed_facts_enabled") is not True:
        print("ERROR: parsed_facts_enabled is not true")
        return 1

    sources = facts.get("parsed_fact_sources") or []
    required = {
        "cisco_show_interfaces",
        "cisco_show_interfaces_counters_errors",
        "cisco_etherchannel_summary",
    }

    missing = sorted(required - set(sources))
    if missing:
        print("ERROR: missing parsed sources:", ",".join(missing))
        return 1

    if not facts.get("interface"):
        print("ERROR: interface missing")
        return 1

    if not facts.get("oper_status") or not facts.get("admin_status"):
        print("ERROR: interface status missing")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
