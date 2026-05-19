#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netaiops.adaptive_evidence_planner import build_adaptive_evidence_plan_for_request


def main() -> int:
    parser = argparse.ArgumentParser(description="Build v6.5 skill-constrained adaptive evidence dry-run plan.")
    parser.add_argument("--rid", required=True)
    parser.add_argument("--base-dir", default=str(ROOT))
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()

    plan = build_adaptive_evidence_plan_for_request(
        request_id=args.rid,
        base_dir=args.base_dir,
        write=args.write,
    )

    compact = {
        "stage": plan.get("stage"),
        "mode": plan.get("mode"),
        "request_id": plan.get("request_id"),
        "family": plan.get("family"),
        "skill_name": plan.get("skill_name"),
        "matched_skill": plan.get("matched_skill"),
        "dispatch_enabled": plan.get("dispatch_enabled"),
        "dispatch_reason": plan.get("dispatch_reason"),
        "candidate_count": plan.get("candidate_count"),
        "suppressed_candidate_count": plan.get("suppressed_candidate_count"),
        "gaps": plan.get("gaps"),
        "policy_verdict": plan.get("policy_result", {}).get("verdict"),
        "policy_violations": plan.get("policy_result", {}).get("violations"),
        "policy_warnings": plan.get("policy_result", {}).get("warnings"),
        "candidates": plan.get("candidates"),
        "adaptive_plan_file": plan.get("adaptive_plan_file", ""),
    }

    print(json.dumps(compact, ensure_ascii=False, indent=2))

    return 0 if plan.get("policy_result", {}).get("verdict") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
