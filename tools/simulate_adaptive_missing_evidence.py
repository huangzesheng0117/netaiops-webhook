#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netaiops.adaptive_evidence_planner import build_adaptive_evidence_plan


EXPECTED_COMMANDS = {
    "show interfaces TenGigabitEthernet1/0/1",
    "show interfaces TenGigabitEthernet1/0/1 counters errors",
    "show etherchannel summary",
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Simulate v6.5 adaptive evidence planning with missing facts.")
    parser.add_argument("--base-dir", default=str(ROOT))
    parser.add_argument("--fixture-dir", default=str(ROOT / "tests" / "fixtures" / "adaptive_missing_facts"))
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    base_dir = Path(args.base_dir)
    fixture_dir = Path(args.fixture_dir)

    session = load_json(fixture_dir / "session.missing_facts.json")
    execution_data = load_json(fixture_dir / "execution.empty.json")
    review_data = load_json(fixture_dir / "review.missing_facts.json")

    plan = build_adaptive_evidence_plan(
        session=session,
        execution_data=execution_data,
        review_data=review_data,
        base_dir=base_dir,
    )

    out_file = ""
    if args.write:
        out_dir = base_dir / "data" / "adaptive_plans"
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / f"{plan.get('request_id')}.adaptive.missing_facts.plan.json"
        out.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
        out_file = str(out)

    commands = [item.get("command") for item in plan.get("candidates", []) if isinstance(item, dict)]
    command_set = set(commands)

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
        "commands": commands,
        "adaptive_plan_file": out_file,
    }

    print(json.dumps(compact, ensure_ascii=False, indent=2))

    errors = []

    if plan.get("stage") != "v6.5":
        errors.append("stage is not v6.5")

    if plan.get("mode") != "skill_constrained_dry_run":
        errors.append("mode is not skill_constrained_dry_run")

    if plan.get("dispatch_enabled") is not False:
        errors.append("dispatch_enabled must be false")

    if plan.get("policy_result", {}).get("verdict") != "pass":
        errors.append("policy verdict is not pass")

    if plan.get("policy_result", {}).get("violations"):
        errors.append("policy violations is not empty")

    if plan.get("candidate_count", 0) <= 0:
        errors.append("candidate_count should be greater than 0 for missing-facts sample")

    if args.strict:
        missing = sorted(EXPECTED_COMMANDS - command_set)
        if missing:
            errors.append("expected commands missing: " + ",".join(missing))

        for item in plan.get("candidates", []) or []:
            if item.get("dispatch_status") != "not_dispatched_dry_run":
                errors.append("candidate dispatch_status is not dry-run: " + str(item.get("command")))
            if item.get("readonly") is not True:
                errors.append("candidate readonly is not true: " + str(item.get("command")))

    if errors:
        print(json.dumps({"errors": errors}, ensure_ascii=False, indent=2))
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
