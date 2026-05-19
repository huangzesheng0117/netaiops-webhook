#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import urllib.request


EXPECTED_COMMANDS = {
    "show interfaces TenGigabitEthernet1/0/1",
    "show interfaces TenGigabitEthernet1/0/1 counters errors",
    "show etherchannel summary",
}


def get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate NetAIOps v6.5 adaptive evidence HTTP APIs.")
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    parser.add_argument("--rid", default="20260513_150124_794181_8b3764c8")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")

    plan = get_json(f"{base}/v6/adaptive/plan/{args.rid}")
    sim = get_json(f"{base}/v6/adaptive/simulate/missing-facts")

    plan_ap = plan.get("adaptive_plan", {})
    sim_ap = sim.get("adaptive_plan", {})

    result = {
        "plan_status": plan.get("status"),
        "plan_stage": plan.get("stage"),
        "plan_request_id": plan.get("request_id"),
        "plan_skill_name": plan_ap.get("skill_name"),
        "plan_dispatch_enabled": plan_ap.get("dispatch_enabled"),
        "plan_dry_run_only": plan_ap.get("dry_run_only"),
        "plan_policy_verdict": plan_ap.get("policy_verdict"),
        "plan_policy_violations": plan_ap.get("policy_violations"),
        "simulate_status": sim.get("status"),
        "simulate_stage": sim.get("stage"),
        "simulate_candidate_count": sim_ap.get("candidate_count"),
        "simulate_dispatch_enabled": sim_ap.get("dispatch_enabled"),
        "simulate_dry_run_only": sim_ap.get("dry_run_only"),
        "simulate_policy_verdict": sim_ap.get("policy_verdict"),
        "simulate_policy_violations": sim_ap.get("policy_violations"),
        "simulate_commands": sim_ap.get("commands"),
        "simulate_validation_errors": sim.get("validation_errors"),
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    assert plan.get("status") == "ok"
    assert plan.get("stage") == "v6.5_adaptive_plan"
    assert plan.get("request_id") == args.rid
    assert plan_ap.get("skill_name") == "interface_utilization_high"
    assert plan_ap.get("dispatch_enabled") is False
    assert plan_ap.get("dry_run_only") is True
    assert plan_ap.get("readonly_only") is True
    assert plan_ap.get("policy_verdict") == "pass"
    assert not plan_ap.get("policy_violations")

    assert sim.get("status") == "ok"
    assert sim.get("stage") == "v6.5_adaptive_missing_facts_simulation"
    assert sim_ap.get("candidate_count") == 3
    assert sim_ap.get("dispatch_enabled") is False
    assert sim_ap.get("dry_run_only") is True
    assert sim_ap.get("readonly_only") is True
    assert sim_ap.get("policy_verdict") == "pass"
    assert not sim_ap.get("policy_violations")
    assert not sim.get("validation_errors")

    commands = set(sim_ap.get("commands") or [])
    missing = EXPECTED_COMMANDS - commands
    assert not missing, f"missing expected commands: {missing}"

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
