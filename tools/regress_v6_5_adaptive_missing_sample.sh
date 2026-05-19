#!/usr/bin/env bash
set -euo pipefail

cd /opt/netaiops-webhook
source venv/bin/activate

echo "===== v6.5 missing-facts sample compileall ====="
python -m compileall -q app.py netaiops tools tests agent_runner

echo
echo "===== v6.5 missing-facts sample unit tests ====="
python -m unittest \
  tests.test_adaptive_evidence_policy \
  tests.test_adaptive_evidence_planner \
  tests.test_adaptive_session_context \
  tests.test_adaptive_missing_facts_sample \
  -v

echo
echo "===== v6.5 missing-facts sample strict simulation ====="
python tools/simulate_adaptive_missing_evidence.py --write --strict

echo
echo "===== v6.5 missing-facts plan file verify ====="
python - <<'PY'
import json
from pathlib import Path

p = Path("/opt/netaiops-webhook/data/adaptive_plans/simulated_missing_facts_001.adaptive.missing_facts.plan.json")
data = json.loads(p.read_text(encoding="utf-8"))

commands = [item.get("command") for item in data.get("candidates", []) or []]

print("adaptive_plan_file:", p)
print("stage:", data.get("stage"))
print("mode:", data.get("mode"))
print("skill_name:", data.get("skill_name"))
print("family:", data.get("family"))
print("dispatch_enabled:", data.get("dispatch_enabled"))
print("candidate_count:", data.get("candidate_count"))
print("policy_verdict:", data.get("policy_result", {}).get("verdict"))
print("policy_violations:", data.get("policy_result", {}).get("violations"))
print("commands:", commands)

assert data.get("stage") == "v6.5"
assert data.get("mode") == "skill_constrained_dry_run"
assert data.get("skill_name") == "interface_utilization_high"
assert data.get("family") == "interface_or_link_utilization_high"
assert data.get("dispatch_enabled") is False
assert data.get("policy_result", {}).get("verdict") == "pass"
assert not data.get("policy_result", {}).get("violations")
assert data.get("candidate_count") == 3
assert "show interfaces TenGigabitEthernet1/0/1" in commands
assert "show interfaces TenGigabitEthernet1/0/1 counters errors" in commands
assert "show etherchannel summary" in commands
PY

echo
echo "===== v6.5 missing-facts sample regression PASS ====="
