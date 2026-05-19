#!/usr/bin/env bash
set -euo pipefail

cd /opt/netaiops-webhook
source venv/bin/activate

RID="${RID:-20260513_150124_794181_8b3764c8}"

echo "===== v6.5 compileall ====="
python -m compileall -q app.py netaiops tools tests agent_runner

echo
echo "===== v6.5 unit tests ====="
python -m unittest \
  tests.test_output_judger \
  tests.test_evidence_facts \
  tests.test_investigation_state \
  tests.test_investigation_policy \
  tests.test_tool_registry \
  tests.test_parser_registry \
  tests.test_execution_parser_enricher \
  tests.test_skill_registry \
  tests.test_skill_binding_validator \
  tests.test_skill_session_context \
  tests.test_skill_compliance_validator \
  tests.test_skill_runtime \
  tests.test_skill_runtime_session_context \
  tests.test_skill_runtime_api \
  tests.test_adaptive_evidence_policy \
  tests.test_adaptive_evidence_planner \
  tests.test_adaptive_session_context \
  tests.test_adaptive_missing_facts_sample \
  tests.test_adaptive_evidence_api \
  -v

echo
echo "===== v6.5 dry-run adaptive plan for real request ====="
python tools/plan_adaptive_evidence.py --rid "$RID" --write

echo
echo "===== v6.5 verify real request adaptive plan ====="
python - <<PY
import json
from pathlib import Path

rid = "${RID}"
p = Path("/opt/netaiops-webhook/data/adaptive_plans") / f"{rid}.adaptive.plan.json"

data = json.loads(p.read_text(encoding="utf-8"))

print("adaptive_plan_file:", p)
print("stage:", data.get("stage"))
print("mode:", data.get("mode"))
print("family:", data.get("family"))
print("skill_name:", data.get("skill_name"))
print("dispatch_enabled:", data.get("dispatch_enabled"))
print("candidate_count:", data.get("candidate_count"))
print("policy_verdict:", data.get("policy_result", {}).get("verdict"))
print("policy_violations:", data.get("policy_result", {}).get("violations"))

assert data.get("stage") == "v6.5"
assert data.get("mode") == "skill_constrained_dry_run"
assert data.get("family") == "interface_or_link_utilization_high"
assert data.get("skill_name") == "interface_utilization_high"
assert data.get("dispatch_enabled") is False
assert data.get("policy_result", {}).get("verdict") == "pass"
assert not data.get("policy_result", {}).get("violations")
PY

echo
echo "===== v6.5 investigation adaptive context ====="
python tools/show_investigation_adaptive_context.py --rid "$RID" --write-plan-file

echo
echo "===== v6.5 verify persisted investigation adaptive context ====="
python - <<PY
import json
from pathlib import Path

rid = "${RID}"
p = Path("/opt/netaiops-webhook/data/investigation") / f"{rid}.investigation.session.json"

data = json.loads(p.read_text(encoding="utf-8"))
ac = data.get("adaptive_evidence_context") or {}

print("session_file:", p)
print("stage:", ac.get("stage"))
print("mode:", ac.get("mode"))
print("family:", ac.get("family"))
print("skill_name:", ac.get("skill_name"))
print("dispatch_enabled:", ac.get("dispatch_enabled"))
print("adaptive_execution_enabled:", ac.get("adaptive_execution_enabled"))
print("readonly_only:", ac.get("readonly_only"))
print("candidate_count:", ac.get("candidate_count"))
print("policy_verdict:", ac.get("policy_verdict"))
print("policy_violations:", ac.get("policy_violations"))

assert ac.get("stage") == "v6.5"
assert ac.get("mode") == "skill_constrained_dry_run"
assert ac.get("family") == "interface_or_link_utilization_high"
assert ac.get("skill_name") == "interface_utilization_high"
assert ac.get("dispatch_enabled") is False
assert ac.get("adaptive_execution_enabled") is False
assert ac.get("readonly_only") is True
assert ac.get("policy_verdict") == "pass"
assert not ac.get("policy_violations")
PY

echo
echo "===== v6.5 missing-facts sample regression ====="
bash tools/regress_v6_5_adaptive_missing_sample.sh

echo
echo "===== v6.5 health before adaptive API validation ====="
curl -sf http://127.0.0.1:18080/health | python -m json.tool

echo
echo "===== v6.5 adaptive evidence HTTP API validation ====="
python tools/validate_adaptive_evidence_api.py --rid "$RID"

echo
echo "===== v6.5 direct adaptive API smoke test ====="
python - <<PY
import json
import urllib.request

rid = "${RID}"
base = "http://127.0.0.1:18080"

urls = {
    "plan": f"{base}/v6/adaptive/plan/{rid}",
    "simulate": f"{base}/v6/adaptive/simulate/missing-facts",
}

results = {}

for name, url in urls.items():
    with urllib.request.urlopen(url, timeout=10) as resp:
        results[name] = json.loads(resp.read().decode("utf-8"))

plan = results["plan"].get("adaptive_plan", {})
sim = results["simulate"].get("adaptive_plan", {})

print(json.dumps({
    "plan_status": results["plan"].get("status"),
    "plan_stage": results["plan"].get("stage"),
    "plan_request_id": results["plan"].get("request_id"),
    "plan_skill_name": plan.get("skill_name"),
    "plan_dispatch_enabled": plan.get("dispatch_enabled"),
    "plan_dry_run_only": plan.get("dry_run_only"),
    "plan_readonly_only": plan.get("readonly_only"),
    "plan_policy_verdict": plan.get("policy_verdict"),
    "plan_policy_violations": plan.get("policy_violations"),
    "simulate_status": results["simulate"].get("status"),
    "simulate_stage": results["simulate"].get("stage"),
    "simulate_candidate_count": sim.get("candidate_count"),
    "simulate_dispatch_enabled": sim.get("dispatch_enabled"),
    "simulate_dry_run_only": sim.get("dry_run_only"),
    "simulate_readonly_only": sim.get("readonly_only"),
    "simulate_policy_verdict": sim.get("policy_verdict"),
    "simulate_policy_violations": sim.get("policy_violations"),
    "simulate_commands": sim.get("commands"),
    "simulate_validation_errors": results["simulate"].get("validation_errors"),
}, ensure_ascii=False, indent=2))

assert results["plan"].get("status") == "ok"
assert results["plan"].get("stage") == "v6.5_adaptive_plan"
assert results["plan"].get("request_id") == rid
assert plan.get("skill_name") == "interface_utilization_high"
assert plan.get("dispatch_enabled") is False
assert plan.get("dry_run_only") is True
assert plan.get("readonly_only") is True
assert plan.get("policy_verdict") == "pass"
assert not plan.get("policy_violations")

assert results["simulate"].get("status") == "ok"
assert results["simulate"].get("stage") == "v6.5_adaptive_missing_facts_simulation"
assert sim.get("candidate_count") == 3
assert sim.get("dispatch_enabled") is False
assert sim.get("dry_run_only") is True
assert sim.get("readonly_only") is True
assert sim.get("policy_verdict") == "pass"
assert not sim.get("policy_violations")
assert not results["simulate"].get("validation_errors")

commands = set(sim.get("commands") or [])
assert "show interfaces TenGigabitEthernet1/0/1" in commands
assert "show interfaces TenGigabitEthernet1/0/1 counters errors" in commands
assert "show etherchannel summary" in commands
PY

echo
echo "===== v6.4 compatibility regression ====="
bash tools/regress_v6_4.sh

echo
echo "===== v6.5 final health check ====="
curl -sf http://127.0.0.1:18080/health | python -m json.tool

echo
echo "===== v6.5 regression PASS ====="
