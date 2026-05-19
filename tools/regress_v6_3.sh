#!/usr/bin/env bash
set -euo pipefail

cd /opt/netaiops-webhook
source venv/bin/activate

RID="${RID:-20260513_150124_794181_8b3764c8}"

echo "===== v6.3 compileall ====="
python -m compileall -q app.py netaiops tools tests agent_runner

echo
echo "===== v6.3 unit tests ====="
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
  -v

echo
echo "===== v6.3 skill package validation ====="
python tools/validate_skills.py
python tools/validate_skills.py --skill interface_utilization_high

echo
echo "===== v6.3 skill binding validation ====="
python tools/validate_skill_bindings.py
python tools/validate_skill_bindings.py --skill interface_utilization_high

echo
echo "===== v6.3 investigation skill context ====="
python tools/show_investigation_skill_context.py --rid "$RID"

echo
echo "===== v6.3 skill compliance validation ====="
python tools/validate_skill_compliance.py --rid "$RID"

echo
echo "===== v6.3 compact compliance check ====="
python - <<PY
from netaiops.skill_compliance_validator import validate_request_skill_compliance

rid = "${RID}"
result = validate_request_skill_compliance(rid, "/opt/netaiops-webhook")

print("verdict:", result.get("verdict"))
print("skill_name:", result.get("skill_name"))
print("family:", result.get("family"))
print("violations:", result.get("violations"))
print("warnings:", result.get("warnings"))
print("execution_summary:", result.get("checks", {}).get("execution", {}).get("summary", {}))
print("review_summary:", result.get("checks", {}).get("review", {}).get("summary", {}))

assert result.get("verdict") == "pass"
assert result.get("skill_name") == "interface_utilization_high"
assert result.get("family") == "interface_or_link_utilization_high"
assert not result.get("violations")
PY

echo
echo "===== v6.2 compatibility regression ====="
bash tools/regress_v6_2.sh

echo
echo "===== v6.3 health check ====="
curl -sf http://127.0.0.1:18080/health | python -m json.tool

echo
echo "===== v6.3 regression PASS ====="
