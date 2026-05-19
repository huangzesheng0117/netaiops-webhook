#!/usr/bin/env bash
set -euo pipefail

cd /opt/netaiops-webhook
source venv/bin/activate

RID="${RID:-20260513_150124_794181_8b3764c8}"

echo "===== v6.2 compileall ====="
python -m compileall -q app.py netaiops tools tests agent_runner

echo
echo "===== v6.2 unit tests ====="
python -m unittest \
  tests.test_output_judger \
  tests.test_evidence_facts \
  tests.test_investigation_state \
  tests.test_investigation_policy \
  tests.test_tool_registry \
  tests.test_parser_registry \
  tests.test_execution_parser_enricher \
  -v

echo
echo "===== v6.2 tool registry validation ====="
python tools/validate_tool_registry.py

echo
echo "===== v6.2 parser registry validation ====="
python tools/validate_parser_registry.py --sample --rid "$RID"

echo
echo "===== v6.2 execution parsed enrichment ====="
python tools/enrich_execution_parsed.py --rid "$RID"

echo
echo "===== v6.2 verify parsed command count ====="
python - <<PY
import json
from pathlib import Path

rid = "${RID}"
files = sorted(Path("/opt/netaiops-webhook/data/execution").glob(f"*{rid}*.json"))
if not files:
    raise SystemExit("execution file not found")

p = files[-1]
data = json.loads(p.read_text(encoding="utf-8"))

statuses = {}
for item in data.get("command_results", []) or []:
    parsed = item.get("parsed") if isinstance(item.get("parsed"), dict) else {}
    status = parsed.get("status") or "missing"
    statuses[status] = statuses.get(status, 0) + 1

print("execution_file:", p)
print("parse_status_counts:", statuses)

assert statuses.get("parsed") == 5, f"expected parsed=5, got {statuses}"
assert statuses.get("skipped", 0) == 0, f"expected skipped=0, got {statuses}"
PY

echo
echo "===== v6.2 verify evidence parsed-first ====="
python tools/verify_evidence_parsed_facts.py --rid "$RID"

echo
echo "===== v6.2 health check ====="
curl -sf http://127.0.0.1:18080/health | python -m json.tool

echo
echo "===== v6.1 compatibility regression ====="
bash tools/regress_v6_1.sh

echo
echo "===== v6.2 regression PASS ====="
