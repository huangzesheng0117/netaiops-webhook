#!/usr/bin/env bash
set -euo pipefail

cd /opt/netaiops-webhook
source venv/bin/activate

echo "===== v6.1 compileall ====="
python -m compileall -q app.py netaiops tools tests agent_runner

echo
echo "===== v6.1 unit tests ====="
python -m unittest \
  tests.test_output_judger \
  tests.test_evidence_facts \
  tests.test_investigation_state \
  tests.test_investigation_policy \
  -v

echo
echo "===== v6.1 investigation session regression ====="
python tools/regress_investigation_sessions.py --limit 10 --skip-in-progress

echo
echo "===== v6.1 health check ====="
curl -sf http://127.0.0.1:18080/health | python -m json.tool

echo
echo "===== v6.1 regression PASS ====="
