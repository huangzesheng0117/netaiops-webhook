#!/usr/bin/env bash
set -euo pipefail

cd /opt/netaiops-webhook
source venv/bin/activate

python -m compileall -q \
  netaiops/memory_store.py \
  netaiops/memory_api.py \
  tools/build_incident_memory.py \
  tools/query_incident_memory.py \
  tests/test_memory_store.py

python -m unittest tests.test_memory_store -v

python tools/build_incident_memory.py --all --limit 20 --write
python tools/query_incident_memory.py --limit 5 --summary >/tmp/netaiops_v7_1_memory_query.txt

printf '===== v7.1 incident memory regression PASS =====\n'
