#!/usr/bin/env bash
set -euo pipefail

cd /opt/netaiops-webhook
source venv/bin/activate

python -m compileall -q \
  netaiops/relation_engine.py \
  netaiops/relation_api.py \
  tools/build_incident_relations.py \
  tools/query_incident_relations.py \
  tests/test_relation_engine.py

python -m unittest tests.test_relation_engine -v

python tools/build_incident_memory.py --all --limit 50 --write
python tools/build_incident_relations.py --limit 50 --summary
python tools/query_incident_relations.py --min-score 60 --limit 5 --summary >/tmp/netaiops_v7_2_relation_query.txt

printf '===== v7.2 relation engine regression PASS =====\n'
