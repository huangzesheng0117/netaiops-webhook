#!/usr/bin/env bash
set -euo pipefail

cd /opt/netaiops-webhook
source venv/bin/activate

python -m compileall -q \
  netaiops/skill_proposal_builder.py \
  netaiops/skill_proposal_api.py \
  tools/build_skill_proposals.py \
  tools/query_skill_proposals.py \
  tests/test_skill_proposal_builder.py

python -m unittest tests.test_skill_proposal_builder -v

python tools/build_incident_memory.py --all --limit 100 --write
python tools/build_incident_relations.py --limit 100 --summary
python tools/build_skill_proposals.py --summary --validate-safety
python tools/query_skill_proposals.py --summary --min-score 50 >/tmp/netaiops_v7_3_skill_proposal_query.txt

printf '===== v7.3 skill proposal builder regression PASS =====\n'
