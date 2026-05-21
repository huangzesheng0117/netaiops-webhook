#!/usr/bin/env bash

cd /opt/netaiops-webhook
source venv/bin/activate

python -m compileall -q \
  netaiops/skill_proposal_review.py \
  netaiops/skill_proposal_review_api.py \
  tools/review_skill_proposal.py \
  tests/test_skill_proposal_review.py

if [ "$?" -ne 0 ]; then
  echo "compileall failed"
  exit 2
fi

python -m unittest tests.test_skill_proposal_review -v
if [ "$?" -ne 0 ]; then
  echo "unittest failed"
  exit 2
fi

python tools/build_skill_proposals.py --summary --validate-safety
if [ "$?" -ne 0 ]; then
  echo "build_skill_proposals failed"
  exit 2
fi

python tools/review_skill_proposal.py --pending --min-score 50 --limit 5 >/tmp/netaiops_v7_4_pending.txt
if [ "$?" -ne 0 ]; then
  echo "pending query failed"
  exit 2
fi

python tools/review_skill_proposal.py --summary >/tmp/netaiops_v7_4_summary.json
if [ "$?" -ne 0 ]; then
  echo "review summary failed"
  exit 2
fi

printf '===== v7.4 skill proposal review gate regression PASS =====\n'
