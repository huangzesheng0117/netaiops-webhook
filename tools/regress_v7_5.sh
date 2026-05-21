#!/usr/bin/env bash

cd /opt/netaiops-webhook
source venv/bin/activate

python -m compileall -q \
  netaiops/skill_draft_builder.py \
  netaiops/skill_draft_api.py \
  tools/build_skill_drafts.py \
  tests/test_skill_draft_builder.py

if [ "$?" -ne 0 ]; then
  echo "compileall failed"
  exit 2
fi

python -m unittest tests.test_skill_draft_builder -v
if [ "$?" -ne 0 ]; then
  echo "unittest failed"
  exit 2
fi

python tools/build_skill_drafts.py --summary --validate-safety
if [ "$?" -ne 0 ]; then
  echo "build_skill_drafts failed"
  exit 2
fi

python tools/build_skill_drafts.py --list --limit 5 >/tmp/netaiops_v7_5_skill_drafts.txt
if [ "$?" -ne 0 ]; then
  echo "list skill drafts failed"
  exit 2
fi

printf '===== v7.5 skill draft builder regression PASS =====\n'
