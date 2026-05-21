#!/usr/bin/env bash

cd /opt/netaiops-webhook
source venv/bin/activate

python -m compileall -q \
  netaiops/v7_release_audit.py \
  netaiops/v7_release_audit_api.py \
  tools/v7_release_audit.py \
  tests/test_v7_release_audit.py

if [ "$?" -ne 0 ]; then
  echo "compileall failed"
  exit 2
fi

python -m unittest tests.test_v7_release_audit -v
if [ "$?" -ne 0 ]; then
  echo "unittest failed"
  exit 2
fi

python tools/v7_release_audit.py --summary --write
if [ "$?" -ne 0 ]; then
  echo "v7 release audit failed"
  exit 2
fi

printf '===== v7.7 release audit regression PASS =====\n'
