#!/usr/bin/env bash

cd /opt/netaiops-webhook
source venv/bin/activate

python -m compileall -q \
  netaiops/learning_report.py \
  netaiops/learning_report_api.py \
  tools/build_learning_report.py \
  tests/test_learning_report.py

if [ "$?" -ne 0 ]; then
  echo "compileall failed"
  exit 2
fi

python -m unittest tests.test_learning_report -v
if [ "$?" -ne 0 ]; then
  echo "unittest failed"
  exit 2
fi

python tools/build_learning_report.py --summary --validate-safety
if [ "$?" -ne 0 ]; then
  echo "build_learning_report failed"
  exit 2
fi

python tools/build_learning_report.py --list --limit 5 >/tmp/netaiops_v7_6_learning_reports.txt
if [ "$?" -ne 0 ]; then
  echo "list learning reports failed"
  exit 2
fi

printf '===== v7.6 learning report regression PASS =====\n'
