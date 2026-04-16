#!/bin/bash
set -e

REQ_ID="$1"

cd /opt/netaiops-webhook
source /opt/netaiops-webhook/venv/bin/activate

python - <<PY
from netaiops.notifier import send_notification

result = send_notification("${REQ_ID}")
print(result)
PY
