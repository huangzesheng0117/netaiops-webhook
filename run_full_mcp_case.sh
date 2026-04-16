#!/bin/bash
set -e

REQ_ID="$1"

cd /opt/netaiops-webhook
source /opt/netaiops-webhook/venv/bin/activate

python - <<PY
from netaiops.dispatcher import dispatch_request_id
result = dispatch_request_id("${REQ_ID}")
print(result)
PY

/opt/netaiops-webhook/run_runner_mcp.sh "${REQ_ID}"
/opt/netaiops-webhook/run_callback.sh "${REQ_ID}"

echo
echo "===== final summary ====="
curl -s "http://127.0.0.1:18080/v4/request/${REQ_ID}/summary" | python -m json.tool
