#!/bin/bash
set -e

REQ_ID="$1"

cd /opt/netaiops-webhook
source /opt/netaiops-webhook/venv/bin/activate

python - <<PY
import json
from pathlib import Path
from agent_runner.callback_client import post_execution_result

request_id = "${REQ_ID}"
runner_file = Path(f"/opt/netaiops-webhook/data/callback/{request_id}.runner.result.json")

with open(runner_file, "r", encoding="utf-8") as f:
    payload = json.load(f)

result = post_execution_result(
    webhook_base_url="http://127.0.0.1:18080",
    request_id=request_id,
    payload=payload,
    timeout=30,
)

print(result)
PY
