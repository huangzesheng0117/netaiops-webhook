#!/bin/bash
set -e

REQ_ID="$1"
TS=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/opt/netaiops-webhook/logs/runner/${REQ_ID}_${TS}.log"

cd /opt/netaiops-webhook
source /opt/netaiops-webhook/venv/bin/activate

export RUNNER_BACKEND=mcp
export MCP_WRAPPER_CMD=/opt/netaiops-webhook/agent_runner/mcp_bridge_netmiko.py
export MCP_HELPER_CMD=/opt/netaiops-mcp-helper/bridge_helper.py
export MCP_SERVER_URL=http://10.191.97.137:10000/sse
unset MCP_NAME_MAP_FILE
export MCP_TIMEOUT=60

python -m agent_runner.runner "${REQ_ID}" 2>&1 | tee "${LOG_FILE}"
