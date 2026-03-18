#!/usr/bin/env bash
set -euo pipefail

BASE_URL="http://127.0.0.1:18080"
PAYLOAD_FILE="${1:-/opt/netaiops-webhook/testdata/alertmanager/interface_down.json}"

if [[ ! -f "${PAYLOAD_FILE}" ]]; then
  echo "payload file not found: ${PAYLOAD_FILE}"
  exit 1
fi

if [[ "${PAYLOAD_FILE}" == *"/alertmanager/"* ]]; then
  ENDPOINT="${BASE_URL}/webhook/alertmanager"
  SOURCE_TYPE="alertmanager"
elif [[ "${PAYLOAD_FILE}" == *"/elastic/"* ]]; then
  ENDPOINT="${BASE_URL}/webhook/elastic"
  SOURCE_TYPE="elastic"
else
  echo "cannot determine source type from path: ${PAYLOAD_FILE}"
  echo "payload file path must contain /alertmanager/ or /elastic/"
  exit 1
fi

echo "===== payload file ====="
echo "${PAYLOAD_FILE}"

echo
echo "===== source type ====="
echo "${SOURCE_TYPE}"

echo
echo "===== health ====="
curl -s "${BASE_URL}/health" | python -m json.tool

echo
echo "===== send ${SOURCE_TYPE} test webhook ====="
RESP=$(curl -s -X POST "${ENDPOINT}" \
  -H 'Content-Type: application/json' \
  --data @"${PAYLOAD_FILE}")

echo "${RESP}" | python -m json.tool

REQUEST_ID=$(echo "${RESP}" | /opt/netaiops-webhook/venv/bin/python -c 'import sys,json; print(json.load(sys.stdin)["request_id"])')

echo
echo "===== request_id ====="
echo "${REQUEST_ID}"

sleep 15

echo
echo "===== query analysis by request_id ====="
curl -s "${BASE_URL}/analysis/${REQUEST_ID}" | python -m json.tool

echo
echo "===== latest analysis file ====="
LATEST_FILE=$(ls -1t /opt/netaiops-webhook/data/analysis/*.analysis.json | head -n 1)
echo "${LATEST_FILE}"

echo
echo "===== latest 20 log lines ====="
tail -n 20 /opt/netaiops-webhook/logs/netaiops-webhook.log
