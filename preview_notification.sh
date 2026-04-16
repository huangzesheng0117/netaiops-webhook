#!/bin/bash
set -e

REQ_ID="$1"

cd /opt/netaiops-webhook
source /opt/netaiops-webhook/venv/bin/activate

python -m netaiops.notification_payload "${REQ_ID}"
