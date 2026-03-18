#!/bin/bash
set -e

cd /opt/netaiops-webhook
source /opt/netaiops-webhook/venv/bin/activate

exec uvicorn app:app --host 0.0.0.0 --port 18080
