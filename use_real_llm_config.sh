#!/usr/bin/env bash
set -euo pipefail

cp -a /opt/netaiops-webhook/config.yaml /opt/netaiops-webhook/backup/config.yaml.before_real_llm_$(date +%F_%H%M%S)
cp -a /opt/netaiops-webhook/config.real-llm.yaml /opt/netaiops-webhook/config.yaml

echo "config.yaml has been replaced by config.real-llm.yaml"
echo "Please edit real base_url / api_key / model before restarting service."
