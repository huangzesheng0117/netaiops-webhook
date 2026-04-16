#!/usr/bin/env bash
BASE_DIR="/opt/netaiops-webhook"
LOG_FILE="${BASE_DIR}/logs/netaiops-webhook.log"

while true; do
    clear
    echo "============================================================"
    echo " NetAIOps webhook 7x24 monitor"
    echo " Time: $(date '+%F %T %Z')"
    echo " Host: $(hostname)"
    echo "============================================================"
    echo

    echo "==== 1) Recent log lines (last 30) ===="
    if [ -f "${LOG_FILE}" ]; then
        tail -n 30 "${LOG_FILE}"
    else
        echo "log file not found: ${LOG_FILE}"
    fi
    echo

    for subdir in analysis plans dispatch callback execution reviews; do
        echo "==== 2) data/${subdir} latest files ===="
        if [ -d "${BASE_DIR}/data/${subdir}" ]; then
            ls -lt "${BASE_DIR}/data/${subdir}" 2>/dev/null | head -n 6
        else
            echo "directory not found: ${BASE_DIR}/data/${subdir}"
        fi
        echo
    done

    LATEST_ANALYSIS_FILE="$(ls -t ${BASE_DIR}/data/analysis/*.analysis.json 2>/dev/null | head -n 1)"

    echo "==== 3) Latest request summary ===="
    if [ -n "${LATEST_ANALYSIS_FILE}" ]; then
        BASENAME="$(basename "${LATEST_ANALYSIS_FILE}")"
        REQ_ID="${BASENAME#*_}"
        REQ_ID="${REQ_ID%.analysis.json}"

        echo "LATEST_ANALYSIS_FILE=${LATEST_ANALYSIS_FILE}"
        echo "REQ_ID=${REQ_ID}"
        echo

        SUMMARY_JSON="$(curl -s "http://127.0.0.1:18080/v4/request/${REQ_ID}/summary")"
        export SUMMARY_JSON

        python3 - <<'PY'
import os
import json

raw = os.environ.get("SUMMARY_JSON", "")

try:
    data = json.loads(raw) if raw else {}
    summary = data.get("summary", {}) or {}
    analysis = summary.get("analysis", {}) or {}
    plan = summary.get("plan", {}) or {}
    execution = summary.get("execution", {}) or {}
    review = summary.get("review", {}) or {}

    print("analysis.exists               =", analysis.get("exists"))
    print("analysis.status               =", analysis.get("status"))
    print("analysis.summary              =", analysis.get("summary"))
    print()
    print("plan.exists                   =", plan.get("exists"))
    print("plan.status                   =", plan.get("status"))
    print("plan.execution_source         =", plan.get("execution_source"))
    print("plan.auto_confirm_recommended =", plan.get("auto_confirm_recommended"))
    print("plan.playbook_id              =", ((plan.get("playbook", {}) or {}).get("playbook_id")))
    print()
    print("execution.exists              =", execution.get("exists"))
    print("execution.status              =", execution.get("status"))
    print("execution.mode                =", execution.get("mode"))
    print("execution.stats               =", execution.get("stats"))
    print()
    print("review.exists                 =", review.get("exists"))
    print("review.status                 =", review.get("status"))
    print("review.conclusion             =", review.get("conclusion"))
except Exception as e:
    print("summary parse failed:", e)
    if raw:
        print("raw summary head:")
        print(raw[:800])
PY
    else
        echo "no analysis file found yet"
    fi

    echo
    echo "refresh in 2 seconds, Ctrl+C to exit"
    sleep 2
done
