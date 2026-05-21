# NetAIOps webhook v7.6 Learning Report Runbook

v7.6 summarizes the Hermes-style learning loop:

incident_memory -> relation_engine -> skill_proposal -> review_gate -> skill_draft

## Safety

- Reads v7 sidecar files only.
- Writes data/learning_reports only.
- Does not execute MCP or device commands.
- Does not write formal skills/.
- Does not auto merge.

## Commands

python tools/build_learning_report.py --summary --validate-safety

python tools/build_learning_report.py --list

curl -s 'http://127.0.0.1:18080/v7/learning/report?rebuild=true' | python -m json.tool

curl -s 'http://127.0.0.1:18080/v7/learning/reports?limit=10' | python -m json.tool

## Expected

- report JSON and Markdown are generated under data/learning_reports/.
- safety.ok=true.
- lifecycle_counts summarize v7.1-v7.5 state.
