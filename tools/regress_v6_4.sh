#!/usr/bin/env bash
set -euo pipefail

cd /opt/netaiops-webhook
source venv/bin/activate

RID="${RID:-20260513_150124_794181_8b3764c8}"

echo "===== v6.4 compileall ====="
python -m compileall -q app.py netaiops tools tests agent_runner

echo
echo "===== v6.4 unit tests ====="
python -m unittest \
  tests.test_output_judger \
  tests.test_evidence_facts \
  tests.test_investigation_state \
  tests.test_investigation_policy \
  tests.test_tool_registry \
  tests.test_parser_registry \
  tests.test_execution_parser_enricher \
  tests.test_skill_registry \
  tests.test_skill_binding_validator \
  tests.test_skill_session_context \
  tests.test_skill_compliance_validator \
  tests.test_skill_runtime \
  tests.test_skill_runtime_session_context \
  tests.test_skill_runtime_api \
  -v

echo
echo "===== v6.4 skill runtime validation ====="
python tools/show_skill_runtime.py --validate

echo
echo "===== v6.4 runtime index ====="
python tools/show_skill_runtime.py --index | head -120

echo
echo "===== v6.4 investigation runtime context ====="
python tools/show_investigation_skill_runtime.py --rid "$RID" --levels metadata

echo
echo "===== v6.4 verify persisted investigation runtime context ====="
python - <<PY
import json
from pathlib import Path

rid = "${RID}"
p = Path("/opt/netaiops-webhook/data/investigation") / f"{rid}.investigation.session.json"

data = json.loads(p.read_text(encoding="utf-8"))
rc = data.get("skill_runtime_context") or {}

print("session_file:", p)
print("stage:", rc.get("stage"))
print("runtime_version:", rc.get("runtime_version"))
print("load_strategy:", rc.get("load_strategy"))
print("matched:", rc.get("matched"))
print("family:", rc.get("family"))
print("skill_name:", rc.get("skill_name"))
print("loaded_levels:", rc.get("loaded_levels"))
print("content_embedded:", rc.get("content_embedded"))
print("content_policy:", rc.get("content_policy"))

assert rc.get("stage") == "v6.4"
assert rc.get("runtime_version") == "v6.4.0"
assert rc.get("load_strategy") == "progressive_loading"
assert rc.get("matched") is True
assert rc.get("family") == "interface_or_link_utilization_high"
assert rc.get("skill_name") == "interface_utilization_high"
assert rc.get("loaded_levels") == ["metadata"]
assert rc.get("content_embedded") is False
PY

echo
echo "===== v6.4 health before API validation ====="
curl -sf http://127.0.0.1:18080/health | python -m json.tool

echo
echo "===== v6.4 runtime HTTP API validation ====="
python tools/validate_skill_runtime_api.py

echo
echo "===== v6.4 direct API smoke test ====="
python - <<'PY'
import json
import urllib.request

base = "http://127.0.0.1:18080"

urls = {
    "index": f"{base}/v6/skills/runtime",
    "validate": f"{base}/v6/skills/runtime/validate",
    "family_metadata": f"{base}/v6/skills/runtime/family/interface_or_link_utilization_high?levels=metadata",
    "family_commands": f"{base}/v6/skills/runtime/family/interface_or_link_utilization_high?levels=metadata,commands",
    "skill_full": f"{base}/v6/skills/runtime/skill/interface_utilization_high?levels=metadata,instructions,commands,evidence,schema",
}

results = {}
for name, url in urls.items():
    with urllib.request.urlopen(url, timeout=10) as resp:
        results[name] = json.loads(resp.read().decode("utf-8"))

print(json.dumps({
    "index_status": results["index"].get("status"),
    "index_skill_count": results["index"].get("skill_count"),
    "validate_status": results["validate"].get("status"),
    "validate_verdict": results["validate"].get("result", {}).get("verdict"),
    "family_metadata_status": results["family_metadata"].get("status"),
    "family_metadata_levels": results["family_metadata"].get("runtime_context", {}).get("loaded_levels"),
    "family_metadata_content_embedded": results["family_metadata"].get("runtime_context", {}).get("runtime_api", {}).get("content_embedded"),
    "family_commands_levels": results["family_commands"].get("runtime_context", {}).get("loaded_levels"),
    "family_commands_content_embedded": results["family_commands"].get("runtime_context", {}).get("runtime_api", {}).get("content_embedded"),
    "skill_full_levels": results["skill_full"].get("runtime_context", {}).get("loaded_levels"),
    "skill_full_content_embedded": results["skill_full"].get("runtime_context", {}).get("runtime_api", {}).get("content_embedded"),
}, ensure_ascii=False, indent=2))

assert results["index"].get("status") == "ok"
assert results["index"].get("skill_count", 0) >= 1
assert results["validate"].get("status") == "ok"
assert results["validate"].get("result", {}).get("verdict") == "pass"

fm = results["family_metadata"].get("runtime_context", {})
assert fm.get("loaded_levels") == ["metadata"]
assert fm.get("runtime_api", {}).get("content_embedded") is False

fc = results["family_commands"].get("runtime_context", {})
assert fc.get("loaded_levels") == ["metadata", "commands"]
assert fc.get("runtime_api", {}).get("content_embedded") is True

sf = results["skill_full"].get("runtime_context", {})
assert sf.get("loaded_levels") == ["metadata", "instructions", "commands", "evidence", "schema"]
assert sf.get("runtime_api", {}).get("content_embedded") is True
PY

echo
echo "===== v6.3 compatibility regression ====="
bash tools/regress_v6_3.sh

echo
echo "===== v6.4 final health check ====="
curl -sf http://127.0.0.1:18080/health | python -m json.tool

echo
echo "===== v6.4 regression PASS ====="
