#!/usr/bin/env bash
set -euo pipefail

cd /opt/netaiops-webhook
source venv/bin/activate

RID="${RID:-20260513_150124_794181_8b3764c8}"

echo "===== v6.6 all compileall ====="
python -m compileall -q app.py netaiops tools tests agent_runner

echo
echo "===== v6.6 release precheck before regression ====="
python tools/v6_release_precheck.py --rid "$RID"

echo
echo "===== v6.1 regression ====="
bash tools/regress_v6_1.sh

echo
echo "===== v6.2 regression ====="
bash tools/regress_v6_2.sh

echo
echo "===== v6.3 regression ====="
bash tools/regress_v6_3.sh

echo
echo "===== v6.4 regression ====="
bash tools/regress_v6_4.sh

echo
echo "===== v6.5 regression ====="
bash tools/regress_v6_5.sh

echo
echo "===== v6.6 final health check ====="
curl -sf http://127.0.0.1:18080/health | python -m json.tool

echo
echo "===== v6.6 write release snapshot ====="
python tools/v6_release_precheck.py \
  --rid "$RID" \
  --write docs/v6_6_release_snapshot.json

echo
echo "===== v6.6 release snapshot compact check ====="
python - <<'PY'
import json
from pathlib import Path

p = Path("/opt/netaiops-webhook/docs/v6_6_release_snapshot.json")
data = json.loads(p.read_text(encoding="utf-8"))

print("snapshot_file:", p)
print("verdict:", data.get("verdict"))
print("stage:", data.get("stage"))
print("violations:", data.get("violations"))
print("warnings:", data.get("warnings"))
print("health_ok:", data.get("health", {}).get("ok"))
print("git_status_count:", len(data.get("git_status_short") or []))

assert data.get("verdict") == "pass"
assert data.get("stage") == "v6.6"
assert not data.get("violations")
assert data.get("health", {}).get("ok") is True
PY

echo
echo "===== v6.6 git status summary ====="
git status --short || true

echo
echo "===== v6.6 all regression PASS ====="
