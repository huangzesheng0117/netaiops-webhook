#!/opt/netaiops-webhook/venv/bin/python
# -*- coding: utf-8 -*-

import json
import subprocess
import time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

BASE_DIR = Path("/opt/netaiops-webhook")
APP_PY = BASE_DIR / "app.py"
RAW_DIR = BASE_DIR / "data" / "raw"
PLAN_DIR = BASE_DIR / "data" / "plans"

HEALTH_URL = "http://127.0.0.1:18080/health"
WEBHOOK_URL = "http://127.0.0.1:18080/webhook/alertmanager"
SUMMARY_URL = "http://127.0.0.1:18080/v4/request/{request_id}/summary"

KEYWORD = "DCI线路流量突降"


def run(cmd, check=True):
    print("\n$ " + " ".join(cmd))
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.stdout:
        print(proc.stdout.rstrip())
    if proc.stderr:
        print(proc.stderr.rstrip())
    if check and proc.returncode != 0:
        raise SystemExit(proc.returncode)
    return proc


def http_get_json(url, timeout=20):
    req = Request(url, method="GET")
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def http_post_json_file(url, path, timeout=30):
    data = path.read_bytes()
    req = Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def wait_for_health(url, retries=30, interval=1.0):
    last_err = None
    for i in range(1, retries + 1):
        try:
            data = http_get_json(url, timeout=5)
            if isinstance(data, dict) and data.get("status") == "ok":
                print(f"health ok on attempt {i}/{retries}")
                return data
            last_err = f"unexpected health response: {data}"
        except Exception as e:
            last_err = repr(e)
        print(f"health not ready yet ({i}/{retries}), retrying in {interval:.1f}s ...")
        time.sleep(interval)
    raise SystemExit(f"health check failed after {retries} retries, last_err={last_err}")


def find_latest_raw():
    matched = []
    for fp in sorted(RAW_DIR.glob("*.json")):
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
            if KEYWORD in text:
                matched.append(fp)
        except Exception:
            pass
    if not matched:
        raise SystemExit(f"no raw file found for keyword: {KEYWORD}")
    return matched[-1]


def print_plan_key_fields(request_id):
    plan_file = PLAN_DIR / f"alertmanager_{request_id}.plan.json"
    if not plan_file.exists():
        print(f"\nplan file not found: {plan_file}")
        return

    with open(plan_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    print("\n==== plan key fields ====")
    print("request_id =", data.get("request_id"))
    print("plan_status =", data.get("plan_status"))
    print("execution_source =", data.get("execution_source"))
    print("auto_confirm_recommended =", data.get("auto_confirm_recommended"))
    print("classification.playbook_type =", (data.get("classification") or {}).get("playbook_type"))
    print("classification.auto_execute_allowed =", (data.get("classification") or {}).get("auto_execute_allowed"))
    print("playbook.matched =", (data.get("playbook") or {}).get("matched"))
    print("playbook.playbook_id =", (data.get("playbook") or {}).get("playbook_id"))
    print("policy_result =", json.dumps(data.get("policy_result", {}), ensure_ascii=False, indent=2))

    print("\ncommands =")
    for item in data.get("execution_candidates", []):
        print(" -", item.get("command"))


def main():
    print("==== 1) py_compile app.py ====")
    run([str(BASE_DIR / "venv" / "bin" / "python"), "-m", "py_compile", str(APP_PY)])

    print("\n==== 2) restart service ====")
    run(["sudo", "systemctl", "restart", "netaiops-webhook"])
    run(["sudo", "systemctl", "status", "netaiops-webhook", "--no-pager"], check=False)

    print("\n==== 3) wait for health ====")
    health = wait_for_health(HEALTH_URL, retries=30, interval=1.0)
    print(json.dumps(health, ensure_ascii=False, indent=2))

    print("\n==== 4) find latest raw ====")
    raw_file = find_latest_raw()
    print(raw_file)

    print("\n==== 5) replay alert ====")
    replay = http_post_json_file(WEBHOOK_URL, raw_file, timeout=30)
    print(json.dumps(replay, ensure_ascii=False, indent=2))
    request_id = replay.get("request_id")
    if not request_id:
        raise SystemExit("request_id missing in replay response")

    print("\n==== 6) wait a bit for pipeline ====")
    time.sleep(3)

    print("\n==== 7) query summary ====")
    summary = http_get_json(SUMMARY_URL.format(request_id=request_id), timeout=20)
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    print_plan_key_fields(request_id)

    print("\n==== 8) final verdict ====")
    summary_body = summary.get("summary", {}) or {}
    plan = summary_body.get("plan", {}) or {}
    execution = summary_body.get("execution", {}) or {}
    review = summary_body.get("review", {}) or {}

    print("summary.plan.status =", plan.get("status"))
    print("summary.execution.exists =", execution.get("exists"))
    print("summary.execution.status =", execution.get("status"))
    print("summary.review.exists =", review.get("exists"))
    print("summary.review.status =", review.get("status"))


if __name__ == "__main__":
    main()
