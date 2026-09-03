#!/opt/netaiops-webhook/venv/bin/python
"""V13 Production Owner Release Acceptance.

Read-only audit for the frozen V13 production boundary. It verifies Git,
VERSION/release docs, production ownership controls, source mount tokens and
the seven existing HTTP health endpoints. It never calls GLM, Prometheus MCP,
Netmiko MCP, Evidence MCP, Analytics MCP, OPS ES API, or any device.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

PROJECT_IMPORT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_IMPORT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_IMPORT_ROOT))

from netaiops.v13.production_control import MIGRATED_FAMILIES, load_release_control
from netaiops.v13.production_integration import production_contract_summary


RELEASE_VERSION = "13.0.0-v13-production-ownership"
HEALTH_PATHS = (
    "/health",
    "/evidence?limit=1",
    "/evidence-ui",
    "/governance/health",
    "/governance-ui",
    "/agent/health",
    "/agent-ui",
)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def git(root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(root),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed")
    return proc.stdout.rstrip("\n")


def probe(base_url: str, path: str) -> dict:
    req = Request(
        base_url.rstrip("/") + path,
        headers={"Accept": "application/json,text/html"},
    )
    try:
        with urlopen(req, timeout=8) as response:
            response.read(1024)
            code = int(response.status)
    except HTTPError as exc:
        code = int(exc.code)
    except (URLError, OSError) as exc:
        return {
            "path": path,
            "code": 0,
            "ok": False,
            "error_type": type(exc).__name__,
        }
    return {"path": path, "code": code, "ok": code == 200}


def require_token(
    root: Path,
    rel: str,
    token: str,
    problems: list[str],
) -> None:
    path = root / rel
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        problems.append(
            f"source_unreadable:{rel}:{type(exc).__name__}"
        )
        return
    if token not in text:
        problems.append(f"source_token_missing:{rel}:{token}")


def audit(
    project_root: Path,
    base_url: str,
    expected_head: str,
    expected_version: str,
) -> dict:
    problems: list[str] = []
    warnings: list[str] = []
    root = project_root.resolve()

    try:
        branch = git(root, "rev-parse", "--abbrev-ref", "HEAD")
        head = git(root, "rev-parse", "HEAD")
        origin = git(root, "rev-parse", "origin/main")
        remote = git(root, "config", "--get", "remote.origin.url")
        diff_check = git(root, "diff", "--check")
    except Exception as exc:
        return {
            "schema_version": "v13-release-acceptance-2",
            "status": "FAIL",
            "problems": [
                f"git_probe_failed:{type(exc).__name__}"
            ],
            "warnings": [],
            "checked_at": utcnow(),
        }

    if branch != "main":
        problems.append(f"branch_mismatch:{branch}")
    if head != expected_head or origin != expected_head:
        problems.append("baseline_head_or_origin_mismatch")
    if remote != "git@github.com:huangzesheng0117/netaiops-webhook.git":
        problems.append("remote_mismatch")
    if diff_check.strip():
        problems.append("git_diff_check_not_clean")

    try:
        version = (root / "VERSION").read_text(
            encoding="utf-8"
        ).strip()
    except Exception as exc:
        version = ""
        problems.append(
            f"version_unreadable:{type(exc).__name__}"
        )

    if version != expected_version:
        problems.append(
            f"version_mismatch:expected={expected_version}:actual={version}"
        )

    for relative in ("README.md", "README_STATUS.md"):
        try:
            text = (root / relative).read_text(encoding="utf-8")
        except Exception as exc:
            problems.append(
                f"release_doc_unreadable:{relative}:{type(exc).__name__}"
            )
            continue
        if expected_version not in text:
            problems.append(
                f"release_doc_version_missing:{relative}:{expected_version}"
            )

    try:
        control = load_release_control(root, strict=True)
    except Exception as exc:
        control = {}
        problems.append(
            f"release_control_invalid:{type(exc).__name__}"
        )

    if control:
        if control.get("mode") != "three_family":
            problems.append(
                f"release_control_mode:{control.get('mode')}"
            )
        if control.get("allowed_owner_families") != list(
            MIGRATED_FAMILIES
        ):
            problems.append("release_control_family_set_mismatch")
        if control.get("triage_mounted") is not True:
            problems.append("triage_not_mounted")
        if control.get("owner_real_calls_enabled") is not True:
            problems.append("owner_real_calls_not_enabled")
        if control.get("fail_open_to_legacy") is not True:
            problems.append("fail_open_to_legacy_not_true")
        if control.get("notifications_use_v12") is not False:
            problems.append("notifications_use_v12_changed")
        if control.get("logs_enabled") is not False:
            problems.append("logs_agent_enabled_in_v13")
        if control.get("knowledge_enabled") is not False:
            problems.append("knowledge_agent_enabled_in_v13")

    try:
        contract = production_contract_summary(project_root=root)
        if contract.get("triage_owner") != "triage":
            problems.append("triage_owner_contract_mismatch")
        if contract.get("metrics_owner") != "metrics_agent":
            problems.append("metrics_owner_contract_mismatch")
        if contract.get("device_owner") != "device_agent":
            problems.append("device_owner_contract_mismatch")
        if contract.get("notification_owner_changed") is not False:
            problems.append("notification_owner_changed_in_v13")
        if contract.get("arbitrary_promql_allowed") is not False:
            problems.append("arbitrary_promql_allowed")
        if contract.get("arbitrary_cli_allowed") is not False:
            problems.append("arbitrary_cli_allowed")
        if contract.get("write_commands_allowed") is not False:
            problems.append("write_commands_allowed")
    except Exception as exc:
        contract = {}
        problems.append(
            f"production_contract_invalid:{type(exc).__name__}"
        )

    tokens = {
        "app.py": (
            "_v13_mount_triage_safe",
            '_v13_mount_triage_safe(request_id, "alertmanager", normalized_events)',
        ),
        "netaiops/classifier.py": (
            "classify_event_from_family_result",
        ),
        "netaiops/plan_builder.py": (
            "load_canonical_family_result",
        ),
        "netaiops/pipeline.py": (
            "run_metrics_owner_for_plan_result",
            "run_device_owner_for_plan",
        ),
        "netaiops/prometheus_runtime_sidecar.py": (
            "v13_owner_call",
            "skip_duplicate",
        ),
        "agent_runner/runner.py": (
            "v13_device_owner_results_reused",
            "skip_duplicate",
        ),
        "netaiops/v13/evidence_owners.py": (
            "fenced_executor",
        ),
    }
    for rel, required in tokens.items():
        for token in required:
            require_token(root, rel, token, problems)

    health = [probe(base_url, path) for path in HEALTH_PATHS]
    if not all(item.get("ok") for item in health):
        problems.append("health_not_7_of_7")

    return {
        "schema_version": "v13-release-acceptance-2",
        "status": "PASS" if not problems else "FAIL",
        "problems": problems,
        "warnings": warnings,
        "checked_at": utcnow(),
        "git": {
            "branch": branch,
            "head": head,
            "origin_main": origin,
            "remote": remote,
            "diff_check_empty": not bool(diff_check.strip()),
        },
        "version": version,
        "control": control,
        "production_contract": contract,
        "health": health,
        "external_calls_performed": False,
        "notifications_sent": False,
        "device_commands_executed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--project-root",
        default="/opt/netaiops-webhook",
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:18080",
    )
    parser.add_argument("--expected-head", required=True)
    parser.add_argument(
        "--expected-version",
        default=RELEASE_VERSION,
    )
    parser.add_argument("--json-out", default="")
    args = parser.parse_args()

    report = audit(
        Path(args.project_root),
        args.base_url,
        args.expected_head,
        args.expected_version,
    )
    text = json.dumps(
        report,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    print(text)
    if args.json_out:
        path = Path(args.json_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    return 0 if report.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
