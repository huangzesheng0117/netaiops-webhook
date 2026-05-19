#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any


STAGE = "v6.6"
DEFAULT_RID = "20260513_150124_794181_8b3764c8"

REQUIRED_GROUPS = {
    "docs": [
        "docs/v6_1_investigation_runbook.md",
        "docs/v6_2_tool_parser_runbook.md",
        "docs/v6_3_skill_runbook.md",
        "docs/v6_4_skill_runtime_runbook.md",
        "docs/v6_5_adaptive_evidence_runbook.md",
        "docs/v6_6_release_and_maintenance_runbook.md",
        "README_STATUS.md",
    ],
    "regression_scripts": [
        "tools/regress_v6_1.sh",
        "tools/regress_v6_2.sh",
        "tools/regress_v6_3.sh",
        "tools/regress_v6_4.sh",
        "tools/regress_v6_5.sh",
        "tools/regress_v6_all.sh",
    ],
    "v6_tools": [
        "tools/show_investigation_session.py",
        "tools/show_investigation_skill_context.py",
        "tools/show_investigation_skill_runtime.py",
        "tools/show_investigation_adaptive_context.py",
        "tools/show_skill_runtime.py",
        "tools/validate_tool_registry.py",
        "tools/validate_parser_registry.py",
        "tools/validate_skills.py",
        "tools/validate_skill_bindings.py",
        "tools/validate_skill_compliance.py",
        "tools/validate_skill_runtime_api.py",
        "tools/validate_adaptive_evidence_api.py",
        "tools/plan_adaptive_evidence.py",
        "tools/simulate_adaptive_missing_evidence.py",
        "tools/v6_release_precheck.py",
    ],
    "netaiops_modules": [
        "netaiops/investigation_state.py",
        "netaiops/investigation_policy.py",
        "netaiops/tool_registry.py",
        "netaiops/parser_registry.py",
        "netaiops/execution_parser_enricher.py",
        "netaiops/evidence_parsed_facts.py",
        "netaiops/skill_registry.py",
        "netaiops/skill_binding_validator.py",
        "netaiops/skill_session_context.py",
        "netaiops/skill_compliance_validator.py",
        "netaiops/skill_runtime.py",
        "netaiops/skill_runtime_api.py",
        "netaiops/skill_runtime_session_context.py",
        "netaiops/adaptive_evidence_policy.py",
        "netaiops/adaptive_evidence_planner.py",
        "netaiops/adaptive_session_context.py",
        "netaiops/adaptive_evidence_api.py",
    ],
    "skills": [
        "skills/interface_utilization_high/SKILL.md",
        "skills/interface_utilization_high/commands.yaml",
        "skills/interface_utilization_high/evidence_rules.yaml",
        "skills/interface_utilization_high/output_schema.json",
    ],
    "tests": [
        "tests/test_investigation_state.py",
        "tests/test_investigation_policy.py",
        "tests/test_tool_registry.py",
        "tests/test_parser_registry.py",
        "tests/test_execution_parser_enricher.py",
        "tests/test_evidence_facts.py",
        "tests/test_skill_registry.py",
        "tests/test_skill_binding_validator.py",
        "tests/test_skill_session_context.py",
        "tests/test_skill_compliance_validator.py",
        "tests/test_skill_runtime.py",
        "tests/test_skill_runtime_api.py",
        "tests/test_skill_runtime_session_context.py",
        "tests/test_adaptive_evidence_policy.py",
        "tests/test_adaptive_evidence_planner.py",
        "tests/test_adaptive_session_context.py",
        "tests/test_adaptive_missing_facts_sample.py",
        "tests/test_adaptive_evidence_api.py",
        "tests/test_v6_release_precheck.py",
    ],
}


EXECUTABLE_SCRIPTS = [
    "tools/regress_v6_1.sh",
    "tools/regress_v6_2.sh",
    "tools/regress_v6_3.sh",
    "tools/regress_v6_4.sh",
    "tools/regress_v6_5.sh",
    "tools/regress_v6_all.sh",
    "tools/validate_tool_registry.py",
    "tools/validate_parser_registry.py",
    "tools/validate_skills.py",
    "tools/validate_skill_bindings.py",
    "tools/validate_skill_compliance.py",
    "tools/validate_skill_runtime_api.py",
    "tools/validate_adaptive_evidence_api.py",
    "tools/v6_release_precheck.py",
]


def _run(cmd: list[str], cwd: Path) -> dict[str, Any]:
    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        return {
            "cmd": cmd,
            "returncode": p.returncode,
            "stdout": p.stdout.strip(),
            "stderr": p.stderr.strip(),
        }
    except Exception as exc:
        return {
            "cmd": cmd,
            "returncode": 999,
            "stdout": "",
            "stderr": str(exc),
        }


def _health(base_url: str) -> dict[str, Any]:
    url = base_url.rstrip("/") + "/health"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return {
            "ok": data.get("status") == "ok",
            "url": url,
            "data": data,
        }
    except Exception as exc:
        return {
            "ok": False,
            "url": url,
            "error": str(exc),
        }


def _path_status(base: Path) -> dict[str, Any]:
    groups = {}
    missing = []

    for group, items in REQUIRED_GROUPS.items():
        group_items = []
        for item in items:
            p = base / item
            exists = p.exists()
            group_items.append({
                "path": item,
                "exists": exists,
                "size_bytes": p.stat().st_size if exists and p.is_file() else None,
            })
            if not exists:
                missing.append(item)
        groups[group] = group_items

    return {
        "groups": groups,
        "missing": missing,
    }


def _script_status(base: Path) -> dict[str, Any]:
    result = []
    not_executable = []

    for item in EXECUTABLE_SCRIPTS:
        p = base / item
        exists = p.exists()
        executable = os.access(p, os.X_OK) if exists else False
        result.append({
            "path": item,
            "exists": exists,
            "executable": executable,
        })
        if exists and not executable:
            not_executable.append(item)

    return {
        "scripts": result,
        "not_executable": not_executable,
    }


def build_release_snapshot(
    base_dir: str | Path = ".",
    rid: str = DEFAULT_RID,
    base_url: str = "http://127.0.0.1:18080",
    check_health: bool = True,
) -> dict[str, Any]:
    base = Path(base_dir).resolve()
    violations = []
    warnings = []

    path_status = _path_status(base)
    script_status = _script_status(base)

    for item in path_status["missing"]:
        violations.append(f"missing required file: {item}")

    for item in script_status["not_executable"]:
        violations.append(f"script is not executable: {item}")

    git = _run(["git", "status", "--short"], cwd=base)
    git_status_lines = [x for x in git.get("stdout", "").splitlines() if x.strip()]
    if git_status_lines:
        warnings.append("git working tree has uncommitted changes; expected before final v6 commit")

    health = {}
    if check_health:
        health = _health(base_url)
        if not health.get("ok"):
            violations.append("health check failed")

    python_version = sys.version.split()[0]

    return {
        "verdict": "fail" if violations else "pass",
        "stage": STAGE,
        "purpose": "v6 release and maintenance precheck",
        "base_dir": str(base),
        "request_id": rid,
        "python_version": python_version,
        "violations": violations,
        "warnings": warnings,
        "required_path_status": path_status,
        "script_status": script_status,
        "health": health,
        "git_status_short": git_status_lines,
        "release_boundaries": {
            "adaptive_execution_enabled": False,
            "adaptive_mode": "skill_constrained_dry_run",
            "readonly_only": True,
            "llm_free_command_generation": False,
            "git_commit_in_this_batch": False,
        },
        "recommended_release_order": [
            "run bash tools/regress_v6_all.sh",
            "review docs/v6_6_release_snapshot.json",
            "review git diff --stat",
            "review sensitive files are not tracked",
            "restart netaiops-webhook if needed",
            "confirm /health",
            "create final git commit only after v6.6 is stable",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="NetAIOps webhook v6.6 release precheck.")
    parser.add_argument("--base-dir", default="/opt/netaiops-webhook")
    parser.add_argument("--rid", default=DEFAULT_RID)
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    parser.add_argument("--skip-health", action="store_true")
    parser.add_argument("--write", default="")
    args = parser.parse_args()

    snapshot = build_release_snapshot(
        base_dir=args.base_dir,
        rid=args.rid,
        base_url=args.base_url,
        check_health=not args.skip_health,
    )

    print(json.dumps(snapshot, ensure_ascii=False, indent=2))

    if args.write:
        out = Path(args.write)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")

    return 0 if snapshot.get("verdict") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
