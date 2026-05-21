"""v7.7 Release Audit.

Final pre-release audit for NetAIOps webhook v7 Hermes-style sidecar.

Safety:
- Does not execute MCP or device commands.
- Does not modify formal skills/.
- Does not commit Git.
- Writes only docs/v7_7_release_audit_snapshot.json when requested.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

SCHEMA_VERSION = "v7.7.release_audit.v1"
DEFAULT_BASE_DIR = Path("/opt/netaiops-webhook")
SNAPSHOT_REL = Path("docs/v7_7_release_audit_snapshot.json")

ALLOWED_IPS = {"127.0.0.1", "0.0.0.0"}

STRICT_SIDE_CAR_DIRS = [
    "data/skill_proposals",
    "data/skill_proposal_reviews",
    "data/skill_drafts",
    "data/learning_reports",
]

WARN_SIDE_CAR_DIRS = [
    "data/memory",
]

REQUIRED_FILES = [
    "docs/v7_1_incident_memory_runbook.md",
    "docs/v7_2_relation_engine_runbook.md",
    "docs/v7_3_skill_proposal_builder_runbook.md",
    "docs/v7_4_skill_proposal_review_runbook.md",
    "docs/v7_5_skill_draft_builder_runbook.md",
    "docs/v7_6_learning_report_runbook.md",
    "docs/v7_7_release_audit_runbook.md",

    "netaiops/memory_store.py",
    "netaiops/memory_api.py",
    "netaiops/relation_engine.py",
    "netaiops/relation_api.py",
    "netaiops/skill_proposal_builder.py",
    "netaiops/skill_proposal_api.py",
    "netaiops/skill_proposal_review.py",
    "netaiops/skill_proposal_review_api.py",
    "netaiops/skill_draft_builder.py",
    "netaiops/skill_draft_api.py",
    "netaiops/learning_report.py",
    "netaiops/learning_report_api.py",
    "netaiops/v7_release_audit.py",
    "netaiops/v7_release_audit_api.py",

    "tools/build_incident_memory.py",
    "tools/query_incident_memory.py",
    "tools/build_incident_relations.py",
    "tools/query_incident_relations.py",
    "tools/build_skill_proposals.py",
    "tools/query_skill_proposals.py",
    "tools/review_skill_proposal.py",
    "tools/build_skill_drafts.py",
    "tools/build_learning_report.py",
    "tools/v7_release_audit.py",

    "tools/regress_v7_1.sh",
    "tools/regress_v7_2.sh",
    "tools/regress_v7_3.sh",
    "tools/regress_v7_4.sh",
    "tools/regress_v7_5.sh",
    "tools/regress_v7_6.sh",
    "tools/regress_v7_7.sh",
    "tools/regress_v7_all.sh",

    "tests/test_memory_store.py",
    "tests/test_relation_engine.py",
    "tests/test_skill_proposal_builder.py",
    "tests/test_skill_proposal_review.py",
    "tests/test_skill_draft_builder.py",
    "tests/test_learning_report.py",
    "tests/test_v7_release_audit.py",
]

REQUIRED_API_ROUTES = [
    "/v7/memory/incidents",
    "/v7/relations/incidents",
    "/v7/skill-proposals",
    "/v7/skill-proposal-reviews",
    "/v7/skill-drafts",
    "/v7/learning/report",
    "/v7/learning/reports",
    "/v7/release/audit",
]

REQUIRED_EXECUTABLES = [
    "tools/build_incident_memory.py",
    "tools/query_incident_memory.py",
    "tools/build_incident_relations.py",
    "tools/query_incident_relations.py",
    "tools/build_skill_proposals.py",
    "tools/query_skill_proposals.py",
    "tools/review_skill_proposal.py",
    "tools/build_skill_drafts.py",
    "tools/build_learning_report.py",
    "tools/v7_release_audit.py",
    "tools/regress_v7_1.sh",
    "tools/regress_v7_2.sh",
    "tools/regress_v7_3.sh",
    "tools/regress_v7_4.sh",
    "tools/regress_v7_5.sh",
    "tools/regress_v7_6.sh",
    "tools/regress_v7_7.sh",
    "tools/regress_v7_all.sh",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def run_cmd(args: List[str], cwd: Path) -> Dict[str, Any]:
    try:
        cp = subprocess.run(
            args,
            cwd=str(cwd),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
        return {
            "rc": cp.returncode,
            "stdout": cp.stdout.strip()[:4000],
            "stderr": cp.stderr.strip()[:4000],
        }
    except Exception as exc:
        return {
            "rc": 999,
            "stdout": "",
            "stderr": str(exc),
        }


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def required_file_status(base_dir: Path) -> Dict[str, Any]:
    rows = []
    missing = []

    for rel in REQUIRED_FILES:
        p = base_dir / rel
        item = {
            "path": rel,
            "exists": p.exists(),
            "size_bytes": p.stat().st_size if p.exists() and p.is_file() else 0,
        }
        rows.append(item)
        if not item["exists"]:
            missing.append(rel)

    return {
        "files": rows,
        "missing": missing,
    }


def executable_status(base_dir: Path) -> Dict[str, Any]:
    rows = []
    not_executable = []

    for rel in REQUIRED_EXECUTABLES:
        p = base_dir / rel
        executable = p.exists() and os.access(str(p), os.X_OK)
        rows.append({
            "path": rel,
            "exists": p.exists(),
            "executable": executable,
        })
        if not executable:
            not_executable.append(rel)

    return {
        "scripts": rows,
        "not_executable": not_executable,
    }


def api_route_status(base_dir: Path) -> Dict[str, Any]:
    app_text = read_text(base_dir / "app.py")
    rows = []
    missing = []

    for route in REQUIRED_API_ROUTES:
        exists = route in app_text
        rows.append({
            "route": route,
            "exists": exists,
        })
        if not exists:
            missing.append(route)

    return {
        "routes": rows,
        "missing": missing,
    }


def scan_text_for_raw_ipv4(text: str) -> List[str]:
    hits = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    return sorted(set([x for x in hits if x not in ALLOWED_IPS]))


def scan_text_for_secret_patterns(text: str) -> List[str]:
    lower = text.lower()
    patterns = [
        r"password\s*[:=]\s*[^,\s\"']{4,}",
        r"passwd\s*[:=]\s*[^,\s\"']{4,}",
        r"api[_-]?key\s*[:=]\s*[^,\s\"']{4,}",
        r"access[_-]?token\s*[:=]\s*[^,\s\"']{4,}",
        r"secret[_-]?token\s*[:=]\s*[^,\s\"']{4,}",
        r"webhook[_-]?secret\s*[:=]\s*[^,\s\"']{4,}",
        r"mcp[_-]?server[_-]?url\s*[:=]\s*[^,\s\"']{4,}",
    ]

    found = []
    for pat in patterns:
        if re.search(pat, lower):
            found.append(pat)

    return found


def iter_scan_files(root: Path) -> List[Path]:
    if not root.exists():
        return []

    allow_suffix = {".json", ".jsonl", ".md", ".yaml", ".yml", ".txt"}
    result = []

    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in allow_suffix:
            continue
        result.append(p)

    return result


def sensitive_sidecar_scan(base_dir: Path) -> Dict[str, Any]:
    violations = []
    warnings = []

    for rel in STRICT_SIDE_CAR_DIRS:
        root = base_dir / rel
        for p in iter_scan_files(root):
            text = read_text(p)
            ip_hits = scan_text_for_raw_ipv4(text)
            secret_hits = scan_text_for_secret_patterns(text)

            if ip_hits:
                violations.append({
                    "type": "raw_ipv4_in_strict_sidecar",
                    "file": str(p.relative_to(base_dir)),
                    "count": len(ip_hits),
                })

            if secret_hits:
                violations.append({
                    "type": "secret_pattern_in_strict_sidecar",
                    "file": str(p.relative_to(base_dir)),
                    "patterns": secret_hits,
                })

    for rel in WARN_SIDE_CAR_DIRS:
        root = base_dir / rel
        for p in iter_scan_files(root):
            text = read_text(p)
            ip_hits = scan_text_for_raw_ipv4(text)
            secret_hits = scan_text_for_secret_patterns(text)

            if ip_hits:
                warnings.append({
                    "type": "raw_ipv4_in_memory_sidecar_warning",
                    "file": str(p.relative_to(base_dir)),
                    "count": len(ip_hits),
                    "note": "memory sidecar may contain historical IP-like hostnames; published reports/proposals/drafts must stay sanitized",
                })

            if secret_hits:
                violations.append({
                    "type": "secret_pattern_in_memory_sidecar",
                    "file": str(p.relative_to(base_dir)),
                    "patterns": secret_hits,
                })

    return {
        "violations": violations,
        "warnings": warnings,
    }


def runtime_git_status(base_dir: Path) -> Dict[str, Any]:
    tracked = run_cmd(
        [
            "git",
            "ls-files",
            "--",
            "data/memory",
            "data/skill_proposals",
            "data/skill_proposal_reviews",
            "data/skill_drafts",
            "data/learning_reports",
        ],
        cwd=base_dir,
    )

    git_status = run_cmd(["git", "status", "--short"], cwd=base_dir)

    tracked_files = [
        line.strip()
        for line in tracked.get("stdout", "").splitlines()
        if line.strip()
    ]

    ignored_rows = []
    for rel in [
        "data/memory",
        "data/skill_proposals",
        "data/skill_proposal_reviews",
        "data/skill_drafts",
        "data/learning_reports",
    ]:
        cp = run_cmd(["git", "check-ignore", "-q", rel], cwd=base_dir)
        ignored_rows.append({
            "path": rel,
            "ignored": cp.get("rc") == 0,
        })

    return {
        "tracked_runtime_files": tracked_files,
        "tracked_runtime_count": len(tracked_files),
        "runtime_ignore_status": ignored_rows,
        "git_status_short": [
            line for line in git_status.get("stdout", "").splitlines()
            if line.strip()
        ],
    }


def boundary_status(base_dir: Path) -> Dict[str, Any]:
    return {
        "adaptive_execution_enabled": False,
        "adaptive_mode": "skill_constrained_dry_run",
        "readonly_only": True,
        "llm_free_command_generation": False,
        "proposal_auto_merge_enabled": False,
        "draft_writes_formal_skill": False,
        "git_commit_in_this_batch": False,
        "formal_skill_dir_write_in_v7_7": False,
    }


def build_violations_and_warnings(report: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    violations: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []

    missing_files = report["required_path_status"]["missing"]
    if missing_files:
        violations.append({
            "type": "missing_required_v7_files",
            "count": len(missing_files),
            "items": missing_files[:20],
        })

    missing_routes = report["api_route_status"]["missing"]
    if missing_routes:
        violations.append({
            "type": "missing_required_v7_api_routes",
            "count": len(missing_routes),
            "items": missing_routes,
        })

    not_exec = report["executable_status"]["not_executable"]
    if not_exec:
        violations.append({
            "type": "non_executable_v7_tools",
            "count": len(not_exec),
            "items": not_exec[:20],
        })

    tracked_runtime = report["runtime_git_status"]["tracked_runtime_files"]
    if tracked_runtime:
        violations.append({
            "type": "runtime_sidecar_files_tracked_by_git",
            "count": len(tracked_runtime),
            "items": tracked_runtime[:20],
        })

    for item in report["runtime_git_status"]["runtime_ignore_status"]:
        if not item.get("ignored"):
            warnings.append({
                "type": "runtime_sidecar_dir_not_explicitly_gitignored",
                "path": item.get("path"),
                "note": "not fatal if parent data/ is ignored, but should be reviewed during Git cleanup",
            })

    scan = report["sensitive_sidecar_scan"]
    violations.extend(scan.get("violations") or [])
    warnings.extend(scan.get("warnings") or [])

    if report["runtime_git_status"]["git_status_short"]:
        warnings.append({
            "type": "working_tree_has_uncommitted_changes",
            "count": len(report["runtime_git_status"]["git_status_short"]),
            "note": "expected before final v7 Git cleanup",
        })

    return {
        "violations": violations,
        "warnings": warnings,
    }


def audit_v7_release(base_dir: Path = DEFAULT_BASE_DIR, write: bool = False) -> Dict[str, Any]:
    base_dir = Path(base_dir)

    report: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "stage": "v7.7_release_audit",
        "purpose": "v7 Hermes-style sidecar release and Git cleanup precheck",
        "created_at": utc_now(),
        "base_dir": str(base_dir),
        "required_path_status": required_file_status(base_dir),
        "executable_status": executable_status(base_dir),
        "api_route_status": api_route_status(base_dir),
        "sensitive_sidecar_scan": sensitive_sidecar_scan(base_dir),
        "runtime_git_status": runtime_git_status(base_dir),
        "release_boundaries": boundary_status(base_dir),
        "recommended_release_order": [
            "run bash tools/regress_v7_all.sh",
            "run bash tools/regress_v6_all.sh",
            "review docs/v7_7_release_audit_snapshot.json",
            "review git status --short",
            "review git diff --stat",
            "confirm runtime sidecar files are not tracked",
            "confirm /health",
            "commit only after manual Git review",
        ],
    }

    vw = build_violations_and_warnings(report)
    report["violations"] = vw["violations"]
    report["warnings"] = vw["warnings"]
    report["verdict"] = "pass" if not report["violations"] else "fail"

    if write:
        path = base_dir / SNAPSHOT_REL
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        report["snapshot_file"] = str(path)

    return report
