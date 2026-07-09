"""Governance Release Audit for NetAIOps Webhook v11.

Batch 7 creates a deterministic development/release audit record from local Git
state, governed test/replay/smoke summaries, and Governance Store integrity. It
is side-effect free: it never restarts the service, calls GLM/MCP, sends
notifications, modifies Skill/Playbook files, or writes production data.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .contracts import AuditStatus, GOVERNANCE_SCHEMA_VERSION
from .schemas import AuditRecord
from .store import ALLOWED_COLLECTIONS, GovernanceStore

RELEASE_AUDIT_VERSION = "11.0.0-release-audit-v1"
_FORBIDDEN_PATH_RE = re.compile(
    r"(^|/)(config\.yaml|data|logs|backup|venv|__pycache__)(/|$)"
    r"|(^|/)(\.env|[^/]+\.env)$"
    r"|\.(zip|tar|tgz|gz|bz2|xz|7z)$"
)
_SECRET_TEXT_RE = re.compile(r"(?i)(token|secret|password|api[_-]?key|authorization|x-ops-admin-key)")

class ReleaseAuditError(RuntimeError):
    """Raised when a governed release audit cannot be built safely."""

def _aware_utc(value: datetime | None = None) -> datetime:
    result = value or datetime.now(timezone.utc)
    if result.tzinfo is None or result.utcoffset() is None:
        raise ReleaseAuditError("created_at must include timezone information")
    return result.astimezone(timezone.utc)

def _run_git(project_root: Path, args: Sequence[str]) -> tuple[int, str, str]:
    proc = subprocess.run(["git", *args], cwd=str(project_root), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()

def _git_lines(project_root: Path, args: Sequence[str]) -> list[str]:
    code, out, _err = _run_git(project_root, args)
    if code != 0 or not out:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]

def git_worktree_state(project_root: Path | str) -> dict[str, Any]:
    root = Path(project_root).expanduser().resolve(strict=True)
    branch_code, branch, branch_err = _run_git(root, ["rev-parse", "--abbrev-ref", "HEAD"])
    commit_code, commit, commit_err = _run_git(root, ["rev-parse", "HEAD"])
    status = _git_lines(root, ["status", "--short", "--untracked-files=all"])
    staged = _git_lines(root, ["diff", "--cached", "--name-only"])
    unstaged = _git_lines(root, ["diff", "--name-only"])
    untracked = _git_lines(root, ["ls-files", "--others", "--exclude-standard"])
    changed = sorted(set(staged) | set(unstaged) | set(untracked))
    return {
        "available": branch_code == 0 and commit_code == 0,
        "branch": branch if branch_code == 0 else "",
        "commit": commit if commit_code == 0 else "",
        "dirty": bool(status),
        "status_short": status,
        "staged": sorted(set(staged)),
        "unstaged": sorted(set(unstaged)),
        "untracked": sorted(set(untracked)),
        "changed_files": changed,
        "errors": [msg for msg in (branch_err, commit_err) if msg],
    }

def sensitive_file_check(paths: Sequence[str]) -> dict[str, Any]:
    unique = sorted({str(path).strip().replace("\\", "/") for path in paths if str(path).strip()})
    forbidden = [path for path in unique if _FORBIDDEN_PATH_RE.search(path)]
    suspicious = [path for path in unique if _SECRET_TEXT_RE.search(path)]
    return {"checked_count": len(unique), "forbidden_paths": forbidden, "suspicious_secret_named_paths": suspicious, "passed": not forbidden and not suspicious}

def governance_data_integrity(governance_root: Path | str) -> dict[str, Any]:
    root = Path(governance_root).expanduser().resolve(strict=False)
    store = GovernanceStore(root)
    collections: dict[str, Any] = {}
    total_valid = 0
    total_corrupt = 0
    for collection in sorted(ALLOWED_COLLECTIONS):
        try:
            page = store.list_records(collection, page=1, page_size=500, descending=False)
            collections[collection] = {"valid_count": page.total, "page_item_count": len(page.items), "corrupt_count": page.corrupt_count, "errors": [dict(item) for item in page.errors[:20]]}
            total_valid += page.total
            total_corrupt += page.corrupt_count
        except Exception as exc:
            collections[collection] = {"valid_count": 0, "page_item_count": 0, "corrupt_count": 1, "errors": [{"collection": collection, "error": str(exc)}]}
            total_corrupt += 1
    return {"root": str(root), "exists": root.exists(), "collections": collections, "total_valid_records": total_valid, "total_corrupt_records": total_corrupt, "passed": total_corrupt == 0}

def _audit_id(commit: str, mode: str, created_at: datetime, changed_files: Sequence[str]) -> str:
    material = json.dumps({"version": RELEASE_AUDIT_VERSION, "commit": commit, "mode": mode, "created_at": created_at.isoformat(), "changed_files": sorted(changed_files)}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"audit_{hashlib.sha256(material).hexdigest()[:24]}"

def _normalise_summary(value: Mapping[str, Any] | None, *, default_status: str) -> dict[str, Any]:
    if value is None:
        return {"status": default_status, "provided": False}
    return dict(value)

def determine_audit_status(*, worktree: Mapping[str, Any], sensitive: Mapping[str, Any], governance_integrity: Mapping[str, Any], test_results: Mapping[str, Any], replay_results: Mapping[str, Any], smoke_results: Mapping[str, Any]) -> tuple[AuditStatus, list[str], list[str]]:
    problems: list[str] = []
    warnings: list[str] = []
    if not worktree.get("available"):
        problems.append("git_metadata_unavailable")
    if not sensitive.get("passed", False):
        problems.append("sensitive_or_forbidden_path_detected")
    if not governance_integrity.get("passed", False):
        warnings.append("governance_store_has_corrupt_records")
    if str(test_results.get("status", "unknown")).lower() not in {"passed", "ok", "not_run"}:
        problems.append("tests_not_passed")
    if bool(replay_results.get("safety_regression", False)):
        problems.append("replay_safety_regression")
    if str(smoke_results.get("status", "not_run")).lower() in {"failed", "error"}:
        problems.append("smoke_failed")
    if worktree.get("dirty"):
        warnings.append("worktree_has_planned_or_uncommitted_changes")
    if problems:
        return AuditStatus.BLOCKED, sorted(set(problems)), sorted(set(warnings))
    if warnings:
        return AuditStatus.WARNING, [], sorted(set(warnings))
    return AuditStatus.PASS, [], []

def build_release_audit(project_root: Path | str, *, mode: str = "development", target_version: str = "v11-governance", governance_root: Path | str | None = None, test_results: Mapping[str, Any] | None = None, replay_results: Mapping[str, Any] | None = None, smoke_results: Mapping[str, Any] | None = None, created_at: datetime | None = None) -> AuditRecord:
    root = Path(project_root).expanduser().resolve(strict=True)
    timestamp = _aware_utc(created_at)
    governance = Path(governance_root) if governance_root is not None else root / "data" / "governance"
    worktree = git_worktree_state(root)
    changed_files = list(worktree.get("changed_files", []))
    sensitive = sensitive_file_check(changed_files)
    integrity = governance_data_integrity(governance)
    tests = _normalise_summary(test_results, default_status="not_run")
    replay = _normalise_summary(replay_results, default_status="not_run")
    smoke = _normalise_summary(smoke_results, default_status="not_run")
    external_calls = {"glm": False, "prometheus": False, "device": False, "notification": False, "production_write": False}
    status, problems, warnings = determine_audit_status(worktree=worktree, sensitive=sensitive, governance_integrity=integrity, test_results=tests, replay_results=replay, smoke_results=smoke)
    commit = str(worktree.get("commit") or "0" * 40)
    return AuditRecord(
        audit_id=_audit_id(commit, mode, timestamp, changed_files),
        target_version=target_version,
        branch=str(worktree.get("branch") or "unknown"),
        commit=commit,
        created_at=timestamp,
        worktree={"mode": mode, "dirty": bool(worktree.get("dirty", False)), "status_short": list(worktree.get("status_short", [])), "staged": list(worktree.get("staged", [])), "unstaged": list(worktree.get("unstaged", [])), "untracked": list(worktree.get("untracked", [])), "git_available": bool(worktree.get("available", False))},
        changed_files=changed_files,
        test_results=tests,
        replay_results=replay,
        smoke_results=smoke,
        sensitive_file_check=sensitive,
        external_calls=external_calls,
        governance_data_integrity=integrity,
        status=status,
        problems=problems,
        warnings=warnings,
    )

def audit_safety_summary(audit: AuditRecord | Mapping[str, Any]) -> dict[str, Any]:
    record = audit if isinstance(audit, AuditRecord) else AuditRecord.model_validate(dict(audit))
    enabled_calls = sorted(key for key, value in record.external_calls.items() if bool(value))
    return {"safe": not enabled_calls and not bool(record.external_calls.get("production_write", False)), "status": record.status.value, "enabled_external_calls": enabled_calls, "production_write": bool(record.external_calls.get("production_write", False)), "problem_count": len(record.problems), "warning_count": len(record.warnings), "schema_version": GOVERNANCE_SCHEMA_VERSION, "release_audit_version": RELEASE_AUDIT_VERSION}

__all__ = ["RELEASE_AUDIT_VERSION", "ReleaseAuditError", "audit_safety_summary", "build_release_audit", "determine_audit_status", "git_worktree_state", "governance_data_integrity", "sensitive_file_check"]
