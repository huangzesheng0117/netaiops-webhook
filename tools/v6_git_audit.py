#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any


STAGE = "v6.6"

FORBIDDEN_PATH_PREFIXES = [
    "data/",
    "logs/",
    "backup/",
    "venv/",
    ".venv/",
    "__pycache__/",
]

FORBIDDEN_EXACT_PATHS = [
    "config.yaml",
    ".env",
    "secrets.yaml",
    "device_inventory.yaml",
    "device_inventory.normalized.yaml",
]

FORBIDDEN_SUFFIXES = [
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".crt",
    ".csr",
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".ucs",
    ".sqlite",
    ".db",
]

SENSITIVE_KEYWORDS = [
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "authorization",
    "bearer ",
    "webhook_secret",
    "webhook_token",
    "webhook_key",
    "webhook_url",
    "mcp_server_url",
    "prometheus_base_url",
]

EXPECTED_V6_TOP_LEVELS = [
    "app.py",
    "README_STATUS.md",
    "docs/",
    "netaiops/",
    "skills/",
    "tests/",
    "tools/",
]


def run_cmd(cmd: list[str], cwd: Path) -> dict[str, Any]:
    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )
        return {
            "cmd": cmd,
            "returncode": p.returncode,
            "stdout": p.stdout,
            "stderr": p.stderr,
        }
    except Exception as exc:
        return {
            "cmd": cmd,
            "returncode": 999,
            "stdout": "",
            "stderr": str(exc),
        }


def parse_git_status_porcelain(text: str) -> list[dict[str, str]]:
    result = []

    for raw in text.splitlines():
        if not raw.strip():
            continue

        status = raw[:2].strip()
        path = raw[3:].strip() if len(raw) >= 4 else raw.strip()

        if " -> " in path:
            old, new = path.split(" -> ", 1)
            path = new.strip()

        result.append({
            "status": status,
            "path": path,
        })

    return result


def is_forbidden_path(path: str) -> bool:
    p = path.strip().replace("\\", "/")
    lower = p.lower()

    if lower in FORBIDDEN_EXACT_PATHS:
        return True

    for prefix in FORBIDDEN_PATH_PREFIXES:
        if lower.startswith(prefix):
            return True

    for suffix in FORBIDDEN_SUFFIXES:
        if lower.endswith(suffix):
            return True

    return False


def classify_changed_path(path: str) -> str:
    p = path.strip().replace("\\", "/")

    for prefix in EXPECTED_V6_TOP_LEVELS:
        if prefix.endswith("/"):
            if p.startswith(prefix):
                return prefix.rstrip("/")
        else:
            if p == prefix:
                return prefix

    return "other"


def load_ignore_text(base: Path) -> str:
    p = base / ".gitignore"
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="ignore")


def check_gitignore(ignore_text: str) -> dict[str, Any]:
    expected = [
        "config.yaml",
        "data/",
        "logs/",
        "backup/",
        "venv/",
    ]

    missing = []
    for item in expected:
        if item not in ignore_text:
            missing.append(item)

    return {
        "expected": expected,
        "missing": missing,
        "ok": len(missing) == 0,
    }


def scan_diff_for_sensitive_keywords(diff_text: str) -> list[dict[str, Any]]:
    hits = []

    for lineno, line in enumerate(diff_text.splitlines(), start=1):
        if not line.startswith("+") or line.startswith("+++"):
            continue

        low = line.lower()

        for keyword in SENSITIVE_KEYWORDS:
            if keyword in low:
                hits.append({
                    "line": lineno,
                    "keyword": keyword,
                    "sample": line[:180],
                })
                break

    return hits


def build_git_audit_report(
    base_dir: str | Path = ".",
    include_diff_scan: bool = True,
) -> dict[str, Any]:
    base = Path(base_dir).resolve()
    violations = []
    warnings = []

    status_result = run_cmd(["git", "status", "--porcelain"], base)
    status_items = parse_git_status_porcelain(status_result.get("stdout", ""))

    changed_paths = [item["path"] for item in status_items]
    forbidden_changed = [p for p in changed_paths if is_forbidden_path(p)]

    for path in forbidden_changed:
        violations.append(f"forbidden path appears in git status: {path}")

    classified: dict[str, list[str]] = {}
    for path in changed_paths:
        group = classify_changed_path(path)
        classified.setdefault(group, []).append(path)

    other_paths = classified.get("other", [])
    if other_paths:
        warnings.append("changed paths outside common v6 groups: " + ",".join(other_paths))

    ignore_text = load_ignore_text(base)
    ignore_check = check_gitignore(ignore_text)
    if not ignore_check["ok"]:
        warnings.append(".gitignore may miss runtime/sensitive entries: " + ",".join(ignore_check["missing"]))

    sensitive_hits = []
    if include_diff_scan:
        diff_result = run_cmd(["git", "diff", "--", "."], base)
        sensitive_hits = scan_diff_for_sensitive_keywords(diff_result.get("stdout", ""))

        filtered_hits = []
        for hit in sensitive_hits:
            sample_low = hit["sample"].lower()
            benign = (
                "forbidden_patterns" in sample_low
                or "sensitive" in sample_low
                or "/opt/netaiops-webhook" in sample_low
                or "netaiops-webhook" in sample_low
                or "webhook 平台" in sample_low
                or "secret" in sample_low and "do not" in sample_low
                or "secret" in sample_low and "不得提交" in sample_low
                or "secret" in sample_low and "不要" in sample_low
                or "password" in sample_low and "不要" in sample_low
                or "password" in sample_low and "不得提交" in sample_low
                or "password" in sample_low and "sensitive" in sample_low
            )
            if not benign:
                filtered_hits.append(hit)

        sensitive_hits = filtered_hits

        if sensitive_hits:
            violations.append("possible sensitive keyword found in git diff")

    return {
        "verdict": "fail" if violations else "pass",
        "stage": STAGE,
        "purpose": "git diff and commit readiness audit",
        "base_dir": str(base),
        "violations": violations,
        "warnings": warnings,
        "git_status_count": len(status_items),
        "git_status": status_items,
        "classified_paths": classified,
        "forbidden_changed_paths": forbidden_changed,
        "gitignore_check": ignore_check,
        "sensitive_keyword_hits": sensitive_hits,
        "commit_recommendation": {
            "ready_for_commit": len(violations) == 0,
            "commit_now": False,
            "reason": "v6.6 still in release audit stage; commit after final confirmation.",
            "suggested_commit_message": "feat: complete NetAIOps webhook v6 investigation, parser, skill and adaptive dry-run framework",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="NetAIOps v6.6 Git diff and sensitive-file audit.")
    parser.add_argument("--base-dir", default="/opt/netaiops-webhook")
    parser.add_argument("--write", default="")
    parser.add_argument("--skip-diff-scan", action="store_true")
    args = parser.parse_args()

    report = build_git_audit_report(
        base_dir=args.base_dir,
        include_diff_scan=not args.skip_diff_scan,
    )

    print(json.dumps(report, ensure_ascii=False, indent=2))

    if args.write:
        out = Path(args.write)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    return 0 if report.get("verdict") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
