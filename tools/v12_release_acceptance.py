#!/usr/bin/env python3
"""NetAIOps Webhook v12 final Release Acceptance and post-commit audit."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import yaml

PROJECT_IMPORT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_IMPORT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_IMPORT_ROOT))

from netaiops.v12.primary_release import (  # noqa: E402
    APPROVED_FAMILIES,
    PRIMARY_SCHEMA_VERSION,
    load_primary_settings,
)

ACCEPTANCE_VERSION = "12.0.0-release-acceptance-2"
EXPECTED_SERVICE_VERSION = "12.0.0-v12-controlled-multi-agent"
EXPECTED_COMMIT_MESSAGE = "v12: release controlled multi-agent RCA"
_FAILURE_HEADER_RE = re.compile(r"^(FAIL|ERROR):\s+(.+?)\s*$")
_RAN_RE = re.compile(r"^Ran\s+(\d+)\s+tests?\s+in\s+(.+)$")


class V12ReleaseAcceptanceError(RuntimeError):
    """Raised when the frozen v12 release contract is violated."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(dict(payload), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )


def run_command(
    args: Sequence[str],
    *,
    cwd: Path,
    log_path: Path,
) -> dict[str, Any]:
    env = os.environ.copy()
    for variable in (
        "CONFIRM_COMMIT",
        "CONFIRM_PUSH",
        "CONFIRM_ROLLBACK",
        "CONFIRM_REPREPARE",
    ):
        env.pop(variable, None)
    env.update(
        {
            "PROJECT_ROOT": str(cwd),
            "PYTHONPATH": str(cwd),
            "PYTHONDONTWRITEBYTECODE": "1",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    completed = subprocess.run(
        list(args),
        cwd=str(cwd),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(completed.stdout, encoding="utf-8")
    failures: list[str] = []
    ran: dict[str, Any] | None = None
    for raw_line in completed.stdout.splitlines():
        line = raw_line.rstrip()
        match = _FAILURE_HEADER_RE.match(line)
        if match:
            failures.append(f"{match.group(1)}: {match.group(2)}")
        ran_match = _RAN_RE.match(line.strip())
        if ran_match:
            ran = {
                "count": int(ran_match.group(1)),
                "duration": ran_match.group(2),
            }
    return {
        "args": list(args),
        "returncode": completed.returncode,
        "log": str(log_path),
        "ran": ran,
        "failures": sorted(set(failures)),
        "failure_count": len(set(failures)),
    }


def git_output(project_root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=str(project_root),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise V12ReleaseAcceptanceError(
            f"git {' '.join(args)} failed: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def http_probe(base_url: str, path: str) -> dict[str, Any]:
    url = base_url.rstrip("/") + path
    request = Request(url, headers={"Accept": "application/json,text/html"})
    started = utc_now()
    try:
        with urlopen(request, timeout=8) as response:
            body = response.read(4096)
            code = int(response.status)
            content_type = str(response.headers.get("Content-Type") or "")
    except HTTPError as exc:
        code = int(exc.code)
        body = exc.read(4096)
        content_type = str(exc.headers.get("Content-Type") or "")
    except (URLError, OSError) as exc:
        return {
            "path": path,
            "url": url,
            "code": 0,
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
    return {
        "path": path,
        "url": url,
        "code": code,
        "ok": code == 200,
        "content_type": content_type,
        "body_bytes_sampled": len(body),
        "checked_at": started.isoformat(),
    }


def runtime_contract(
    project_root: Path,
    runtime_config: Path,
) -> dict[str, Any]:
    version = (project_root / "VERSION").read_text(encoding="utf-8").strip()
    if version != EXPECTED_SERVICE_VERSION:
        raise V12ReleaseAcceptanceError(
            f"VERSION mismatch: expected {EXPECTED_SERVICE_VERSION}, got {version}"
        )
    settings = load_primary_settings(runtime_config)
    if settings is None:
        raise V12ReleaseAcceptanceError("v12 primary runtime config is missing")
    if settings.enabled is not True or settings.mode != "primary":
        raise V12ReleaseAcceptanceError("v12 primary runtime is not enabled")
    settings.validate_frozen_boundary()
    if tuple(settings.allowed_families) != APPROVED_FAMILIES:
        raise V12ReleaseAcceptanceError(
            "runtime approved family set differs from frozen release set"
        )

    app_text = (project_root / "app.py").read_text(encoding="utf-8")
    primary_token = "run_v12_primary_after_legacy_safe,"
    legacy_notify = "notify_result = send_notification(request_id)"
    if primary_token not in app_text:
        raise V12ReleaseAcceptanceError("app.py does not schedule v12 primary")
    if app_text.find(primary_token) <= app_text.find(legacy_notify):
        raise V12ReleaseAcceptanceError(
            "v12 primary must run only after legacy-compatible delivery"
        )
    if "run_p1_after_legacy_safe," in app_text:
        raise V12ReleaseAcceptanceError(
            "production app still schedules the P1 shadow entry"
        )
    if "config/v12_primary.yaml" not in (
        project_root / ".gitignore"
    ).read_text(encoding="utf-8"):
        raise V12ReleaseAcceptanceError(
            "v12 primary runtime config is not gitignored"
        )
    example = yaml.safe_load(
        (project_root / "config.example.yaml").read_text(encoding="utf-8")
    )
    example_v12 = example["v12_multi_agent"]
    if (
        example_v12.get("enabled") is not False
        or example_v12.get("mode") != "shadow"
        or example_v12.get("rca", {}).get("enabled") is not False
    ):
        raise V12ReleaseAcceptanceError(
            "config.example.yaml must retain safe v12 defaults"
        )
    return {
        "version": version,
        "schema_version": settings.schema_version,
        "activation_id": settings.activation_id,
        "enabled": settings.enabled,
        "mode": settings.mode,
        "fail_open_to_legacy": settings.fail_open_to_legacy,
        "notifications_use_v12": settings.notifications_use_v12,
        "logs_enabled": settings.logs_enabled,
        "knowledge_enabled": settings.knowledge_enabled,
        "allowed_families": list(settings.allowed_families),
        "external_call_budget": {
            "prometheus_mcp": settings.max_metrics_calls_per_request,
            "netmiko_mcp": settings.max_device_calls_per_request,
            "glm_rca": settings.max_rca_calls_per_request,
            "total": settings.max_total_external_calls_per_request,
        },
    }


def write_release_markdown(
    path: Path,
    *,
    report: Mapping[str, Any],
) -> None:
    tests = report["tests"]
    runtime = report["runtime"]
    health = report["health"]
    lines = [
        "# NetAIOps Webhook v12 Release Audit",
        "",
        f"> 生成时间：{report['created_at']}",
        f"> Release Audit：{report['release_audit_status'].upper()}",
        "",
        "## 发布基线",
        "",
        "```text",
        f"version={runtime['version']}",
        f"mode={runtime['mode']}",
        f"fail_open_to_legacy={str(runtime['fail_open_to_legacy']).lower()}",
        f"notifications_use_v12={str(runtime['notifications_use_v12']).lower()}",
        f"logs_enabled={str(runtime['logs_enabled']).lower()}",
        f"knowledge_enabled={str(runtime['knowledge_enabled']).lower()}",
        "```",
        "",
        "## Primary Family",
        "",
        "```text",
        *runtime["allowed_families"],
        "```",
        "",
        "其他 Family 固定 fallback legacy。",
        "",
        "## 测试",
        "",
        "```text",
        f"all_v12_tests={tests['all_v12']['ran']['count']}",
        f"all_v12_returncode={tests['all_v12']['returncode']}",
        f"full_repository_tests={tests['full_repository']['ran']['count']}",
        f"full_repository_returncode={tests['full_repository']['returncode']}",
        "historical_failures=0",
        "new_failures=0",
        "```",
        "",
        "## 运行时入口",
        "",
        "```text",
    ]
    for item in health:
        lines.append(f"{item['path']}={item['code']}")
    lines.extend(
        [
            "```",
            "",
            "## 外部调用与通知边界",
            "",
            "```text",
            "Release Audit synthetic GLM calls=0",
            "Release Audit synthetic Prometheus MCP calls=0",
            "Release Audit synthetic Netmiko MCP calls=0",
            "Release Audit synthetic notifications=0",
            "Evidence MCP calls=0",
            "OPS ES API calls=0",
            "Analytics MCP calls=0",
            "FastMCP calls=0",
            "",
            "Approved primary request budget:",
            "Prometheus MCP<=1",
            "Netmiko MCP<=1",
            "GLM RCA<=1",
            "v12 notification=0",
            "```",
            "",
            "## 审计结果",
            "",
            "```text",
            f"problems={json.dumps(report['problems'], ensure_ascii=False)}",
            f"warnings={json.dumps(report['warnings'], ensure_ascii=False)}",
            "release_audit=PASS",
            "```",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def run_acceptance(
    *,
    project_root: Path,
    runtime_config: Path,
    output_dir: Path,
    base_url: str,
    post_commit: bool,
    write_markdown: bool,
    skip_health: bool,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    runtime = runtime_contract(project_root, runtime_config)
    python = sys.executable

    all_v12 = run_command(
        [
            python,
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-p",
            "test_v12_*.py",
            "-v",
        ],
        cwd=project_root,
        log_path=output_dir / "all_v12_tests.log",
    )
    if (
        all_v12["returncode"] != 0
        or all_v12["failure_count"] != 0
        or not all_v12["ran"]
    ):
        raise V12ReleaseAcceptanceError(f"all v12 tests failed: {all_v12}")

    full = run_command(
        [
            python,
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-v",
        ],
        cwd=project_root,
        log_path=output_dir / "full_repository_tests.log",
    )
    if full["returncode"] != 0 or full["failure_count"] != 0 or not full["ran"]:
        raise V12ReleaseAcceptanceError(
            f"full repository tests failed: {full}"
        )

    diff_check = subprocess.run(
        ["git", "diff", "--check"],
        cwd=str(project_root),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if diff_check.returncode != 0 or diff_check.stdout.strip():
        raise V12ReleaseAcceptanceError(
            "git diff --check failed: " + diff_check.stdout.strip()
        )

    paths = (
        "/health",
        "/evidence?limit=1",
        "/evidence-ui",
        "/governance/health",
        "/governance-ui",
        "/agent/health",
        "/agent-ui",
    )
    health = [] if skip_health else [http_probe(base_url, path) for path in paths]
    failed_health = [item for item in health if item.get("ok") is not True]
    if failed_health:
        raise V12ReleaseAcceptanceError(
            "runtime endpoint acceptance failed: "
            + json.dumps(failed_health, ensure_ascii=False)
        )

    git_state = {
        "branch": git_output(project_root, "rev-parse", "--abbrev-ref", "HEAD"),
        "head": git_output(project_root, "rev-parse", "HEAD"),
        "origin_main": git_output(project_root, "rev-parse", "origin/main"),
        "worktree_status": git_output(
            project_root,
            "status",
            "--short",
            "--untracked-files=all",
        ),
    }
    if git_state["branch"] != "main":
        raise V12ReleaseAcceptanceError("release branch must be main")
    if post_commit:
        if git_state["worktree_status"]:
            raise V12ReleaseAcceptanceError(
                "post-commit Release Audit requires a clean worktree"
            )
        if git_state["head"] != git_state["origin_main"]:
            raise V12ReleaseAcceptanceError(
                "post-commit Release Audit requires HEAD=origin/main"
            )
        subject = git_output(project_root, "log", "-1", "--pretty=%s")
        if subject != EXPECTED_COMMIT_MESSAGE:
            raise V12ReleaseAcceptanceError(
                f"release commit subject mismatch: {subject}"
            )
        git_state["subject"] = subject

    report: dict[str, Any] = {
        "acceptance_version": ACCEPTANCE_VERSION,
        "mode": (
            "post-commit"
            if post_commit
            else "pre-activation" if skip_health else "pre-commit"
        ),
        "overall_status": "PASS",
        "release_audit_status": "pass",
        "runtime": runtime,
        "tests": {
            "all_v12": all_v12,
            "full_repository": full,
            "historical_failures": 0,
            "new_failures": 0,
        },
        "health": health,
        "git": git_state,
        "problems": [],
        "warnings": [],
        "external_calls": {
            "glm": False,
            "prometheus_mcp": False,
            "netmiko_mcp": False,
            "notification": False,
            "evidence_mcp": False,
            "ops_es_api": False,
            "analytics_mcp": False,
            "fastmcp": False,
        },
        "created_at": utc_now().isoformat(),
    }
    write_json(output_dir / "v12_release_acceptance.json", report)
    write_json(output_dir / "v12_release_audit.json", report)
    if write_markdown:
        write_release_markdown(
            project_root / "docs" / "V12_RELEASE_AUDIT_2026-08-04.md",
            report=report,
        )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", default="/opt/netaiops-webhook")
    parser.add_argument(
        "--runtime-config",
        default="/opt/netaiops-webhook/config/v12_primary.yaml",
    )
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    parser.add_argument("--post-commit", action="store_true")
    parser.add_argument("--write-markdown", action="store_true")
    parser.add_argument("--skip-health", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    run_acceptance(
        project_root=Path(args.project_root).resolve(strict=True),
        runtime_config=Path(args.runtime_config).resolve(strict=True),
        output_dir=Path(args.output_dir).resolve(strict=False),
        base_url=args.base_url,
        post_commit=args.post_commit,
        write_markdown=args.write_markdown,
        skip_health=args.skip_health,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
