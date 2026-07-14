#!/usr/bin/env python3
"""NetAIOps Webhook v11 final release acceptance and strict zero-failure gate.

Modes
-----
offline
    Validate one historical request through the deterministic Governance sidecar
    and offline Replay without real external calls or production writes.

repository-gate
    Run the Batch 10 focused tests, all v11 tests, and the full repository
    unittest suite. The full suite is accepted only when it exits successfully
    with zero FAIL/ERROR identities. The resulting release audit must be PASS.
"""
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

PROJECT_IMPORT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_IMPORT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_IMPORT_ROOT))

from netaiops.governance.contracts import AuditStatus  # noqa: E402
from netaiops.governance.integration import build_governance_artifacts_safe  # noqa: E402
from netaiops.governance.release_audit import build_release_audit  # noqa: E402
from netaiops.governance.replay_engine import (  # noqa: E402
    replay_safety_summary,
    run_offline_replay,
)
from netaiops.governance.schemas import AuditRecord  # noqa: E402

ACCEPTANCE_VERSION = "11.1.0-release-acceptance-v2"
EXPECTED_SERVICE_VERSION = "11.0.0-v11-learning-governance"
KNOWN_FAILURE_POLICY = "strict-zero-regressions-v2"
RESOLVED_HISTORICAL_FAILURE_POLICY = "frozen-historical-regressions-v1"
RESOLVED_HISTORICAL_FAILURE_COUNT = 28
KNOWN_HISTORICAL_FAILURES: tuple[str, ...] = ()

_FAILURE_HEADER_RE = re.compile(r"^(FAIL|ERROR):\s+(.+?)\s*$")
_RAN_RE = re.compile(r"^Ran\s+(\d+)\s+tests?\s+in\s+(.+)$")
_FAILED_RE = re.compile(r"^FAILED\s+\((.+)\)$")


class ReleaseAcceptanceError(RuntimeError):
    """Raised when an acceptance gate cannot be completed safely."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(dict(payload), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )


def parse_unittest_output(text: str) -> dict[str, Any]:
    failures: list[str] = []
    ran: dict[str, Any] | None = None
    failed_summary = ""
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        header = _FAILURE_HEADER_RE.match(line)
        if header:
            failures.append(f"{header.group(1)}: {header.group(2)}")
        ran_match = _RAN_RE.match(line.strip())
        if ran_match:
            ran = {
                "count": int(ran_match.group(1)),
                "duration": ran_match.group(2),
            }
        failed_match = _FAILED_RE.match(line.strip())
        if failed_match:
            failed_summary = failed_match.group(1)
    return {
        "failures": sorted(set(failures)),
        "failure_count": len(set(failures)),
        "ran": ran,
        "failed_summary": failed_summary,
    }


def compare_failure_set(
    observed: Sequence[str],
    expected: Sequence[str] = KNOWN_HISTORICAL_FAILURES,
) -> dict[str, Any]:
    observed_set = set(observed)
    expected_set = set(expected)
    new = sorted(observed_set - expected_set)
    missing = sorted(expected_set - observed_set)
    common = sorted(observed_set & expected_set)
    return {
        "policy": KNOWN_FAILURE_POLICY,
        "expected_count": len(expected_set),
        "observed_count": len(observed_set),
        "common_count": len(common),
        "new_failure_count": len(new),
        "missing_failure_count": len(missing),
        "exact_match": observed_set == expected_set,
        "new_failures": new,
        "missing_failures": missing,
        "common_failures": common,
    }


def _run_command(
    args: Sequence[str],
    *,
    cwd: Path,
    log_path: Path,
) -> dict[str, Any]:
    env = os.environ.copy()
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
    parsed = parse_unittest_output(completed.stdout)
    return {
        "args": list(args),
        "returncode": completed.returncode,
        "log": str(log_path),
        **parsed,
    }


def _assert_zero_external_calls(
    values: Mapping[str, Any],
    *,
    context: str,
) -> None:
    enabled = sorted(key for key, value in values.items() if bool(value))
    if enabled:
        raise ReleaseAcceptanceError(
            f"{context} unexpectedly enabled external calls: {enabled}"
        )


def run_offline_acceptance(
    *,
    project_root: Path,
    request_id: str,
    output_dir: Path,
    no_notify: bool,
    no_real_glm: bool,
    no_real_prometheus: bool,
    no_real_device: bool,
) -> dict[str, Any]:
    if not all((no_notify, no_real_glm, no_real_prometheus, no_real_device)):
        raise ReleaseAcceptanceError(
            "offline mode requires --no-notify, --no-real-glm, "
            "--no-real-prometheus and --no-real-device"
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    governance_root = output_dir / "governance"
    sidecar = build_governance_artifacts_safe(
        request_id,
        project_root=project_root,
        governance_root=governance_root,
        include_signals=True,
        include_proposals=True,
        write=True,
        force=False,
    )
    if sidecar.get("ok") is not True:
        raise ReleaseAcceptanceError(
            f"governance sidecar failed: {sidecar}"
        )
    _assert_zero_external_calls(
        sidecar.get("external_calls") or {},
        context="governance sidecar",
    )

    replay = run_offline_replay(str(project_root), request_id)
    replay_safety = replay_safety_summary(replay)
    if replay_safety.get("safe") is not True:
        raise ReleaseAcceptanceError(
            f"offline replay safety failed: {replay_safety}"
        )
    _assert_zero_external_calls(
        replay.record.external_calls,
        context="offline replay",
    )

    report = {
        "acceptance_version": ACCEPTANCE_VERSION,
        "mode": "offline",
        "overall_status": "PASS",
        "request_id": request_id,
        "governance_sidecar": sidecar,
        "replay": replay.summary(),
        "replay_safety": replay_safety,
        "problems": [],
        "warnings": list(replay.record.warnings),
        "external_calls": {
            "glm": False,
            "prometheus": False,
            "device": False,
            "notification": False,
            "production_write": False,
        },
        "created_at": utc_now().isoformat(),
    }
    _write_json(output_dir / "v11_acceptance_report.json", report)
    return report


def _final_pass_audit(
    *,
    project_root: Path,
    test_results: Mapping[str, Any],
    replay_results: Mapping[str, Any],
    smoke_results: Mapping[str, Any],
) -> AuditRecord:
    audit = build_release_audit(
        project_root,
        mode="release",
        target_version=EXPECTED_SERVICE_VERSION,
        test_results=test_results,
        replay_results=replay_results,
        smoke_results=smoke_results,
    )
    if audit.status is not AuditStatus.PASS:
        raise ReleaseAcceptanceError(
            "final release audit must be PASS: "
            f"status={audit.status.value}, "
            f"problems={audit.problems}, warnings={audit.warnings}"
        )
    if audit.problems or audit.warnings:
        raise ReleaseAcceptanceError(
            "final release audit must have no problems or warnings: "
            f"problems={audit.problems}, warnings={audit.warnings}"
        )
    _assert_zero_external_calls(
        audit.external_calls,
        context="final release audit",
    )
    return audit


def run_repository_gate(
    *,
    project_root: Path,
    output_dir: Path,
    expected_version: str,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    version = (project_root / "VERSION").read_text(
        encoding="utf-8"
    ).strip()
    if version != expected_version:
        raise ReleaseAcceptanceError(
            f"VERSION mismatch: expected {expected_version!r}, "
            f"got {version!r}"
        )

    python = sys.executable
    focused = _run_command(
        [
            python,
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-p",
            "test_v11_governance_integration.py",
            "-v",
        ],
        cwd=project_root,
        log_path=output_dir / "batch10_integration_tests.log",
    )
    if focused["returncode"] != 0 or focused["failure_count"] != 0:
        raise ReleaseAcceptanceError(
            f"Batch 10 integration validation failed: {focused}"
        )

    v11 = _run_command(
        [
            python,
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-p",
            "test_v11_*.py",
            "-v",
        ],
        cwd=project_root,
        log_path=output_dir / "v11_tests.log",
    )
    if v11["returncode"] != 0 or v11["failure_count"] != 0:
        raise ReleaseAcceptanceError(f"v11 tests failed: {v11}")

    full = _run_command(
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
    failure_gate = compare_failure_set(full["failures"])
    if full["returncode"] != 0 or full["failure_count"] != 0:
        raise ReleaseAcceptanceError(
            "full repository tests must pass with zero FAIL/ERROR: "
            f"returncode={full['returncode']}, "
            f"failure_gate={failure_gate}"
        )
    if failure_gate["exact_match"] is not True:
        raise ReleaseAcceptanceError(
            "strict zero-failure gate mismatch: "
            f"{failure_gate}"
        )

    test_results = {
        "status": "passed",
        "v11": v11,
        "batch10_integration": focused,
        "full_repository": {
            **full,
            "strict_zero_failure_gate": True,
        },
        "known_failure_gate": failure_gate,
    }
    replay_results = {
        "status": "passed",
        "mode": "offline",
        "safety_regression": False,
        "reason": (
            "three deterministic offline fixture acceptances are "
            "executed by the master runner"
        ),
    }
    smoke_results = {
        "status": "not_run",
        "reason": (
            "no real GLM/MCP/notification smoke is required by the "
            "deterministic final repository gate"
        ),
    }
    audit = _final_pass_audit(
        project_root=project_root,
        test_results=test_results,
        replay_results=replay_results,
        smoke_results=smoke_results,
    )
    audit_payload = audit.to_payload()
    _write_json(output_dir / "v11_release_audit.json", audit_payload)

    report = {
        "acceptance_version": ACCEPTANCE_VERSION,
        "mode": "repository-gate",
        "overall_status": "PASS",
        "release_audit_status": "pass",
        "version": version,
        "batch10_integration_validation": focused,
        "v11_test_validation": v11,
        "full_repository_validation": full,
        "known_failure_gate": failure_gate,
        "known_historical_failure_count": 0,
        "resolved_historical_failure_count": (
            RESOLVED_HISTORICAL_FAILURE_COUNT
        ),
        "new_failure_count": 0,
        "problems": [],
        "warnings": [],
        "notes": [
            (
                "28 historical regressions were cleared by "
                "v11.1 Batches B-D"
            ),
            (
                "real external smokes remain outside this deterministic "
                "release gate"
            ),
        ],
        "external_calls": {
            "glm": False,
            "prometheus": False,
            "device": False,
            "notification": False,
            "production_write": False,
        },
        "release_audit_file": str(
            output_dir / "v11_release_audit.json"
        ),
        "created_at": utc_now().isoformat(),
    }
    _write_json(output_dir / "v11_acceptance_report.json", report)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", required=True)
    parser.add_argument(
        "--mode",
        choices=("offline", "repository-gate"),
        required=True,
    )
    parser.add_argument("--baseline-request-id")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument(
        "--expected-version",
        default=EXPECTED_SERVICE_VERSION,
    )
    parser.add_argument(
        "--known-failure-policy",
        choices=(KNOWN_FAILURE_POLICY,),
        default=KNOWN_FAILURE_POLICY,
    )
    parser.add_argument("--no-notify", action="store_true")
    parser.add_argument("--no-real-glm", action="store_true")
    parser.add_argument("--no-real-prometheus", action="store_true")
    parser.add_argument("--no-real-device", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    project_root = Path(args.project_root).expanduser().resolve(strict=True)
    output_dir = Path(args.output_dir).expanduser().resolve(strict=False)

    if args.mode == "offline":
        if not args.baseline_request_id:
            raise ReleaseAcceptanceError(
                "--baseline-request-id is required in offline mode"
            )
        report = run_offline_acceptance(
            project_root=project_root,
            request_id=args.baseline_request_id,
            output_dir=output_dir,
            no_notify=args.no_notify,
            no_real_glm=args.no_real_glm,
            no_real_prometheus=args.no_real_prometheus,
            no_real_device=args.no_real_device,
        )
    else:
        report = run_repository_gate(
            project_root=project_root,
            output_dir=output_dir,
            expected_version=args.expected_version,
        )

    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
