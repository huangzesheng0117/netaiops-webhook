"""v7.7 Release Audit API helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from netaiops.v7_release_audit import audit_v7_release


def v7_release_audit_response(base_dir: Path, write: bool = False) -> Dict[str, Any]:
    report = audit_v7_release(base_dir=base_dir, write=write)
    return {
        "status": "ok" if report.get("verdict") == "pass" else "failed",
        "stage": "v7.7_release_audit",
        "verdict": report.get("verdict"),
        "violation_count": len(report.get("violations") or []),
        "warning_count": len(report.get("warnings") or []),
        "report": report,
    }
