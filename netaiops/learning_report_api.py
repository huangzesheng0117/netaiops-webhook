"""v7.6 Learning Report API helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from netaiops.learning_report import (
    build_learning_report,
    get_report,
    latest_report,
    list_learning_reports,
    validate_report_safety,
)


def build_learning_report_response(base_dir: Path) -> Dict[str, Any]:
    report = build_learning_report(base_dir=base_dir, write=True)
    return {
        "status": "ok",
        "stage": "v7.6_learning_report",
        "safety_check": validate_report_safety(report),
        "report": report,
    }


def latest_learning_report_response(base_dir: Path, rebuild: bool = False) -> Dict[str, Any]:
    report = build_learning_report(base_dir=base_dir, write=True) if rebuild else latest_report(base_dir)
    if not report:
        report = build_learning_report(base_dir=base_dir, write=True)

    full = get_report(report.get("report_id"), base_dir=base_dir) or report

    return {
        "status": "ok",
        "stage": "v7.6_learning_report",
        "safety_check": validate_report_safety(full),
        "report": full,
    }


def list_learning_reports_response(base_dir: Path, limit: int = 20) -> Dict[str, Any]:
    rows = list_learning_reports(base_dir=base_dir, limit=limit)
    return {
        "status": "ok",
        "stage": "v7.6_learning_report",
        "report_count": len(rows),
        "reports": rows,
    }


def learning_report_detail_response(report_id: str, base_dir: Path) -> Dict[str, Any]:
    report = get_report(report_id, base_dir=base_dir)
    if not report:
        raise FileNotFoundError(f"learning report not found: {report_id}")

    return {
        "status": "ok",
        "stage": "v7.6_learning_report_detail",
        "report_id": report_id,
        "safety_check": validate_report_safety(report),
        "report": report,
    }
