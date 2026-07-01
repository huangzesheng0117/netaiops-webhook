#!/usr/bin/env python3
"""Representative historical regression checks for Evidence Hub.

This tool validates that selected historical request_ids have usable Evidence Hub
artifacts, API responses, UI pages, and slim notification summaries. It is read-only
for source data. Reports are written under data/evidence_hub/regression by default.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

DEFAULT_MIN_FILES = ("summary.json", "meta.json")
RECOMMENDED_FILES = (
    "alert_context.json",
    "normalized_event.json",
    "analysis_result.json",
    "plan.json",
    "metrics_evidence.json",
    "device_evidence.json",
    "review.json",
    "notification_summary.json",
    "summary.json",
    "meta.json",
)
SENSITIVE_KEYWORDS = (
    "token",
    "secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
)


@dataclass
class HttpProbeResult:
    path: str
    ok: bool
    status_code: Optional[int] = None
    error: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "ok": self.ok,
            "status_code": self.status_code,
            "error": self.error,
        }


@dataclass
class CaseResult:
    request_id: str
    status: str = "pass"
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    files_present: List[str] = field(default_factory=list)
    files_missing: List[str] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    meta: Dict[str, Any] = field(default_factory=dict)
    detail_url: str = ""
    http_probes: List[HttpProbeResult] = field(default_factory=list)

    def add_error(self, message: str) -> None:
        self.errors.append(message)
        self.status = "fail"

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)
        if self.status == "pass":
            self.status = "warning"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "status": self.status,
            "errors": self.errors,
            "warnings": self.warnings,
            "files_present": self.files_present,
            "files_missing": self.files_missing,
            "summary": self.summary,
            "meta": self.meta,
            "detail_url": self.detail_url,
            "http_probes": [p.as_dict() for p in self.http_probes],
        }


def _utc_now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _safe_read_json(path: Path) -> Tuple[Optional[Dict[str, Any]], str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, "missing"
    except Exception as exc:
        return None, f"read_error: {exc}"
    if isinstance(value, dict):
        return value, ""
    return {"_value": value}, ""


def _request_base(data_root: Path) -> Path:
    return data_root / "evidence_hub" / "requests"


def _request_dir(data_root: Path, request_id: str) -> Path:
    return _request_base(data_root) / request_id


def list_existing_request_ids(data_root: Path) -> List[str]:
    base = _request_base(data_root)
    if not base.is_dir():
        return []
    ids = [p.name for p in base.iterdir() if p.is_dir()]
    return sorted(ids, reverse=True)


def select_latest_request_ids(data_root: Path, limit: int) -> List[str]:
    if limit <= 0:
        return []
    return list_existing_request_ids(data_root)[:limit]


def _dig_first(mapping: Dict[str, Any], paths: Sequence[Sequence[str]]) -> Any:
    for path in paths:
        cur: Any = mapping
        ok = True
        for key in path:
            if not isinstance(cur, dict) or key not in cur:
                ok = False
                break
            cur = cur[key]
        if ok and cur not in (None, ""):
            return cur
    return ""


def extract_detail_url(summary: Dict[str, Any], meta: Dict[str, Any], request_id: str) -> str:
    candidates = [
        _dig_first(summary, (("detail_url",), ("detail", "url"), ("notification", "detail_url"))),
        _dig_first(meta, (("detail_url",), ("detail", "url"), ("links", "detail_url"))),
    ]
    for item in candidates:
        if isinstance(item, str) and item:
            return item
    return ""


def compact_case_summary(summary: Dict[str, Any], meta: Dict[str, Any]) -> Dict[str, Any]:
    fields = {
        "timestamp": _dig_first(summary, (("timestamp",), ("created_at",), ("time",))),
        "hostname": _dig_first(summary, (("hostname",), ("device", "hostname"), ("device_name",))),
        "device_ip": _dig_first(summary, (("device_ip",), ("device", "ip"), ("ip",))),
        "family": _dig_first(summary, (("family",), ("alert_family",), ("classification", "family"))),
        "object": _dig_first(summary, (("object",), ("interface",), ("target", "object"), ("alert_object",))),
        "judgement": _dig_first(summary, (("judgement",), ("current_judgement",), ("final_judgement",), ("analysis", "judgement"))),
        "recommendation": _dig_first(summary, (("recommendation",), ("recommendation_summary",), ("suggestion",), ("advice",))),
        "git_commit": _dig_first(meta, (("git_commit",), ("git", "commit"))),
    }
    return {k: v for k, v in fields.items() if v not in (None, "")}


def _walk_keys(value: Any, prefix: str = "") -> Iterable[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            new_prefix = f"{prefix}.{key}" if prefix else str(key)
            yield new_prefix
            yield from _walk_keys(item, new_prefix)
    elif isinstance(value, list):
        for idx, item in enumerate(value[:50]):
            yield from _walk_keys(item, f"{prefix}[{idx}]")


def detect_sensitive_keys(*values: Dict[str, Any]) -> List[str]:
    hits: List[str] = []
    for value in values:
        for key_path in _walk_keys(value):
            lower = key_path.lower()
            if any(word in lower for word in SENSITIVE_KEYWORDS):
                hits.append(key_path)
    return sorted(set(hits))


def probe_http(base_url: str, path: str, timeout: int = 5) -> HttpProbeResult:
    url = base_url.rstrip("/") + path
    req = urllib.request.Request(url, headers={"User-Agent": "netaiops-evidence-regression/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            body = resp.read(4096)
        ok = 200 <= int(status) < 300
        if ok and not body:
            return HttpProbeResult(path=path, ok=False, status_code=int(status), error="empty response body")
        return HttpProbeResult(path=path, ok=ok, status_code=int(status))
    except urllib.error.HTTPError as exc:
        return HttpProbeResult(path=path, ok=False, status_code=exc.code, error=str(exc))
    except Exception as exc:
        return HttpProbeResult(path=path, ok=False, status_code=None, error=str(exc))


def validate_request(data_root: Path, request_id: str, *, base_url: str = "", probe: bool = False, timeout: int = 5) -> CaseResult:
    result = CaseResult(request_id=request_id)
    root = _request_dir(data_root, request_id)
    if not root.is_dir():
        result.add_error(f"detail directory missing: {root}")
        return result

    present: List[str] = []
    missing: List[str] = []
    for name in RECOMMENDED_FILES:
        if (root / name).exists():
            present.append(name)
        else:
            missing.append(name)
    result.files_present = present
    result.files_missing = missing

    for name in DEFAULT_MIN_FILES:
        if name not in present:
            result.add_error(f"required file missing: {name}")

    summary, summary_err = _safe_read_json(root / "summary.json")
    if summary_err:
        result.add_error(f"summary.json {summary_err}")
        summary = {}
    meta, meta_err = _safe_read_json(root / "meta.json")
    if meta_err:
        result.add_error(f"meta.json {meta_err}")
        meta = {}

    result.summary = compact_case_summary(summary or {}, meta or {})
    result.meta = {
        "schema_version": _dig_first(meta or {}, (("schema_version",), ("schema",))),
        "created_at": _dig_first(meta or {}, (("created_at",), ("timestamp",))),
        "detail_url": _dig_first(meta or {}, (("detail_url",),)),
    }
    result.detail_url = extract_detail_url(summary or {}, meta or {}, request_id)
    if not result.detail_url:
        result.add_warning("detail_url missing in summary/meta")
    elif f"/evidence-ui/{request_id}" not in result.detail_url:
        result.add_warning("detail_url does not contain expected /evidence-ui/<request_id> path")

    if missing:
        result.add_warning("recommended files missing: " + ", ".join(missing))

    sensitive_hits = detect_sensitive_keys(summary or {}, meta or {})
    if sensitive_hits:
        result.add_warning("sensitive-looking keys present in summary/meta: " + ", ".join(sensitive_hits[:10]))

    slim_path = root / "notification_summary_slim.json"
    if not slim_path.exists():
        result.add_warning("notification_summary_slim.json missing; run slim summary builder or trigger Batch 10 path")
    else:
        slim, slim_err = _safe_read_json(slim_path)
        if slim_err:
            result.add_warning(f"notification_summary_slim.json {slim_err}")
        elif slim:
            text = str(slim.get("text") or slim.get("message") or "")
            banned = ("command_results", "raw_payload", "query_range")
            if any(word in text for word in banned):
                result.add_error("slim notification contains forbidden long-evidence markers")

    if probe and base_url:
        for path in (f"/evidence/{request_id}", f"/evidence-ui/{request_id}"):
            probe_result = probe_http(base_url, path, timeout=timeout)
            result.http_probes.append(probe_result)
            if not probe_result.ok:
                result.add_error(f"HTTP probe failed: {path} {probe_result.status_code} {probe_result.error}")

    return result


def build_report(cases: Sequence[CaseResult], *, data_root: Path, base_url: str = "", selected_request_ids: Sequence[str] = ()) -> Dict[str, Any]:
    passed = sum(1 for c in cases if c.status == "pass")
    warnings = sum(1 for c in cases if c.status == "warning")
    failed = sum(1 for c in cases if c.status == "fail")
    return {
        "schema_version": "v10.evidence_hub.regression.v1",
        "generated_at": _utc_now_iso(),
        "data_root": str(data_root),
        "base_url": base_url,
        "selected_request_ids": list(selected_request_ids),
        "summary": {
            "total": len(cases),
            "pass": passed,
            "warning": warnings,
            "fail": failed,
            "overall_status": "fail" if failed else ("warning" if warnings else "pass"),
        },
        "cases": [c.as_dict() for c in cases],
    }


def write_report(report: Dict[str, Any], output_dir: Path) -> Dict[str, str]:
    timestamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = output_dir / timestamp
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "evidence_hub_regression_report.json"
    md_path = out / "evidence_hub_regression_report.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = [
        "# Evidence Hub Regression Report",
        "",
        f"- Generated: {report.get('generated_at', '')}",
        f"- Overall: {report.get('summary', {}).get('overall_status', '')}",
        f"- Total: {report.get('summary', {}).get('total', 0)}",
        f"- Pass: {report.get('summary', {}).get('pass', 0)}",
        f"- Warning: {report.get('summary', {}).get('warning', 0)}",
        f"- Fail: {report.get('summary', {}).get('fail', 0)}",
        "",
        "## Cases",
        "",
    ]
    for case in report.get("cases", []):
        lines.append(f"### {case.get('request_id')} - {case.get('status')}")
        if case.get("detail_url"):
            lines.append(f"- Detail URL: {case.get('detail_url')}")
        if case.get("summary"):
            lines.append("- Summary: " + json.dumps(case.get("summary"), ensure_ascii=False))
        if case.get("warnings"):
            lines.append("- Warnings: " + "; ".join(case.get("warnings")))
        if case.get("errors"):
            lines.append("- Errors: " + "; ".join(case.get("errors")))
        lines.append("")
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}


def parse_request_ids(values: Sequence[str]) -> List[str]:
    result: List[str] = []
    for value in values:
        for item in str(value).replace(",", " ").split():
            item = item.strip()
            if item and item not in result:
                result.append(item)
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run representative Evidence Hub regression checks")
    parser.add_argument("--data-root", default="data", help="Project data directory, default: data")
    parser.add_argument("--request-id", action="append", default=[], help="Request ID to validate; can be repeated or comma-separated")
    parser.add_argument("--latest", type=int, default=6, help="Validate latest N existing Evidence Hub requests")
    parser.add_argument("--base-url", default="", help="Base URL such as http://127.0.0.1:18080")
    parser.add_argument("--probe-http", action="store_true", help="Probe /evidence and /evidence-ui HTTP endpoints")
    parser.add_argument("--timeout", type=int, default=5, help="HTTP timeout seconds")
    parser.add_argument("--output-dir", default="data/evidence_hub/regression", help="Report output directory")
    parser.add_argument("--strict", action="store_true", help="Return non-zero on warnings as well as failures")
    parser.add_argument("--json-only", action="store_true", help="Print compact JSON summary only")
    args = parser.parse_args(argv)
    data_root = Path(args.data_root)
    request_ids = parse_request_ids(args.request_id)
    if not request_ids:
        request_ids = select_latest_request_ids(data_root, args.latest)
    if not request_ids:
        print(json.dumps({"status": "fail", "error": "no Evidence Hub request directories found"}, ensure_ascii=False))
        return 1
    cases = [
        validate_request(data_root, rid, base_url=args.base_url, probe=args.probe_http, timeout=args.timeout)
        for rid in request_ids
    ]
    report = build_report(cases, data_root=data_root, base_url=args.base_url, selected_request_ids=request_ids)
    paths = write_report(report, Path(args.output_dir))
    report["output_files"] = paths
    if args.json_only:
        print(json.dumps({"status": report["summary"]["overall_status"], "summary": report["summary"], "output_files": paths}, ensure_ascii=False))
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["summary"]["fail"]:
        return 1
    if args.strict and report["summary"]["warning"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
