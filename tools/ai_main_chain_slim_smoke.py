#!/usr/bin/env python3
"""Batch 13 AI main-chain slim notification smoke test.

This tool performs a controlled Alertmanager POST to the AI analysis entry,
then validates that the generated request_id has Evidence Hub detail, UI/API
access, and slim notification artifacts. It also repairs/audits the Batch 12
historical-warning risk for recent Evidence Hub records by adding missing
detail_url fields and regenerating notification_summary_slim.json in runtime
data only.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

# Batch 13 repair: allow direct execution from tools/ by adding project root to sys.path.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from netaiops.evidence_hub.detail_url import build_detail_url, get_evidence_hub_base_url
from netaiops.notification_summary_builder import write_slim_notification_summary

DEFAULT_PROJECT_ROOT = Path("/opt/netaiops-webhook")
DEFAULT_DATA_ROOT = DEFAULT_PROJECT_ROOT / "data"
DEFAULT_BASE_URL = "http://127.0.0.1:18080"
BANNED_SLIM_MARKERS = ("command_results", "raw_payload", "query_range")


@dataclass
class HttpResult:
    path: str
    ok: bool
    status_code: Optional[int] = None
    error: str = ""
    body_preview: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "ok": self.ok,
            "status_code": self.status_code,
            "error": self.error,
            "body_preview": self.body_preview,
        }


@dataclass
class RepairResult:
    request_id: str
    ok: bool = True
    detail_url: str = ""
    repaired_fields: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    slim_file: str = ""

    def add_error(self, message: str) -> None:
        self.ok = False
        self.errors.append(message)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "ok": self.ok,
            "detail_url": self.detail_url,
            "repaired_fields": self.repaired_fields,
            "warnings": self.warnings,
            "errors": self.errors,
            "slim_file": self.slim_file,
        }


@dataclass
class SmokeResult:
    request_id: str = ""
    ok: bool = True
    status: str = "pass"
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    posted_payload: Dict[str, Any] = field(default_factory=dict)
    post_response: Dict[str, Any] = field(default_factory=dict)
    files_present: List[str] = field(default_factory=list)
    files_missing: List[str] = field(default_factory=list)
    detail_url: str = ""
    slim_file: str = ""
    http_probes: List[HttpResult] = field(default_factory=list)

    def add_error(self, message: str) -> None:
        self.ok = False
        self.status = "fail"
        self.errors.append(message)

    def add_warning(self, message: str) -> None:
        if self.status != "fail":
            self.status = "warning"
        self.warnings.append(message)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "ok": self.ok,
            "status": self.status,
            "errors": self.errors,
            "warnings": self.warnings,
            "post_response": self.post_response,
            "files_present": self.files_present,
            "files_missing": self.files_missing,
            "detail_url": self.detail_url,
            "slim_file": self.slim_file,
            "http_probes": [item.as_dict() for item in self.http_probes],
        }


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def read_json(path: Path) -> Tuple[Dict[str, Any], str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, "missing"
    except Exception as exc:
        return {}, f"read_error: {exc}"
    if isinstance(value, dict):
        return value, ""
    return {"_value": value}, ""


def write_json(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(dict(data), ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def request_base(data_root: Path) -> Path:
    return data_root / "evidence_hub" / "requests"


def request_dir(data_root: Path, request_id: str) -> Path:
    return request_base(data_root) / request_id


def latest_request_ids(data_root: Path, limit: int) -> List[str]:
    base = request_base(data_root)
    if not base.is_dir() or limit <= 0:
        return []
    return sorted([p.name for p in base.iterdir() if p.is_dir()], reverse=True)[:limit]


def infer_project_root(data_root: Path) -> Path:
    data_root = data_root.resolve()
    return data_root.parent if data_root.name == "data" else DEFAULT_PROJECT_ROOT


def effective_base_url(project_root: Path, cli_base_url: str = "") -> str:
    if cli_base_url:
        return cli_base_url.rstrip("/")
    try:
        # Prefer runtime config/environment when available.
        return get_evidence_hub_base_url({}, allow_default=True).rstrip("/") or DEFAULT_BASE_URL
    except Exception:
        return DEFAULT_BASE_URL


def build_runtime_detail_url(request_id: str, base_url: str) -> str:
    if base_url:
        return base_url.rstrip("/") + f"/evidence-ui/{request_id}"
    try:
        return build_detail_url(request_id)
    except Exception:
        return f"{DEFAULT_BASE_URL}/evidence-ui/{request_id}"


def repair_request_runtime_artifacts(data_root: Path, request_id: str, base_url: str) -> RepairResult:
    root = request_dir(data_root, request_id)
    result = RepairResult(request_id=request_id)
    if not root.is_dir():
        result.add_error(f"detail directory missing: {root}")
        return result

    detail_url = build_runtime_detail_url(request_id, base_url)
    result.detail_url = detail_url
    project_root = infer_project_root(data_root)

    summary_path = root / "summary.json"
    summary, summary_err = read_json(summary_path)
    if summary_err:
        result.warnings.append(f"summary.json {summary_err}; creating minimal runtime summary")
        summary = {"request_id": request_id}
    if summary.get("detail_url") != detail_url:
        summary["detail_url"] = detail_url
        result.repaired_fields.append("summary.detail_url")
        write_json(summary_path, summary)

    meta_path = root / "meta.json"
    meta, meta_err = read_json(meta_path)
    if meta_err:
        result.warnings.append(f"meta.json {meta_err}; creating minimal runtime meta")
        meta = {"request_id": request_id}
    if meta.get("detail_url") != detail_url:
        meta["detail_url"] = detail_url
        result.repaired_fields.append("meta.detail_url")
    if not meta.get("batch12_warning_repaired_at"):
        meta["batch12_warning_repaired_at"] = now_iso()
        result.repaired_fields.append("meta.batch12_warning_repaired_at")
    write_json(meta_path, meta)

    try:
        slim = write_slim_notification_summary(request_id, base_dir=project_root)
        result.slim_file = str(slim.get("output_file", "")) if isinstance(slim, dict) else ""
        if result.slim_file:
            result.repaired_fields.append("notification_summary_slim.json")
    except Exception as exc:
        result.add_error(f"write_slim_notification_summary failed: {exc}")

    return result


def repair_latest_runtime_artifacts(data_root: Path, latest: int, base_url: str) -> List[RepairResult]:
    return [repair_request_runtime_artifacts(data_root, rid, base_url) for rid in latest_request_ids(data_root, latest)]


def make_alertmanager_payload() -> Dict[str, Any]:
    starts_at = now_iso()
    return {
        "receiver": "netaiops-batch13-smoke",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "Cisco接口状态异常",
                    "severity": "warning",
                    "vendor": "cisco",
                    "instance": "SH16-G03-DCI-BN-SW01",
                    "hostname": "SH16-G03-DCI-BN-SW01",
                    "ip": "10.187.251.101",
                    "device_ip": "10.187.251.101",
                    "interface": "TenGigabitEthernet1/0/1",
                    "job": "network-device",
                    "source": "batch13_ai_main_chain_smoke",
                    "batch": "v10_batch13",
                },
                "annotations": {
                    "summary": "Batch13 AI主链路短文本全链路仿真：Cisco接口状态异常",
                    "description": "Batch13 smoke test for Evidence Hub detail URL and slim DingDong notification. Device SH16-G03-DCI-BN-SW01 interface TenGigabitEthernet1/0/1 reported oper status abnormal. This is a controlled test alert.",
                },
                "startsAt": starts_at,
                "endsAt": "0001-01-01T00:00:00Z",
                "generatorURL": "http://batch13-smoke.local/prometheus/graph?g0.expr=ifOperStatus",
                "fingerprint": "batch13-smoke-" + str(int(time.time())),
            }
        ],
        "groupLabels": {"alertname": "Cisco接口状态异常"},
        "commonLabels": {"alertname": "Cisco接口状态异常", "severity": "warning"},
        "commonAnnotations": {"summary": "Batch13 AI主链路短文本全链路仿真"},
        "externalURL": "http://alertmanager.batch13.local",
        "version": "4",
        "groupKey": "batch13-ai-main-chain-smoke",
        "truncatedAlerts": 0,
    }


def post_json(base_url: str, path: str, payload: Dict[str, Any], timeout: int = 10) -> Dict[str, Any]:
    url = base_url.rstrip("/") + path
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "User-Agent": "netaiops-batch13-smoke/1.0"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
        status = getattr(resp, "status", None) or resp.getcode()
    text = body.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
    except Exception:
        parsed = {"raw_text": text}
    if not isinstance(parsed, dict):
        parsed = {"value": parsed}
    parsed["_http_status"] = status
    return parsed


def probe_http(base_url: str, path: str, timeout: int = 5) -> HttpResult:
    url = base_url.rstrip("/") + path
    req = urllib.request.Request(url, headers={"User-Agent": "netaiops-batch13-smoke/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            body = resp.read(5000)
        text = body.decode("utf-8", errors="replace")
        ok = 200 <= int(status) < 300 and bool(text)
        return HttpResult(path=path, ok=ok, status_code=int(status), body_preview=text[:300])
    except urllib.error.HTTPError as exc:
        return HttpResult(path=path, ok=False, status_code=exc.code, error=str(exc))
    except Exception as exc:
        return HttpResult(path=path, ok=False, error=str(exc))


def wait_for_file(path: Path, timeout_seconds: int, interval: float = 2.0) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if path.exists():
            return True
        time.sleep(interval)
    return path.exists()


def wait_for_evidence_detail(data_root: Path, request_id: str, timeout_seconds: int) -> bool:
    root = request_dir(data_root, request_id)
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if (root / "summary.json").exists() and (root / "meta.json").exists():
            return True
        time.sleep(2)
    return (root / "summary.json").exists() and (root / "meta.json").exists()


def collect_file_status(data_root: Path, request_id: str) -> Tuple[List[str], List[str]]:
    root = request_dir(data_root, request_id)
    expected = [
        "summary.json",
        "meta.json",
        "alert_context.json",
        "normalized_event.json",
        "analysis_result.json",
        "plan.json",
        "metrics_evidence.json",
        "device_evidence.json",
        "review.json",
        "notification_summary.json",
        "notification_summary_slim.json",
    ]
    present = [name for name in expected if (root / name).exists()]
    missing = [name for name in expected if name not in present]
    return present, missing


def validate_slim_file(data_root: Path, request_id: str) -> Tuple[bool, str]:
    path = request_dir(data_root, request_id) / "notification_summary_slim.json"
    data, err = read_json(path)
    if err:
        return False, f"notification_summary_slim.json {err}"
    text = str(data.get("text") or "")
    if not text:
        return False, "notification_summary_slim.json text is empty"
    hit = [marker for marker in BANNED_SLIM_MARKERS if marker in text]
    if hit:
        return False, "slim text contains forbidden markers: " + ", ".join(hit)
    if not data.get("detail_url"):
        return False, "notification_summary_slim.json detail_url missing"
    return True, ""


def wait_for_slim_summary_file(data_root: Path, request_id: str, timeout_seconds: int, interval: float = 2.0) -> Tuple[bool, str]:
    """Wait until Batch 10 slim notification summary has been written and is valid.

    Evidence Hub detail is generated before notification sending. The slim summary
    file is written during send_notification(), so a smoke test must wait for it
    after summary/meta appear instead of checking immediately.
    """
    deadline = time.time() + max(0, timeout_seconds)
    last_err = "notification_summary_slim.json missing"
    while time.time() < deadline:
        ok, err = validate_slim_file(data_root, request_id)
        if ok:
            return True, ""
        if err:
            last_err = err
        time.sleep(interval)
    ok, err = validate_slim_file(data_root, request_id)
    if ok:
        return True, ""
    return False, err or last_err


def run_smoke(args: argparse.Namespace) -> Dict[str, Any]:
    data_root = Path(args.data_root)
    project_root = infer_project_root(data_root)
    base_url = effective_base_url(project_root, args.base_url)
    historical_repairs = repair_latest_runtime_artifacts(data_root, args.repair_latest, base_url) if args.repair_latest else []

    result = SmokeResult()
    payload = make_alertmanager_payload()
    result.posted_payload = {"alertname": payload["alerts"][0]["labels"].get("alertname"), "labels": payload["alerts"][0]["labels"]}

    try:
        response = post_json(base_url, "/webhook/alertmanager", payload, timeout=args.http_timeout)
        result.post_response = response
    except Exception as exc:
        result.add_error(f"POST /webhook/alertmanager failed: {exc}")
        return build_output(result, historical_repairs, data_root, base_url, args.output_dir)

    request_id = str(response.get("request_id") or "").strip()
    result.request_id = request_id
    if not request_id:
        result.add_error("response request_id missing")
        return build_output(result, historical_repairs, data_root, base_url, args.output_dir)

    if str(response.get("status", "")).lower() != "accepted":
        result.add_error(f"webhook response status not accepted: {response.get('status')}")

    raw_ok = wait_for_file(data_root / "raw" / f"alertmanager_{request_id}.json", min(args.wait_seconds, 60))
    norm_ok = wait_for_file(data_root / "normalized" / f"alertmanager_{request_id}.json", min(args.wait_seconds, 60))
    if not raw_ok:
        result.add_error("raw payload file missing after webhook POST")
    if not norm_ok:
        result.add_error("normalized event file missing after webhook POST")

    if not wait_for_evidence_detail(data_root, request_id, args.wait_seconds):
        result.add_error("Evidence Hub detail summary/meta not generated before timeout")
        return build_output(result, historical_repairs, data_root, base_url, args.output_dir)

    # Batch 10 slim summary is generated during notification sending, after
    # Evidence Hub summary/meta are written. Wait for it before collecting
    # file status, otherwise smoke can race and report a false missing file.
    slim_wait_ok, slim_wait_err = wait_for_slim_summary_file(data_root, request_id, args.wait_seconds)
    if not slim_wait_ok:
        result.add_error(slim_wait_err)

    present, missing = collect_file_status(data_root, request_id)
    result.files_present = present
    result.files_missing = missing
    hard_required = {"summary.json", "meta.json"}
    for name in hard_required:
        if name not in present:
            result.add_error(f"required evidence file missing: {name}")

    detail_dir = request_dir(data_root, request_id)
    summary, _ = read_json(detail_dir / "summary.json")
    meta, _ = read_json(detail_dir / "meta.json")
    def _batch13_optional_json(path):
        try:
            if not path.exists():
                return {}
            with path.open("r", encoding="utf-8") as fp:
                data = json.load(fp)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    notification_summary = _batch13_optional_json(detail_dir / "notification_summary.json")
    notification_summary_slim = _batch13_optional_json(detail_dir / "notification_summary_slim.json")

    def _batch13_nested_dict(value):
        return value if isinstance(value, dict) else {}

    def _batch13_pick_detail_url(*values):
        for value in values:
            if value is None:
                continue
            text = str(value).strip()
            if text:
                return text
        return ""

    detail_url = _batch13_pick_detail_url(
        summary.get("detail_url"),
        _batch13_nested_dict(summary.get("summary")).get("detail_url"),
        _batch13_nested_dict(summary.get("data")).get("detail_url"),
        meta.get("detail_url"),
        _batch13_nested_dict(meta.get("data")).get("detail_url"),
        notification_summary.get("detail_url"),
        _batch13_nested_dict(notification_summary.get("data")).get("detail_url"),
        notification_summary_slim.get("detail_url"),
        _batch13_nested_dict(notification_summary_slim.get("data")).get("detail_url"),
    )
    result.detail_url = detail_url
    if not detail_url or f"/evidence-ui/{request_id}" not in detail_url:
        result.add_error("new request detail_url missing or malformed")

    # Batch 13 should prove Batch 10 slim path, not silently mask a new-request miss.
    slim_ok, slim_err = validate_slim_file(data_root, request_id)
    result.slim_file = str(request_dir(data_root, request_id) / "notification_summary_slim.json")
    if not slim_ok and slim_err not in result.errors:
        result.add_error(slim_err)

    for path in (f"/evidence/{request_id}", f"/evidence/{request_id}/summary", f"/evidence-ui/{request_id}"):
        probe = probe_http(base_url, path, timeout=args.http_timeout)
        result.http_probes.append(probe)
        if not probe.ok:
            result.add_error(f"HTTP probe failed: {path} {probe.status_code} {probe.error}")

    # Non-fatal: plan/execution/review/metrics can be missing for synthetic cases, but must be visible in report.
    optional_missing = [name for name in missing if name not in hard_required and name != "notification_summary_slim.json"]
    if optional_missing:
        result.add_warning("optional evidence files missing: " + ", ".join(optional_missing))

    return build_output(result, historical_repairs, data_root, base_url, args.output_dir)


def build_output(smoke: SmokeResult, historical_repairs: Sequence[RepairResult], data_root: Path, base_url: str, output_dir: str) -> Dict[str, Any]:
    historical_errors = [item.as_dict() for item in historical_repairs if not item.ok]
    output = {
        "schema_version": "v10.batch13.ai_main_chain_slim_smoke.v1",
        "generated_at": now_iso(),
        "base_url": base_url,
        "data_root": str(data_root),
        "historical_warning_handling": {
            "repair_count": len(historical_repairs),
            "error_count": len(historical_errors),
            "items": [item.as_dict() for item in historical_repairs],
        },
        "smoke": smoke.as_dict(),
        "overall_status": "fail" if (not smoke.ok or historical_errors) else ("warning" if smoke.warnings else "pass"),
    }
    out_dir = Path(output_dir) / _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "batch13_ai_main_chain_slim_smoke_report.json"
    md_path = out_dir / "batch13_ai_main_chain_slim_smoke_report.md"
    write_json(json_path, output)
    lines = [
        "# Batch 13 AI Main Chain Slim Smoke Report",
        "",
        f"- Generated: {output['generated_at']}",
        f"- Overall: {output['overall_status']}",
        f"- Base URL: {base_url}",
        f"- Request ID: {smoke.request_id}",
        f"- Smoke status: {smoke.status}",
        f"- Historical repairs: {len(historical_repairs)}",
        f"- Historical repair errors: {len(historical_errors)}",
        "",
        "## Errors",
        "",
    ]
    lines.extend([f"- {item}" for item in smoke.errors] or ["- none"])
    lines.extend(["", "## Warnings", ""])
    lines.extend([f"- {item}" for item in smoke.warnings] or ["- none"])
    md_path.write_text("\n".join(lines), encoding="utf-8")
    output["output_files"] = {"json": str(json_path), "markdown": str(md_path)}
    return output


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run Batch 13 AI main-chain slim text smoke test")
    parser.add_argument("--data-root", default=str(DEFAULT_DATA_ROOT))
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--repair-latest", type=int, default=12, help="Repair Batch 12 warning artifacts for latest N historical Evidence Hub requests")
    parser.add_argument("--wait-seconds", type=int, default=240)
    parser.add_argument("--http-timeout", type=int, default=10)
    parser.add_argument("--output-dir", default="data/evidence_hub/batch13_smoke")
    parser.add_argument("--json-only", action="store_true")
    args = parser.parse_args(argv)

    output = run_smoke(args)
    if args.json_only:
        print(json.dumps({"overall_status": output.get("overall_status"), "request_id": output.get("smoke", {}).get("request_id"), "output_files": output.get("output_files")}, ensure_ascii=False))
    else:
        print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0 if output.get("overall_status") in {"pass", "warning"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
