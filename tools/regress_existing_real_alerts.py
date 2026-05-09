#!/usr/bin/env python3
import json
import sqlite3
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path("/opt/netaiops-webhook")
sys.path.insert(0, str(BASE_DIR))

DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "index" / "netaiops_meta.sqlite3"
REPORT_JSON = BASE_DIR / "docs" / "webhook_v5_real_alert_regression_report.json"
REPORT_MD = BASE_DIR / "docs" / "webhook_v5_real_alert_regression_report.md"


FAMILY_PRIORITY = {
    "interface_or_link_utilization_high": "P0",
    "interface_or_link_traffic_drop": "P0",
    "interface_packet_loss_or_discards_high": "P0",
    "interface_status_or_flap": "P0",
    "bgp_neighbor_down": "P0",
    "ospf_neighbor_down": "P0",
    "device_cpu_high": "P0",
    "device_memory_high": "P0",
    "f5_pool_member_down": "P0",

    "hardware_fan_abnormal": "P1",
    "hardware_power_abnormal": "P1",
    "hardware_temperature_high": "P1",
    "chassis_slot_or_module_abnormal": "P1",
    "optical_power_abnormal": "P1",
    "device_disk_high": "P1",

    "dns_request_rate_anomaly": "P2",
    "dns_response_rate_anomaly": "P2",
    "f5_connection_rate_anomaly": "P2",
    "ha_or_cluster_state_abnormal": "P2",

    "cimc_hardware_abnormal": "P3",
    "generic_network_readonly": "P3",
}

TARGET_FAMILIES = list(FAMILY_PRIORITY.keys())


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def read_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def find_file_by_rid(directory: Path, rid: str, suffix: str) -> Optional[Path]:
    suffix = suffix if suffix.startswith(".") else "." + suffix

    direct = directory / f"{rid}{suffix}"
    if direct.exists():
        return direct

    matches = list(directory.glob(f"*_{rid}{suffix}"))
    if matches:
        return matches[0]

    matches = list(directory.glob(f"*{rid}*{suffix}"))
    if matches:
        return matches[0]

    return None


def execution_file(rid: str) -> Optional[Path]:
    return find_file_by_rid(DATA_DIR / "execution", rid, ".execution.json")


def execution_command_count(rid: str) -> int:
    path = execution_file(rid)
    if not path:
        return 0

    data = read_json(path)
    return len(data.get("command_results", []) or [])


def ensure_index() -> Dict[str, Any]:
    from netaiops.storage_index import rebuild_index

    return rebuild_index()


def connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def family_counts() -> Dict[str, int]:
    if not DB_PATH.exists():
        return {}

    with connect_db() as conn:
        rows = conn.execute(
            """
            SELECT family, COUNT(*) AS cnt
            FROM requests
            GROUP BY family
            ORDER BY cnt DESC
            """
        ).fetchall()

    return {safe_text(row["family"]): int(row["cnt"]) for row in rows}


def family_execution_counts() -> Dict[str, int]:
    if not DB_PATH.exists():
        return {}

    with connect_db() as conn:
        rows = conn.execute(
            """
            SELECT family, COUNT(*) AS cnt
            FROM requests
            WHERE has_execution = 1
            GROUP BY family
            ORDER BY cnt DESC
            """
        ).fetchall()

    return {safe_text(row["family"]): int(row["cnt"]) for row in rows}


def latest_executable_samples_by_family(limit_per_family: int = 1) -> Dict[str, List[Dict[str, Any]]]:
    if not DB_PATH.exists():
        ensure_index()

    result: Dict[str, List[Dict[str, Any]]] = {}

    with connect_db() as conn:
        for family in TARGET_FAMILIES:
            rows = conn.execute(
                """
                SELECT *
                FROM requests
                WHERE family = ?
                  AND has_execution = 1
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (family, limit_per_family),
            ).fetchall()

            selected = []
            for row in rows:
                item = dict(row)
                rid = safe_text(item.get("request_id"))
                if rid and execution_file(rid):
                    selected.append(item)

            result[family] = selected

    return result


def check_one_request(row: Dict[str, Any]) -> Dict[str, Any]:
    from netaiops.review_builder import generate_review_for_request_id
    from netaiops.notification_payload import build_notification_payload, build_notification_text

    rid = safe_text(row.get("request_id"))
    family = safe_text(row.get("family"))
    command_count = execution_command_count(rid)

    item: Dict[str, Any] = {
        "request_id": rid,
        "family": family,
        "device_ip": row.get("device_ip"),
        "hostname": row.get("hostname"),
        "interface_name": row.get("interface_name"),
        "event_status": row.get("event_status"),
        "command_count": command_count,
        "ok": False,
        "skipped": False,
        "skip_reason": "",
        "errors": [],
    }

    if not execution_file(rid):
        item["skipped"] = True
        item["skip_reason"] = "no_execution_file"
        item["ok"] = True
        return item

    try:
        review_result = generate_review_for_request_id(rid)
        review = review_result.get("review_data", {}) or {}

        evidence_summary = review.get("evidence_summary", {}) or {}
        evidence_bundle = review.get("evidence_bundle", {}) or {}

        payload = build_notification_payload(rid)
        text = build_notification_text(payload)

        item.update(
            {
                "review_status": review.get("review_status"),
                "has_evidence_summary": bool(evidence_summary),
                "evidence_has_facts": bool(evidence_summary.get("has_facts")),
                "evidence_family": evidence_summary.get("family"),
                "bundle_schema_version": evidence_bundle.get("schema_version"),
                "bundle_confidence": evidence_bundle.get("confidence"),
                "bundle_fact_count": len(evidence_bundle.get("facts", []) or []),
                "bundle_metric_count": len(evidence_bundle.get("metrics", []) or []),
                "bundle_log_count": len(evidence_bundle.get("logs", []) or []),
                "bundle_device_output_count": len(evidence_bundle.get("device_outputs", []) or []),
                "notify_title": payload.get("title"),
                "notify_has_device": "设备：" in text,
                "notify_has_alarm": "告警内容：" in text,
                "notify_has_analysis": "分析过程：" in text,
                "notify_has_recommendation": "建议：" in text,
                "notify_has_removed_context": "分析上下文" in text,
                "notify_has_removed_detail": "详情：" in text,
                "notify_has_command_detail": "具体内容为：" in text,
                "notify_text_len": len(text),
            }
        )

        if not item["has_evidence_summary"]:
            item["errors"].append("missing_evidence_summary")

        if evidence_bundle.get("schema_version") != "1.0":
            item["errors"].append("missing_or_invalid_evidence_bundle")

        if not item["notify_has_device"]:
            item["errors"].append("notification_missing_device")

        if not item["notify_has_alarm"]:
            item["errors"].append("notification_missing_alarm")

        if item["notify_has_removed_context"]:
            item["errors"].append("notification_contains_removed_context")

        if item["notify_has_removed_detail"]:
            item["errors"].append("notification_contains_removed_detail")

        if command_count > 0 and not item["notify_has_command_detail"]:
            item["errors"].append("notification_missing_command_detail")

        item["ok"] = len(item["errors"]) == 0

    except Exception as e:
        item["errors"].append(str(e))
        item["traceback"] = traceback.format_exc(limit=10)

    return item


def write_report(report: Dict[str, Any]) -> None:
    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    lines: List[str] = []
    lines.append("# webhook_v5 真实告警回归报告")
    lines.append("")
    lines.append(f"- generated_at: {report.get('generated_at')}")
    lines.append(f"- total_checked: {report.get('total_checked')}")
    lines.append(f"- passed: {report.get('passed')}")
    lines.append(f"- failed: {report.get('failed')}")
    lines.append(f"- skipped_no_execution_family_count: {len(report.get('skipped_no_execution_sample_families', []))}")
    lines.append(f"- missing_sample_family_count: {len(report.get('missing_sample_families', []))}")
    lines.append("")

    lines.append("## family 总数")
    lines.append("")
    lines.append("| family | total_count | execution_count |")
    lines.append("|---|---:|---:|")

    total_counts = report.get("family_counts", {}) or {}
    exec_counts = report.get("family_execution_counts", {}) or {}

    for family, count in total_counts.items():
        lines.append(f"| {family} | {count} | {exec_counts.get(family, 0)} |")

    lines.append("")
    lines.append("## 缺少真实样本的 family")
    lines.append("")
    if report.get("missing_sample_families"):
        for family in report.get("missing_sample_families", []):
            lines.append(f"- {family}")
    else:
        lines.append("- 无")

    lines.append("")
    lines.append("## 有样本但暂无 execution 的 family")
    lines.append("")
    if report.get("skipped_no_execution_sample_families"):
        for family in report.get("skipped_no_execution_sample_families", []):
            lines.append(f"- {family}")
    else:
        lines.append("- 无")

    lines.append("")
    lines.append("## 回归样本结果")
    lines.append("")
    lines.append("| priority | family | request_id | device | commands | ok | errors |")
    lines.append("|---|---|---|---|---:|---|---|")

    for item in report.get("checked_items", []):
        device = item.get("device_ip") or item.get("hostname") or ""
        errors = "；".join(item.get("errors", []) or [])
        lines.append(
            f"| {FAMILY_PRIORITY.get(item.get('family'), '')} "
            f"| {item.get('family')} "
            f"| {item.get('request_id')} "
            f"| {device} "
            f"| {item.get('command_count')} "
            f"| {item.get('ok')} "
            f"| {errors} |"
        )

    REPORT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    rebuild_result = ensure_index()

    samples = latest_executable_samples_by_family(limit_per_family=1)
    counts = family_counts()
    exec_counts = family_execution_counts()

    checked_items: List[Dict[str, Any]] = []
    missing_sample_families: List[str] = []
    skipped_no_execution_sample_families: List[str] = []

    for family in TARGET_FAMILIES:
        total_count = counts.get(family, 0)
        exec_count = exec_counts.get(family, 0)
        rows = samples.get(family, []) or []

        if not rows:
            if total_count > 0 and exec_count == 0:
                skipped_no_execution_sample_families.append(family)
            elif total_count == 0:
                missing_sample_families.append(family)
            else:
                skipped_no_execution_sample_families.append(family)
            continue

        for row in rows:
            result = check_one_request(row)
            if result.get("skipped"):
                skipped_no_execution_sample_families.append(family)
                continue
            checked_items.append(result)

    failed_items = [x for x in checked_items if not x.get("ok")]
    passed_items = [x for x in checked_items if x.get("ok")]

    report = {
        "generated_at": now(),
        "rebuild_index": rebuild_result,
        "family_counts": counts,
        "family_execution_counts": exec_counts,
        "target_families": TARGET_FAMILIES,
        "missing_sample_families": sorted(set(missing_sample_families)),
        "skipped_no_execution_sample_families": sorted(set(skipped_no_execution_sample_families)),
        "total_checked": len(checked_items),
        "passed": len(passed_items),
        "failed": len(failed_items),
        "checked_items": checked_items,
        "failed_items": failed_items,
        "report_json": str(REPORT_JSON),
        "report_md": str(REPORT_MD),
    }

    write_report(report)

    print("REAL_ALERT_REGRESSION_REPORT_JSON =", REPORT_JSON)
    print("REAL_ALERT_REGRESSION_REPORT_MD =", REPORT_MD)
    print("indexed =", rebuild_result.get("indexed"))
    print("index_failed_count =", len(rebuild_result.get("failed", []) or []))
    print("total_checked =", report["total_checked"])
    print("passed =", report["passed"])
    print("failed =", report["failed"])
    print("missing_sample_families =", report["missing_sample_families"])
    print("skipped_no_execution_sample_families =", report["skipped_no_execution_sample_families"])

    if report["total_checked"] <= 0:
        raise SystemExit("ERROR: no executable real alert samples found")

    if failed_items:
        print("===== failed_items =====")
        print(json.dumps(failed_items, ensure_ascii=False, indent=2))
        raise SystemExit("ERROR: real alert regression has failed items")

    print("REAL_ALERT_REGRESSION_CHECK=PASS")


if __name__ == "__main__":
    main()
