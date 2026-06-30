import json
import tempfile
import unittest
from pathlib import Path

from netaiops.evidence_hub import build_evidence_detail, find_request_artifacts


class TestEvidenceHubWriter(unittest.TestCase):
    def _write_json(self, path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def test_build_detail_from_existing_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            rid = "20260630_101500_123456_abcd1234"

            self._write_json(base / f"data/raw/alertmanager_{rid}.json", {
                "status": "firing",
                "alerts": [],
            })
            self._write_json(base / f"data/normalized/alertmanager_{rid}.json", {
                "request_id": rid,
                "source": "alertmanager",
                "events": [{
                    "source": "alertmanager",
                    "timestamp": "2026-06-30T10:15:00Z",
                    "alarm_type": "接口状态异常",
                    "severity": "critical",
                    "status": "firing",
                    "hostname": "SW01",
                    "device_ip": "10.0.0.1",
                    "vendor": "cisco",
                    "object_type": "interface",
                    "object_name": "TenGigabitEthernet1/0/1",
                    "labels": {"alertname": "接口状态异常"},
                    "annotations": {"summary": "接口 down"},
                    "raw_text": "接口 down",
                }],
            })
            self._write_json(base / f"data/analysis/alertmanager_{rid}.analysis.json", {
                "analysis_status": "ok",
                "result": {"summary": "接口当前异常，需要结合设备取证确认。"},
            })
            self._write_json(base / f"data/plans/alertmanager_{rid}.plan.json", {
                "plan_status": "ok",
                "family_result": {"family": "cisco_interface_down_or_oper_status"},
                "playbook": {"playbook_id": "cisco_interface_down_or_oper_status"},
            })
            self._write_json(base / f"data/prometheus_evidence/alertmanager_{rid}.prometheus_evidence.json", {
                "status": "success",
                "summary_text": "ifOperStatus 最近窗口异常。",
            })
            self._write_json(base / f"data/execution/alertmanager_{rid}.execution.json", {
                "execution_status": "completed",
                "stats": {"total_commands": 3, "completed_commands": 3, "failed_commands": 0},
                "command_results": [],
            })
            self._write_json(base / f"data/reviews/alertmanager_{rid}.review.json", {
                "review_status": "ok",
                "family": "cisco_interface_down_or_oper_status",
                "conclusion": "设备侧与指标侧均显示接口异常。",
                "recommendations": ["先确认对端设备和链路状态。", "检查是否存在计划内维护。"],
                "stats": {"command_total": 3, "command_completed": 3, "command_failed": 0},
            })

            artifacts = find_request_artifacts(rid, base_dir=base)
            self.assertEqual(artifacts["raw_payload"].status, "found")
            self.assertEqual(artifacts["metrics_evidence"].status, "found")

            result = build_evidence_detail(
                rid,
                base_dir=base,
                detail_url=f"http://127.0.0.1:18080/evidence-ui/{rid}",
            )

            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["missing_sections"], [])

            detail_dir = base / "data" / "evidence_hub" / "requests" / rid
            self.assertTrue(detail_dir.is_dir())
            for name in [
                "meta.json",
                "alert_context.json",
                "normalized_event.json",
                "classification.json",
                "plan.json",
                "metrics_evidence.json",
                "device_evidence.json",
                "review.json",
                "analysis_result.json",
                "notification_summary.json",
                "raw_payload.json",
                "summary.json",
            ]:
                self.assertTrue((detail_dir / name).is_file(), name)

            meta = json.loads((detail_dir / "meta.json").read_text(encoding="utf-8"))
            self.assertEqual(meta["data"]["request_id"], rid)
            self.assertEqual(meta["data"]["hostname"], "SW01")
            self.assertEqual(meta["data"]["family"], "cisco_interface_down_or_oper_status")

            summary = json.loads((detail_dir / "notification_summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["data"]["device"]["device_ip"], "10.0.0.1")
            self.assertEqual(summary["data"]["evidence_status"]["metrics"], "found")
            self.assertEqual(summary["data"]["recommendations"][0], "先确认对端设备和链路状态。")

    def test_missing_artifacts_are_recorded_not_raised(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            rid = "missing_case_001"
            self._write_json(base / f"data/raw/alertmanager_{rid}.json", {"status": "firing"})

            result = build_evidence_detail(rid, base_dir=base)
            self.assertEqual(result["status"], "ok")
            self.assertIn("normalized_event", result["missing_sections"])
            self.assertIn("plan", result["missing_sections"])

            detail_dir = base / "data" / "evidence_hub" / "requests" / rid
            meta = json.loads((detail_dir / "meta.json").read_text(encoding="utf-8"))
            self.assertIn("normalized_event", meta["data"]["missing_sections"])

    def test_invalid_request_id_does_not_create_detail_dir(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            with self.assertRaises(ValueError):
                build_evidence_detail("../bad", base_dir=base)
            self.assertFalse((base / "data" / "evidence_hub").exists())


if __name__ == "__main__":
    unittest.main()
