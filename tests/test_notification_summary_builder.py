from pathlib import Path
import json
import tempfile
import unittest

from netaiops.notification_summary_builder import (
    SCHEMA_VERSION,
    SLIM_SUMMARY_FILENAME,
    build_slim_notification_summary,
    render_slim_notification_text,
    write_slim_notification_summary,
)


class NotificationSummaryBuilderTest(unittest.TestCase):
    def _write_json(self, path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def _make_detail(self, base: Path, request_id: str = "20260630_150000_test") -> Path:
        detail = base / "data" / "evidence_hub" / "requests" / request_id
        self._write_json(detail / "meta.json", {
            "status": "generated",
            "data": {"request_id": request_id, "detail_url": f"http://example/evidence-ui/{request_id}"},
        })
        self._write_json(detail / "alert_context.json", {
            "status": "derived",
            "data": {
                "alarm_type": "接口利用率高",
                "hostname": "SW01",
                "device_ip": "10.0.0.1",
                "object_name": "Te1/0/1",
                "summary": "接口 Te1/0/1 出向利用率超过阈值",
                "description": "raw payload should not be copied fully",
            },
        })
        self._write_json(detail / "classification.json", {
            "status": "derived",
            "data": {"family": "interface_or_link_utilization_high"},
        })
        self._write_json(detail / "metrics_evidence.json", {
            "status": "found",
            "data": {"query": "very long prometheus query should not appear in text", "samples": [1, 2, 3]},
        })
        self._write_json(detail / "device_evidence.json", {
            "status": "found",
            "data": {
                "stats": {"total_commands": 3, "completed_commands": 2, "failed_commands": 1},
                "command_results": [{"command": "show interface Te1/0/1", "output": "full output should not appear"}],
            },
        })
        self._write_json(detail / "review.json", {
            "status": "found",
            "data": {
                "conclusion": "接口当前利用率偏高，但需要结合业务时段确认是否持续异常。" * 5,
                "recommendations": [
                    "结合告警时间窗口确认是否持续高利用率。",
                    "如持续高位，进一步确认是否存在大流量业务或异常流量。",
                    "第三条不应进入短摘要。",
                ],
            },
        })
        self._write_json(detail / "notification_summary.json", {
            "status": "derived",
            "data": {
                "request_id": request_id,
                "title": "NetAIOps告警分析 - 接口利用率高",
                "device": {"hostname": "SW01", "device_ip": "10.0.0.1"},
                "object": "Te1/0/1",
                "family": "interface_or_link_utilization_high",
                "judgement": "接口只读取证完成，当前需要结合趋势确认是否持续高位。" * 5,
                "recommendations": [
                    "优先查看 Evidence Hub 中的趋势和设备取证结果。",
                    "确认是否为业务高峰或异常流量。",
                    "第三条不应进入短摘要。",
                ],
                "evidence_status": {"metrics": "found", "device": "found", "review": "found", "detail": "generated"},
                "command_stats": {"total_commands": 3, "completed_commands": 2, "failed_commands": 1},
                "detail_url": f"http://example/evidence-ui/{request_id}",
            },
        })
        self._write_json(detail / "summary.json", {"request_id": request_id, "summary": {"detail_url": f"http://example/evidence-ui/{request_id}"}})
        return detail

    def test_build_slim_summary_from_evidence_hub(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            request_id = "20260630_150000_test"
            self._make_detail(base, request_id)

            summary = build_slim_notification_summary(request_id, base_dir=base)

            self.assertEqual(summary["schema_version"], SCHEMA_VERSION)
            self.assertEqual(summary["request_id"], request_id)
            self.assertEqual(summary["device"]["display"], "SW01（10.0.0.1）")
            self.assertEqual(summary["object"], "Te1/0/1")
            self.assertEqual(len(summary["recommendations"]), 2)
            self.assertTrue(summary["detail_available"])
            self.assertIn("http://example/evidence-ui/", summary["detail_url"])
            self.assertIn("Prometheus：已生成", summary["evidence_summary"]["text"])
            self.assertIn("设备取证已完成：共 3 条", summary["evidence_summary"]["text"])

    def test_render_text_is_slim_and_excludes_full_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            request_id = "20260630_150001_test"
            self._make_detail(base, request_id)

            summary = build_slim_notification_summary(request_id, base_dir=base)
            text = summary["text"]

            self.assertIn("标题：", text)
            self.assertIn("设备：SW01（10.0.0.1）", text)
            self.assertIn("对象：Te1/0/1", text)
            self.assertIn("建议：", text)
            self.assertIn("详情：http://example/evidence-ui/", text)
            self.assertNotIn("show interface", text)
            self.assertNotIn("full output should not appear", text)
            self.assertNotIn("very long prometheus query", text)
            self.assertLess(len(text), 900)

    def test_missing_detail_fallback_mentions_request_id(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            request_id = "20260630_missing_test"
            summary = build_slim_notification_summary(request_id, base_dir=base)
            text = render_slim_notification_text(summary)

            self.assertFalse(summary["detail_available"])
            self.assertEqual(summary["source"], "evidence_hub_missing")
            self.assertIn("详情页生成失败", text)
            self.assertIn(request_id, text)

    def test_write_slim_summary_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            request_id = "20260630_150002_test"
            detail = self._make_detail(base, request_id)

            result = write_slim_notification_summary(request_id, base_dir=base)
            output_file = Path(result["output_file"])

            self.assertEqual(result["status"], "ok")
            self.assertEqual(output_file.name, SLIM_SUMMARY_FILENAME)
            self.assertTrue(output_file.exists())
            written = json.loads(output_file.read_text(encoding="utf-8"))
            self.assertEqual(written["request_id"], request_id)
            self.assertTrue((detail / SLIM_SUMMARY_FILENAME).exists())


if __name__ == "__main__":
    unittest.main()
