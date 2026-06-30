import json
import tempfile
import unittest
from pathlib import Path

from netaiops.evidence_hub.ui_api import (
    build_evidence_detail_html,
    build_evidence_index_html,
    ui_route_manifest,
)


class TestEvidenceHubUiApi(unittest.TestCase):
    def _write_json(self, path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def _make_detail(self, base: Path, rid: str = "rid_ui", hostname: str = "SH16-G03-DCI-BN-SW01") -> Path:
        detail_dir = base / "data" / "evidence_hub" / "requests" / rid
        summary_data = {
            "request_id": rid,
            "title": "NetAIOps告警分析 - interface_down",
            "device": {"hostname": hostname, "device_ip": "10.187.251.101"},
            "object": "Te1/0/1",
            "family": "interface_down",
            "judgement": "接口当前仍处于 down，需要先确认对端和业务影响。",
            "recommendations": ["先确认业务影响", "再查看详情页证据"],
            "evidence_status": {"metrics": "found", "device": "found", "review": "found"},
            "command_stats": {"total_commands": 3, "failed_commands": 0},
            "detail_url": f"http://example/evidence-ui/{rid}",
        }
        self._write_json(detail_dir / "summary.json", {
            "schema_version": "v10.evidence_hub.detail.v1",
            "request_id": rid,
            "generated_at": "2026-06-30T13:00:00+00:00",
            "summary": summary_data,
            "missing_sections": [],
            "read_error_sections": [],
        })
        self._write_json(detail_dir / "meta.json", {
            "section": "meta",
            "schema_version": "v10.evidence_hub.detail.v1",
            "status": "generated",
            "captured_at": "2026-06-30T13:00:00+00:00",
            "data": {
                "request_id": rid,
                "family": "interface_down",
                "hostname": hostname,
                "device_ip": "10.187.251.101",
                "object_name": "Te1/0/1",
                "detail_url": f"http://example/evidence-ui/{rid}",
            },
        })
        self._write_json(detail_dir / "metrics_evidence.json", {
            "section": "metrics_evidence",
            "status": "found",
            "data": {"summary_text": "Prometheus Evidence 正常"},
        })
        self._write_json(detail_dir / "device_evidence.json", {
            "section": "device_evidence",
            "status": "found",
            "data": {"commands": [{"command": "show interface Te1/0/1", "status": "success"}]},
        })
        self._write_json(detail_dir / "review.json", {
            "section": "review",
            "status": "found",
            "data": {"review_text": "Review 正常"},
        })
        self._write_json(detail_dir / "plan.json", {
            "section": "plan",
            "status": "found",
            "data": {"selected_playbook_id": "interface_down"},
        })
        self._write_json(detail_dir / "raw_payload.json", {
            "section": "raw_payload",
            "status": "found",
            "data": {"alerts": []},
        })
        return detail_dir

    def test_index_page_contains_request_link_filters_and_batch8_actions(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            self._make_detail(base, "rid_ui_index")
            html = build_evidence_index_html(base_dir=base, limit=10)
            self.assertIn("Evidence Hub", html)
            self.assertIn("v10 Batch 8", html)
            self.assertIn('/evidence-ui/rid_ui_index', html)
            self.assertIn('name="request_id"', html)
            self.assertIn('name="device_ip"', html)
            self.assertIn('name="family"', html)
            self.assertIn('data-copy-value="rid_ui_index"', html)
            self.assertIn("复制ID", html)
            self.assertIn('/evidence/rid_ui_index/metrics', html)
            self.assertIn('/evidence/rid_ui_index/device', html)
            self.assertIn('/evidence/rid_ui_index/review', html)

    def test_index_page_filter(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            self._make_detail(base, "rid_match", hostname="SH16-G03-DCI-BN-SW01")
            self._make_detail(base, "rid_other", hostname="SH16-G03-DCI-BN-SW01")
            html = build_evidence_index_html(base_dir=base, hostname="SH16-G03")
            self.assertIn("rid_match", html)
            self.assertIn("rid_other", html)
            none_html = build_evidence_index_html(base_dir=base, hostname="NO-SUCH-HOST")
            self.assertIn("暂无 Evidence Hub 详情记录", none_html)

    def test_index_page_pagination_and_request_id_filter(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            self._make_detail(base, "rid_one")
            self._make_detail(base, "rid_two")
            html = build_evidence_index_html(base_dir=base, limit=1, offset=0)
            self.assertIn("下一页", html)
            filtered = build_evidence_index_html(base_dir=base, request_id="rid_one", limit=10)
            self.assertIn("rid_one", filtered)
            self.assertNotIn("rid_two</a>", filtered)

    def test_detail_page_contains_core_sections_and_batch8_interactions(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            self._make_detail(base, "rid_ui_detail")
            html = build_evidence_detail_html("rid_ui_detail", base_dir=base)
            self.assertIn("SH16-G03-DCI-BN-SW01", html)
            self.assertIn("接口当前仍处于 down", html)
            self.assertIn("Prometheus Evidence", html)
            self.assertIn("MCP 命令执行结果", html)
            self.assertIn("Review / Analysis", html)
            self.assertIn('data-copy-value="rid_ui_detail"', html)
            self.assertIn("分区入口", html)
            self.assertIn('#section-metrics_evidence', html)
            self.assertIn('id="section-device_evidence"', html)
            self.assertIn('/evidence/rid_ui_detail/metrics', html)
            self.assertIn('/evidence/rid_ui_detail/device', html)
            self.assertIn('/evidence/rid_ui_detail/review', html)
            self.assertIn('onclick="setAllEvidenceSections(true)"', html)

    def test_detail_page_escapes_html(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            self._make_detail(base, "rid_escape")
            summary_path = base / "data" / "evidence_hub" / "requests" / "rid_escape" / "summary.json"
            doc = json.loads(summary_path.read_text(encoding="utf-8"))
            doc["summary"]["judgement"] = "<script>alert(1)</script>"
            summary_path.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
            html = build_evidence_detail_html("rid_escape", base_dir=base)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
            self.assertNotIn("<script>alert(1)</script>", html)

    def test_detail_page_missing_request_raises(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            with self.assertRaises(FileNotFoundError):
                build_evidence_detail_html("missing_rid", base_dir=base)

    def test_manifest_contains_ui_routes_and_batch8_version(self):
        manifest = ui_route_manifest()
        self.assertEqual(manifest["version"], "v10.batch8.ui")
        paths = {item["path"] for item in manifest["routes"]}
        self.assertIn("/evidence-ui", paths)
        self.assertIn("/evidence-ui/{request_id}", paths)
        self.assertIn("no_device_commands", manifest["boundaries"])
        self.assertIn("no_external_assets", manifest["boundaries"])


if __name__ == "__main__":
    unittest.main()
