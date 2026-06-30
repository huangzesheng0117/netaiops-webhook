import json
import tempfile
import unittest
from pathlib import Path

from netaiops.evidence_hub.detail_api import (
    api_route_manifest,
    detail_exists,
    get_evidence_detail,
    get_evidence_device,
    get_evidence_metrics,
    get_evidence_review,
    get_evidence_section,
    get_evidence_summary,
)


class TestEvidenceHubDetailApi(unittest.TestCase):
    def _write_json(self, path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def _make_detail(self, base: Path, rid: str) -> Path:
        detail_dir = base / "data" / "evidence_hub" / "requests" / rid
        self._write_json(detail_dir / "summary.json", {
            "schema_version": "v10.evidence_hub.detail.v1",
            "request_id": rid,
            "summary": {"title": "NetAIOps告警分析 - InterfaceDown"},
            "missing_sections": [],
        })
        self._write_json(detail_dir / "meta.json", {
            "section": "meta",
            "data": {
                "request_id": rid,
                "detail_dir": str(detail_dir),
                "source_files": {
                    "review": {"source_file": str(base / "data/reviews/demo.review.json")}
                },
            },
        })
        for name in [
            "alert_context",
            "normalized_event",
            "classification",
            "plan",
            "metrics_evidence",
            "device_evidence",
            "review",
            "analysis_result",
            "notification_summary",
            "raw_payload",
        ]:
            self._write_json(detail_dir / f"{name}.json", {
                "section": name,
                "status": "found" if name in {"metrics_evidence", "device_evidence", "review"} else "derived",
                "data": {"name": name, "request_id": rid},
            })
        return detail_dir

    def test_summary_api_reader(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            rid = "20260630_130000_000001_abcd1234"
            self._make_detail(base, rid)
            result = get_evidence_summary(rid, base_dir=base)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["request_id"], rid)
            self.assertEqual(result["section"], "summary")
            self.assertEqual(result["file"], f"data/evidence_hub/requests/{rid}/summary.json")
            self.assertEqual(result["data"]["request_id"], rid)

    def test_full_detail_api_reader(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            rid = "20260630_130000_000001_abcd1234"
            self._make_detail(base, rid)
            result = get_evidence_detail(rid, base_dir=base)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["detail_dir"], f"data/evidence_hub/requests/{rid}")
            self.assertIn("metrics_evidence", result["sections"])
            self.assertIn("device_evidence", result["sections"])
            self.assertIn("review", result["sections"])
            encoded = json.dumps(result, ensure_ascii=False)
            self.assertNotIn(str(base), encoded)

    def test_section_alias_readers(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            rid = "20260630_130000_000001_abcd1234"
            self._make_detail(base, rid)
            self.assertEqual(get_evidence_metrics(rid, base_dir=base)["section"], "metrics_evidence")
            self.assertEqual(get_evidence_device(rid, base_dir=base)["section"], "device_evidence")
            self.assertEqual(get_evidence_review(rid, base_dir=base)["section"], "review")
            self.assertEqual(get_evidence_section(rid, "raw", base_dir=base)["section"], "raw_payload")

    def test_missing_and_invalid_request_id(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            self.assertFalse(detail_exists("missing_request", base_dir=base))
            with self.assertRaises(FileNotFoundError):
                get_evidence_summary("missing_request", base_dir=base)
            with self.assertRaises(ValueError):
                get_evidence_summary("../bad", base_dir=base)

    def test_route_manifest(self):
        manifest = api_route_manifest()
        routes = list(manifest["routes"])
        self.assertIn("GET /evidence/{request_id}", routes)
        self.assertIn("GET /evidence/{request_id}/summary", routes)
        self.assertIn("GET /evidence/{request_id}/metrics", routes)
        self.assertIn("GET /evidence/{request_id}/device", routes)
        self.assertIn("GET /evidence/{request_id}/review", routes)


if __name__ == "__main__":
    unittest.main()
