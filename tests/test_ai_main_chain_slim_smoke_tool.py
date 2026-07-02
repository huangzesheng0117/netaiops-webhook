from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = REPO_ROOT / "tools" / "ai_main_chain_slim_smoke.py"


def load_tool_module():
    spec = importlib.util.spec_from_file_location("ai_main_chain_slim_smoke", TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Batch13AiMainChainSlimSmokeTests(unittest.TestCase):
    def setUp(self):
        self.mod = load_tool_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.project = Path(self.tmp.name) / "project"
        self.data_root = self.project / "data"
        self.req_base = self.data_root / "evidence_hub" / "requests"
        self.req_base.mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def _write_detail(self, rid: str, *, detail_url: str = "") -> Path:
        root = self.req_base / rid
        root.mkdir(parents=True)
        (root / "summary.json").write_text(json.dumps({
            "request_id": rid,
            "hostname": "sw01",
            "device_ip": "10.0.0.1",
            "family": "interface_down",
            "judgement": "test judgement",
            "recommendations": ["open detail"],
            **({"detail_url": detail_url} if detail_url else {}),
        }, ensure_ascii=False), encoding="utf-8")
        (root / "meta.json").write_text(json.dumps({"request_id": rid}, ensure_ascii=False), encoding="utf-8")
        return root

    def test_make_payload_has_alertmanager_shape(self):
        payload = self.mod.make_alertmanager_payload()
        self.assertEqual(payload["status"], "firing")
        self.assertEqual(len(payload["alerts"]), 1)
        labels = payload["alerts"][0]["labels"]
        self.assertEqual(labels["batch"], "v10_batch13")
        self.assertIn("interface", labels)

    def test_repair_request_adds_detail_url_and_slim_file(self):
        rid = "20260701_000001_test"
        self._write_detail(rid)
        result = self.mod.repair_request_runtime_artifacts(self.data_root, rid, "http://example:18080")
        self.assertTrue(result.ok, result.errors)
        self.assertIn("summary.detail_url", result.repaired_fields)
        self.assertIn("meta.detail_url", result.repaired_fields)
        self.assertTrue((self.req_base / rid / "notification_summary_slim.json").exists())
        summary = json.loads((self.req_base / rid / "summary.json").read_text(encoding="utf-8"))
        self.assertIn(f"/evidence-ui/{rid}", summary["detail_url"])

    def test_latest_request_ids_sorted_desc(self):
        for rid in ["20260701_000001_a", "20260701_000003_c", "20260701_000002_b"]:
            self._write_detail(rid)
        self.assertEqual(self.mod.latest_request_ids(self.data_root, 2), ["20260701_000003_c", "20260701_000002_b"])

    def test_validate_slim_file_rejects_long_markers(self):
        rid = "20260701_000001_test"
        root = self._write_detail(rid, detail_url=f"http://example/evidence-ui/{rid}")
        (root / "notification_summary_slim.json").write_text(json.dumps({
            "text": "bad command_results raw_payload query_range",
            "detail_url": f"http://example/evidence-ui/{rid}",
        }, ensure_ascii=False), encoding="utf-8")
        ok, err = self.mod.validate_slim_file(self.data_root, rid)
        self.assertFalse(ok)
        self.assertIn("forbidden", err)

    def test_collect_file_status(self):
        rid = "20260701_000001_test"
        self._write_detail(rid)
        present, missing = self.mod.collect_file_status(self.data_root, rid)
        self.assertIn("summary.json", present)
        self.assertIn("meta.json", present)
        self.assertIn("notification_summary_slim.json", missing)

    def test_build_output_writes_report(self):
        smoke = self.mod.SmokeResult(request_id="rid1")
        out = self.mod.build_output(smoke, [], self.data_root, "http://example", str(self.data_root / "evidence_hub" / "batch13_smoke"))
        self.assertIn(out["overall_status"], {"pass", "warning"})
        self.assertTrue(Path(out["output_files"]["json"]).exists())
        self.assertTrue(Path(out["output_files"]["markdown"]).exists())


if __name__ == "__main__":
    unittest.main()

class TestBatch13DetailUrlCompatibility(unittest.TestCase):
    def test_smoke_tool_reads_nested_detail_url_sources(self):
        source = TOOL_PATH.read_text(encoding="utf-8")
        self.assertIn("notification_summary_slim.json", source)
        self.assertIn("_batch13_nested_dict(meta.get(\"data\")).get(\"detail_url\")", source)
        self.assertIn("notification_summary_slim.get(\"detail_url\")", source)



class TestBatch13DetailDirScope(unittest.TestCase):
    def test_smoke_tool_defines_detail_dir_before_notification_summary_reads(self):
        source = TOOL_PATH.read_text(encoding="utf-8")
        detail_pos = source.index("detail_dir = request_dir(data_root, request_id)")
        notif_pos = source.index('notification_summary = _batch13_optional_json(detail_dir / "notification_summary.json")')
        self.assertLess(detail_pos, notif_pos)
        self.assertIn('summary, _ = read_json(detail_dir / "summary.json")', source)
        self.assertIn('meta, _ = read_json(detail_dir / "meta.json")', source)

class TestBatch13SlimSummaryTiming(unittest.TestCase):
    def test_wait_for_slim_summary_file_accepts_valid_file(self):
        mod = load_tool_module()
        with tempfile.TemporaryDirectory() as td:
            data_root = Path(td) / "data"
            rid = "20260701_000010_wait"
            detail_dir = data_root / "evidence_hub" / "requests" / rid
            detail_dir.mkdir(parents=True)
            (detail_dir / "notification_summary_slim.json").write_text(json.dumps({
                "text": "标题：测试\n详情：http://example/evidence-ui/" + rid,
                "detail_url": "http://example/evidence-ui/" + rid,
            }, ensure_ascii=False), encoding="utf-8")
            ok, err = mod.wait_for_slim_summary_file(data_root, rid, 1, interval=0.01)
            self.assertTrue(ok, err)

    def test_run_smoke_waits_for_slim_before_collect_file_status(self):
        source = TOOL_PATH.read_text(encoding="utf-8")
        wait_pos = source.index("slim_wait_ok, slim_wait_err = wait_for_slim_summary_file")
        collect_pos = source.index("present, missing = collect_file_status")
        self.assertLess(wait_pos, collect_pos)
