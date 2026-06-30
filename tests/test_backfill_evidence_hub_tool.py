from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


TOOL_PATH = Path(__file__).resolve().parents[1] / "tools" / "backfill_evidence_hub.py"


def load_tool_module():
    spec = importlib.util.spec_from_file_location("backfill_evidence_hub_tool", TOOL_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BackfillEvidenceHubToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = load_tool_module()

    def test_extract_request_ids_from_text(self) -> None:
        text = "x/20260630_145915_026622_805e79da.review.json"
        self.assertEqual(
            self.tool.extract_request_ids_from_text(text),
            ["20260630_145915_026622_805e79da"],
        )

    def test_discover_request_ids_sorted_by_mtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            raw = base / "data" / "raw"
            raw.mkdir(parents=True)
            older = raw / "20260630_111111_111111_aaaaaaaa.raw.json"
            newer = raw / "20260630_222222_222222_bbbbbbbb.raw.json"
            older.write_text("{}\n", encoding="utf-8")
            newer.write_text("{}\n", encoding="utf-8")
            os.utime(older, (1000, 1000))
            os.utime(newer, (2000, 2000))
            discovered = self.tool.discover_request_ids(base_dir=base)
            self.assertEqual(discovered[0][0], "20260630_222222_222222_bbbbbbbb")
            self.assertEqual(discovered[1][0], "20260630_111111_111111_aaaaaaaa")

    def test_resolve_explicit_and_latest_request_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            raw = base / "data" / "raw"
            raw.mkdir(parents=True)
            (raw / "20260630_222222_222222_bbbbbbbb.raw.json").write_text("{}\n", encoding="utf-8")
            ids = self.tool.resolve_target_request_ids(
                explicit_ids=["20260630_111111_111111_aaaaaaaa"],
                latest=1,
                base_dir=base,
            )
            self.assertEqual(ids, [
                "20260630_111111_111111_aaaaaaaa",
                "20260630_222222_222222_bbbbbbbb",
            ])

    def test_backfill_request_ids_writes_detail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            rid = "20260630_145915_026622_805e79da"
            raw = base / "data" / "raw"
            raw.mkdir(parents=True)
            (raw / f"{rid}.raw.json").write_text(
                json.dumps({
                    "request_id": rid,
                    "source": "unit-test",
                    "hostname": "sw01",
                    "device_ip": "10.0.0.1",
                    "alerts": [
                        {
                            "labels": {"alertname": "UnitAlert", "instance": "10.0.0.1"},
                            "annotations": {"summary": "unit summary"},
                        }
                    ],
                }, ensure_ascii=False),
                encoding="utf-8",
            )
            report = self.tool.backfill_request_ids(
                [rid],
                base_dir=base,
                config={"evidence_hub": {"base_url": "http://evidence.local"}},
            )
            self.assertEqual(report["status"], "ok")
            detail_dir = base / "data" / "evidence_hub" / "requests" / rid
            self.assertTrue((detail_dir / "meta.json").is_file())
            summary = json.loads((detail_dir / "notification_summary.json").read_text(encoding="utf-8"))
            self.assertIn("/evidence-ui/", summary["data"].get("detail_url", ""))

    def test_main_dry_run_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            raw = base / "data" / "raw"
            raw.mkdir(parents=True)
            rid = "20260630_222222_222222_bbbbbbbb"
            (raw / f"{rid}.raw.json").write_text("{}\n", encoding="utf-8")
            exit_code = self.tool.main([
                "--base-dir",
                str(base),
                "--latest",
                "1",
                "--dry-run",
                "--json",
            ])
            self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
