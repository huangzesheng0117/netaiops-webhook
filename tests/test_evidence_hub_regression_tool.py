from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = REPO_ROOT / "tools" / "evidence_hub_regression.py"
MODULE_NAME = "evidence_hub_regression_tool_under_test"


def load_tool_module():
    """Load the regression tool from file in a dataclass-safe way.

    The tool module defines @dataclass classes. dataclasses expects
    sys.modules[cls.__module__] to exist while the class decorator runs.
    Therefore module_from_spec() alone is not enough: the module must be
    registered in sys.modules before exec_module().
    """
    spec = importlib.util.spec_from_file_location(MODULE_NAME, TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load spec for {TOOL_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(spec.name, None)
        raise
    return module


class EvidenceHubRegressionToolTests(unittest.TestCase):
    def setUp(self):
        self.mod = load_tool_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "data"
        self.base = self.root / "evidence_hub" / "requests"
        self.base.mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()
        sys.modules.pop(MODULE_NAME, None)

    def _write_case(self, request_id: str, *, detail_url: str | None = None, slim: bool = True):
        case_dir = self.base / request_id
        case_dir.mkdir(parents=True)
        detail_url = detail_url or f"http://example/evidence-ui/{request_id}"
        (case_dir / "summary.json").write_text(json.dumps({
            "request_id": request_id,
            "hostname": "sw01.example",
            "device_ip": "10.0.0.1",
            "family": "interface_or_link_utilization_high",
            "judgement": "readonly evidence completed",
            "recommendation": "open detail page",
            "detail_url": detail_url,
        }, ensure_ascii=False), encoding="utf-8")
        (case_dir / "meta.json").write_text(json.dumps({
            "schema_version": "v10.evidence_hub.detail.v1",
            "detail_url": detail_url,
        }, ensure_ascii=False), encoding="utf-8")
        if slim:
            (case_dir / "notification_summary_slim.json").write_text(
                json.dumps({"text": f"详情：{detail_url}"}, ensure_ascii=False),
                encoding="utf-8",
            )
        return case_dir

    def test_dynamic_import_registers_module_for_dataclass(self):
        module = load_tool_module()
        self.assertIn(MODULE_NAME, sys.modules)
        self.assertTrue(hasattr(module, "HttpProbeResult"))
        probe = module.HttpProbeResult(path="/health", ok=True, status_code=200)
        self.assertEqual(probe.as_dict()["status_code"], 200)

    def test_select_latest_request_ids(self):
        self._write_case("20260630_000001_a")
        self._write_case("20260630_000003_c")
        self._write_case("20260630_000002_b")
        self.assertEqual(
            self.mod.select_latest_request_ids(self.root, 2),
            ["20260630_000003_c", "20260630_000002_b"],
        )

    def test_validate_request_passes_with_minimal_files(self):
        rid = "20260630_000001_a"
        self._write_case(rid)
        result = self.mod.validate_request(self.root, rid)
        self.assertIn(result.status, {"pass", "warning"})
        self.assertEqual(result.request_id, rid)
        self.assertIn("summary.json", result.files_present)
        self.assertIn("meta.json", result.files_present)
        self.assertIn(f"/evidence-ui/{rid}", result.detail_url)
        self.assertFalse(result.errors)

    def test_validate_request_fails_when_summary_missing(self):
        rid = "20260630_000001_a"
        case_dir = self.base / rid
        case_dir.mkdir(parents=True)
        (case_dir / "meta.json").write_text("{}", encoding="utf-8")
        result = self.mod.validate_request(self.root, rid)
        self.assertEqual(result.status, "fail")
        self.assertTrue(any("summary.json" in e for e in result.errors))

    def test_sensitive_key_detection_is_warning_not_crash(self):
        hits = self.mod.detect_sensitive_keys({"config": {"api_token": "x"}})
        self.assertIn("config.api_token", hits)

    def test_write_report_creates_json_and_markdown(self):
        rid = "20260630_000001_a"
        self._write_case(rid)
        case = self.mod.validate_request(self.root, rid)
        report = self.mod.build_report(
            [case],
            data_root=self.root,
            base_url="http://example",
            selected_request_ids=[rid],
        )
        output = self.mod.write_report(report, self.root / "evidence_hub" / "regression")
        self.assertTrue(Path(output["json"]).exists())
        self.assertTrue(Path(output["markdown"]).exists())

    def test_parse_request_ids_accepts_repeated_and_comma(self):
        values = self.mod.parse_request_ids(["a,b", "c", "a"])
        self.assertEqual(values, ["a", "b", "c"])


if __name__ == "__main__":
    unittest.main()
