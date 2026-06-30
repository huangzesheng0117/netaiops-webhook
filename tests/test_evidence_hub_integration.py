import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netaiops.evidence_hub.integration import (
    build_detail_url,
    build_evidence_detail_safe,
    evidence_hub_enabled,
    get_evidence_hub_base_url,
)


class TestEvidenceHubIntegration(unittest.TestCase):
    def _write_json(self, path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def test_build_detail_url_from_config(self):
        rid = "20260630_120000_000001_abcd1234"
        config = {"evidence_hub": {"base_url": "http://netaiops.example:18080/"}}
        self.assertEqual(
            build_detail_url(rid, config=config),
            f"http://netaiops.example:18080/evidence-ui/{rid}",
        )

    def test_env_base_url_overrides_config(self):
        rid = "20260630_120000_000001_abcd1234"
        with patch.dict(os.environ, {"EVIDENCE_HUB_BASE_URL": "http://env.example"}, clear=False):
            self.assertEqual(
                build_detail_url(rid, config={"evidence_hub": {"base_url": "http://config.example"}}),
                f"http://env.example/evidence-ui/{rid}",
            )
            self.assertEqual(get_evidence_hub_base_url({}), "http://env.example")

    def test_enabled_default_and_disable(self):
        self.assertTrue(evidence_hub_enabled({}))
        self.assertFalse(evidence_hub_enabled({"evidence_hub": {"enabled": False}}))
        with patch.dict(os.environ, {"EVIDENCE_HUB_ENABLED": "0"}, clear=False):
            self.assertFalse(evidence_hub_enabled({"evidence_hub": {"enabled": True}}))

    def test_safe_build_success(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            rid = "20260630_120000_000001_abcd1234"
            self._write_json(base / f"data/raw/alertmanager_{rid}.json", {"status": "firing"})
            self._write_json(base / f"data/normalized/alertmanager_{rid}.json", {
                "request_id": rid,
                "source": "alertmanager",
                "events": [{
                    "source": "alertmanager",
                    "alarm_type": "接口状态异常",
                    "hostname": "SW01",
                    "device_ip": "10.0.0.1",
                    "object_name": "Te1/0/1",
                    "labels": {"alertname": "InterfaceDown"},
                    "annotations": {"summary": "接口 down"},
                }],
            })
            self._write_json(base / f"data/plans/alertmanager_{rid}.plan.json", {
                "family_result": {"family": "cisco_interface_down"},
                "plan_status": "confirmed",
            })
            self._write_json(base / f"data/reviews/alertmanager_{rid}.review.json", {
                "review_status": "completed",
                "final_judgement": "接口当前为 down",
                "recommendations": ["先确认对端和物理链路"],
            })

            result = build_evidence_detail_safe(
                rid,
                base_dir=base,
                config={"evidence_hub": {"base_url": "http://hub.local"}},
                stage="unit_test",
            )
            self.assertTrue(result["ok"])
            self.assertEqual(result["stage"], "unit_test")
            self.assertEqual(result["detail_url"], f"http://hub.local/evidence-ui/{rid}")
            self.assertTrue((base / "data/evidence_hub/requests" / rid / "summary.json").exists())

    def test_safe_build_disabled(self):
        result = build_evidence_detail_safe(
            "20260630_120000_000001_abcd1234",
            base_dir=Path("/tmp/not-used"),
            config={"evidence_hub": {"enabled": False}},
            stage="unit_test_disabled",
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["reason"], "evidence_hub_disabled")

    def test_safe_build_invalid_request_id_does_not_raise(self):
        result = build_evidence_detail_safe("../bad", stage="invalid")
        self.assertFalse(result["ok"])
        self.assertEqual(result["stage"], "invalid")
        self.assertIn("invalid_request_id", result["error"])


if __name__ == "__main__":
    unittest.main()
