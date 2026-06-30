import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import json

from netaiops.evidence_hub.detail_url import (
    build_detail_url,
    evidence_hub_default_to_local,
    evidence_hub_enabled,
    evidence_hub_url_config_summary,
    get_default_local_base_url,
    get_evidence_hub_base_url,
    normalize_base_url,
)
from netaiops.evidence_hub.integration import build_evidence_detail_safe


class TestEvidenceHubDetailUrl(unittest.TestCase):
    def test_normalize_base_url(self):
        self.assertEqual(normalize_base_url("http://example:18080/"), "http://example:18080")
        self.assertEqual(normalize_base_url("  http://example/a//  "), "http://example/a")
        self.assertEqual(normalize_base_url(""), "")
        self.assertEqual(normalize_base_url(None), "")

    def test_env_base_url_has_highest_priority(self):
        with patch.dict(os.environ, {"EVIDENCE_HUB_BASE_URL": "http://env.example/"}, clear=False):
            config = {
                "evidence_hub": {"base_url": "http://config.example"},
                "external_base_url": "http://external.example",
            }
            self.assertEqual(get_evidence_hub_base_url(config), "http://env.example")
            self.assertEqual(
                build_detail_url("rid001", config=config),
                "http://env.example/evidence-ui/rid001",
            )

    def test_evidence_hub_section_precedes_external_base_url(self):
        config = {
            "evidence_hub": {"base_url": "http://hub.example/"},
            "external_base_url": "http://external.example/",
        }
        self.assertEqual(get_evidence_hub_base_url(config), "http://hub.example")

    def test_external_base_url_is_supported_for_current_production_config(self):
        config = {"external_base_url": "http://10.191.97.138:18080/"}
        self.assertEqual(get_evidence_hub_base_url(config), "http://10.191.97.138:18080")
        self.assertEqual(
            build_detail_url("20260630_120000_000001_abcd1234", config=config),
            "http://10.191.97.138:18080/evidence-ui/20260630_120000_000001_abcd1234",
        )

    def test_default_local_url_uses_listen_port(self):
        config = {"listen_port": 18081}
        self.assertEqual(get_default_local_base_url(config), "http://127.0.0.1:18081")
        self.assertEqual(get_evidence_hub_base_url(config), "http://127.0.0.1:18081")

    def test_default_local_can_be_disabled(self):
        config = {"evidence_hub": {"default_to_local": False}, "listen_port": 18080}
        self.assertFalse(evidence_hub_default_to_local(config))
        self.assertEqual(get_evidence_hub_base_url(config), "")
        self.assertEqual(build_detail_url("rid001", config=config), "")

    def test_enabled_flag_still_works(self):
        self.assertTrue(evidence_hub_enabled({}))
        self.assertFalse(evidence_hub_enabled({"evidence_hub": {"enabled": False}}))
        with patch.dict(os.environ, {"EVIDENCE_HUB_ENABLED": "0"}, clear=False):
            self.assertFalse(evidence_hub_enabled({"evidence_hub": {"enabled": True}}))

    def test_config_summary_is_non_secret_and_explains_source(self):
        config = {"external_base_url": "http://external.example"}
        summary = evidence_hub_url_config_summary(config)
        self.assertEqual(summary["base_url"], "http://external.example")
        self.assertEqual(summary["base_url_source"], "config:external_base_url")
        self.assertTrue(summary["enabled"])

    def test_safe_build_uses_detail_url_from_external_base_url(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            rid = "20260630_120000_000001_abcd1234"
            raw_path = base / f"data/raw/alertmanager_{rid}.json"
            normalized_path = base / f"data/normalized/alertmanager_{rid}.json"
            review_path = base / f"data/reviews/alertmanager_{rid}.review.json"
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            normalized_path.parent.mkdir(parents=True, exist_ok=True)
            review_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_text(json.dumps({"status": "firing"}), encoding="utf-8")
            normalized_path.write_text(json.dumps({
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
            }), encoding="utf-8")
            review_path.write_text(json.dumps({
                "review_status": "completed",
                "final_judgement": {"summary": "接口当前为 down"},
                "recommendations": ["先确认对端和物理链路"],
            }), encoding="utf-8")

            result = build_evidence_detail_safe(
                rid,
                base_dir=base,
                config={"external_base_url": "http://hub.example:18080"},
                stage="unit_test_batch4",
            )
            self.assertTrue(result["ok"])
            self.assertEqual(result["detail_url"], f"http://hub.example:18080/evidence-ui/{rid}")
            summary = json.loads((base / "data/evidence_hub/requests" / rid / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["summary"]["detail_url"], f"http://hub.example:18080/evidence-ui/{rid}")


if __name__ == "__main__":
    unittest.main()
