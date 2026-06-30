import json
import tempfile
import unittest
from pathlib import Path

from netaiops.evidence_hub import (
    REQUIRED_SECTION_FILES,
    SCHEMA_VERSION,
    build_empty_detail,
    request_detail_dir,
    safe_request_id,
    validate_request_id,
)
from netaiops.evidence_hub.schema import expected_detail_files


class TestEvidenceHubSchema(unittest.TestCase):
    def test_request_id_validation(self):
        self.assertTrue(validate_request_id("20260630_101500_123456_abcd1234"))
        self.assertTrue(validate_request_id("alertmanager-20260630T101500"))
        self.assertEqual(safe_request_id("abc_123"), "abc_123")

        for value in ["", ".", "..", "../x", "a/b", "a\\b", " "]:
            self.assertFalse(validate_request_id(value))
            with self.assertRaises(ValueError):
                safe_request_id(value)

    def test_build_empty_detail_schema(self):
        detail = build_empty_detail(
            "20260630_101500_123456_abcd1234",
            source="alertmanager",
            family="cisco_interface_down_or_oper_status",
            hostname="SW01",
            device_ip="10.0.0.1",
            object_name="TenGigabitEthernet1/0/1",
            detail_url="http://127.0.0.1:18080/evidence-ui/20260630_101500_123456_abcd1234",
            git_info={"branch": "main", "commit": "abcdef1", "dirty": False},
        )

        self.assertEqual(detail["schema_version"], SCHEMA_VERSION)
        self.assertEqual(detail["request_id"], "20260630_101500_123456_abcd1234")
        self.assertEqual(detail["meta"]["source"], "alertmanager")
        self.assertEqual(detail["meta"]["family"], "cisco_interface_down_or_oper_status")
        self.assertEqual(detail["summary"]["evidence_status"]["metrics"], "missing")
        self.assertIn("metrics_evidence", detail["sections"])
        self.assertIn("device_evidence", detail["sections"])
        self.assertIn("review", detail["sections"])
        self.assertIn("notification_summary", detail["sections"])
        self.assertIn("raw_payload", detail["sections"])
        self.assertEqual(set(REQUIRED_SECTION_FILES), set(detail["artifacts"]))

        encoded = json.dumps(detail, ensure_ascii=False)
        self.assertNotIn("token", encoded.lower())
        self.assertNotIn("secret", encoded.lower())

    def test_request_detail_paths_are_under_evidence_hub(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            rid = "20260630_101500_123456_abcd1234"
            root = request_detail_dir(rid, base_dir=base)
            self.assertEqual(
                root,
                base / "data" / "evidence_hub" / "requests" / rid,
            )

            files = expected_detail_files(rid, base_dir=base)
            self.assertEqual(files["meta"], root / "meta.json")
            self.assertEqual(files["metrics_evidence"], root / "metrics_evidence.json")
            self.assertEqual(files["device_evidence"], root / "device_evidence.json")


if __name__ == "__main__":
    unittest.main()
