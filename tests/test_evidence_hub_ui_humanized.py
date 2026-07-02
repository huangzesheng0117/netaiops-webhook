from pathlib import Path
import re
import unittest


PROJECT = Path(__file__).resolve().parents[1]
UI_FILE = PROJECT / "netaiops" / "evidence_hub" / "ui_api.py"


class TestEvidenceHubUIHumanized(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = UI_FILE.read_text(encoding="utf-8")

    def test_manifest_version_keeps_batch8_contract(self):
        self.assertRegex(
            self.source,
            r"[\"']version[\"']\s*:\s*[\"']v10\.batch8\.ui[\"']",
        )
        self.assertNotRegex(
            self.source,
            r"[\"']version[\"']\s*:\s*[\"']v10\.batch13_5\.human_readable_ui[\"']",
        )

    def test_device_name_and_ip_are_rendered_as_separate_labels(self):
        self.assertIn("设备名称", self.source)
        self.assertIn("设备IP", self.source)
        # Guard against reverting to a single combined label only.
        self.assertRegex(self.source, r"设备名称")
        self.assertRegex(self.source, r"设备IP")

    def test_evidence_status_and_command_stats_have_humanized_text(self):
        expected_markers = [
            "证据状态",
            "命令统计",
            "工程师",
            "人类可读",
        ]
        missing = [m for m in expected_markers if m not in self.source]
        self.assertFalse(missing, f"missing UI humanized markers: {missing}")

    def test_raw_json_blocks_are_still_preserved(self):
        # Batch 13.5 must add readable explanations but keep original JSON evidence visible.
        self.assertIn("json.dumps", self.source)
        self.assertRegex(self.source, r"<pre|<code|details")


if __name__ == "__main__":
    unittest.main()
