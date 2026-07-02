from __future__ import annotations

import unittest
from pathlib import Path

from netaiops.evidence_hub import ui_api


class EvidenceHubUIRawOutputRenderingTest(unittest.TestCase):
    def test_raw_output_pre_renders_real_newlines(self):
        html = ui_api._batch137_output_pre("line-1\nline-2")
        self.assertIn('class="raw-output-pre"', html)
        self.assertIn("line-1\nline-2", html)
        self.assertNotIn("line-1\\nline-2", html)

    def test_raw_output_pre_normalizes_double_escaped_newlines(self):
        html = ui_api._batch137_output_pre("line-1\\nline-2")
        self.assertIn("line-1\nline-2", html)
        self.assertNotIn("line-1\\nline-2", html)

    def test_command_table_uses_raw_output_renderer(self):
        section_doc = {
            "data": {
                "command_results": [
                    {
                        "order": 1,
                        "status": "completed",
                        "command": "show interface ethernet1/35",
                        "capability": "test_capability",
                        "output": "show interface ethernet1/35\nEthernet1/35 is up\n  input rate 10 bps",
                    }
                ]
            }
        }
        html = ui_api._batch136_render_command_tables(section_doc)
        self.assertIn("查看设备原始输出", html)
        self.assertIn('class="raw-output-pre"', html)
        self.assertIn("show interface ethernet1/35\nEthernet1/35 is up", html)
        self.assertNotIn("show interface ethernet1/35\\nEthernet1/35 is up", html)

    def test_source_no_longer_json_encodes_command_output(self):
        source = Path("netaiops/evidence_hub/ui_api.py").read_text(encoding="utf-8")
        self.assertIn("BATCH13_7_RAW_OUTPUT_NEWLINE_HELPERS_START", source)
        self.assertIn("_batch137_output_pre(output, max_chars=40000)", source)
        self.assertNotIn("_json_pre(output, max_chars=40000)", source)


if __name__ == "__main__":
    unittest.main()
