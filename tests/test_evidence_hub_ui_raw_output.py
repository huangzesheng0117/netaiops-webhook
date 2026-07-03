from __future__ import annotations

import re
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

    def test_each_raw_output_has_copy_button_and_target(self):
        section_doc = {
            "data": {
                "command_results": [
                    {
                        "order": 1,
                        "status": "completed",
                        "command": "show interface ethernet1/35",
                        "output": "line-1\nline-2",
                    }
                ]
            }
        }
        html = ui_api._batch136_render_command_tables(section_doc)
        self.assertIn("复制原始输出", html)
        self.assertIn('data-copy-target="raw-output-success-1"', html)
        self.assertIn('id="raw-output-success-1"', html)
        target = re.search(r'data-copy-target="([^"]+)"', html)
        source = re.search(r'id="([^"]+)" class="raw-output-copy-source"', html)
        self.assertIsNotNone(target)
        self.assertIsNotNone(source)
        self.assertEqual(target.group(1), source.group(1))

    def test_command_table_has_adjustable_output_width_controls(self):
        section_doc = {
            "data": {
                "command_results": [
                    {
                        "order": 1,
                        "status": "completed",
                        "command": "show interfaces counters errors",
                        "output": "wide cli table",
                    }
                ]
            }
        }
        html = ui_api._batch136_render_command_tables(section_doc)
        self.assertIn('class="command-table-shell"', html)
        self.assertIn('class="command-output-width"', html)
        self.assertIn('data-width="72"', html)
        self.assertIn("扩大输出", html)
        self.assertIn("恢复默认", html)
        self.assertIn('class="col-output"', html)

    def test_page_script_supports_copy_target_and_width_controls(self):
        html = ui_api._page("test", "body")
        self.assertIn("data-copy-target", html)
        self.assertIn("target.textContent", html)
        self.assertIn("setCommandOutputWidth", html)
        self.assertIn("command-output-width-preset", html)
        self.assertIn("navigator.clipboard.writeText", html)
        self.assertIn("document.execCommand('copy')", html)

    def test_source_contains_non_wrapping_resizable_output_css(self):
        source = Path("netaiops/evidence_hub/ui_api.py").read_text(encoding="utf-8")
        self.assertIn("BATCH13_8_RAW_OUTPUT_INTERACTION_CSS_START", source)
        self.assertIn("white-space: pre;", source)
        self.assertIn("resize: horizontal;", source)
        self.assertIn("table-layout: fixed;", source)
        self.assertIn("--raw-output-width", source)

    def test_source_no_longer_json_encodes_command_output(self):
        source = Path("netaiops/evidence_hub/ui_api.py").read_text(encoding="utf-8")
        self.assertIn("BATCH13_7_RAW_OUTPUT_NEWLINE_HELPERS_START", source)
        self.assertIn("_batch137_output_pre(value, max_chars=40000)", source)
        self.assertNotIn("_json_pre(output, max_chars=40000)", source)


if __name__ == "__main__":
    unittest.main()
