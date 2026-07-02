from pathlib import Path
import unittest

PROJECT = Path(__file__).resolve().parents[1]
UI_FILE = PROJECT / "netaiops" / "evidence_hub" / "ui_api.py"


class TestEvidenceHubUITables(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = UI_FILE.read_text(encoding="utf-8")

    def test_command_tables_markers_exist(self):
        for marker in ["命令明细", "执行成功命令", "执行失败命令", "失败原因", "查看设备原始输出", "未保存原始输出"]:
            self.assertIn(marker, self.source)

    def test_prometheus_metric_table_markers_exist(self):
        for marker in ["Prometheus指标明细", "指标名", "查询窗口", "当前值", "对比值", "变化量", "变化比例", "窗口最大值", "窗口最小值", "窗口平均值", "趋势判断"]:
            self.assertIn(marker, self.source)

    def test_frontend_only_and_raw_json_preserved(self):
        self.assertIn("_batch136_render_command_tables", self.source)
        self.assertIn("_batch136_render_prometheus_table", self.source)
        self.assertIn("_json_pre(sections[section])", self.source)
        self.assertIn("前端只展示 Evidence Hub 已保存", self.source)
        self.assertNotIn("netmiko_connect", self.source)
        self.assertNotIn("send_dingdong", self.source)


if __name__ == "__main__":
    unittest.main()
