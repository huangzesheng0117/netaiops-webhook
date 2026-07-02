import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from netaiops.ai_analysis_card_builder import (
    CARD_SCHEMA_VERSION,
    CardBuildError,
    build_ai_analysis_card,
    build_ai_analysis_card_from_request,
    normalize_slim_summary,
    slim_summary_path,
    write_card_preview,
)


class AiAnalysisCardBuilderTests(unittest.TestCase):
    def setUp(self):
        self.summary = {
            "schema_version": "v10.notification_summary.slim.v1",
            "request_id": "20260702_150000_abcd1234",
            "title": "NetAIOps告警分析 - Cisco接口状态异常",
            "alert_status": "firing",
            "device": {
                "hostname": "SH16-G03-DCI-BN-SW01",
                "device_ip": "10.187.251.101",
            },
            "object": "TenGigabitEthernet1/0/1",
            "alert_content": "接口状态异常",
            "judgement": "接口只读取证已完成，建议结合状态和日志判断。",
            "recommendations": [
                "核查接口当前 oper/admin 状态。",
                "结合接口日志确认是否存在 flap。",
            ],
            "evidence_summary": "Prometheus：已生成；设备取证：成功 3 条；Review：已生成。",
            "detail_url": "http://10.191.97.138:18080/evidence-ui/20260702_150000_abcd1234",
            "command_results": [{"command": "show interface", "output": "full output"}],
            "prometheus_metrics": [{"name": "in_bps", "value": 1}],
            "raw_payload": {"secret": "must not enter card"},
        }

    def test_normalizes_device_and_status(self):
        normalized = normalize_slim_summary(self.summary)
        self.assertEqual(normalized["alert_status"], "告警中")
        self.assertEqual(
            normalized["device"],
            "SH16-G03-DCI-BN-SW01（10.187.251.101）",
        )
        self.assertEqual(normalized["alert_object"], "TenGigabitEthernet1/0/1")

    def test_builds_required_card_fields(self):
        card = build_ai_analysis_card(self.summary)
        self.assertEqual(card["schema_version"], CARD_SCHEMA_VERSION)
        labels = [item["label"] for item in card["fields"]]
        self.assertEqual(
            labels,
            [
                "告警状态",
                "设备",
                "告警对象",
                "告警内容",
                "当前判断",
                "处理建议",
                "证据摘要",
                "详情链接",
            ],
        )
        self.assertEqual(card["meta"]["full_evidence_embedded"], False)

    def test_universal_card_payload_contains_detail_action(self):
        card = build_ai_analysis_card(self.summary)
        universal = card["universal_card"]
        self.assertEqual(universal["header"]["template"], "default")
        action = universal["elements"][-1]
        self.assertEqual(action["tag"], "action")
        self.assertEqual(action["actions"][0]["text"]["content"], "查看详情")
        self.assertIn("/evidence-ui/", action["actions"][0]["url"])

    def test_full_evidence_is_not_embedded(self):
        card = build_ai_analysis_card(self.summary)
        serialized = json.dumps(card, ensure_ascii=False).lower()
        for forbidden in (
            "command_results",
            "show interface",
            "full output",
            "prometheus_metrics",
            "raw_payload",
            "query_range",
            "must not enter card",
        ):
            self.assertNotIn(forbidden.lower(), serialized)

    def test_invalid_detail_url_does_not_create_action(self):
        summary = dict(self.summary)
        summary["detail_url"] = "javascript:alert(1)"
        card = build_ai_analysis_card(summary)
        self.assertFalse(card["meta"]["detail_available"])
        self.assertNotEqual(card["universal_card"]["elements"][-1]["tag"], "action")

    def test_missing_recommendation_gets_safe_fallback(self):
        summary = dict(self.summary)
        summary.pop("recommendations")
        normalized = normalize_slim_summary(summary)
        self.assertEqual(len(normalized["recommendations"]), 1)
        self.assertIn("详情页", normalized["recommendations"][0])

    def test_build_from_request_reads_only_slim_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = slim_summary_path(self.summary["request_id"], root)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(self.summary, ensure_ascii=False), encoding="utf-8")
            card = build_ai_analysis_card_from_request(
                self.summary["request_id"],
                data_root=root,
            )
            self.assertEqual(card["request_id"], self.summary["request_id"])

    def test_invalid_request_id_rejected(self):
        with self.assertRaises(CardBuildError):
            slim_summary_path("../bad", "/tmp")

    def test_preview_file_is_valid_json(self):
        card = build_ai_analysis_card(self.summary)
        with tempfile.TemporaryDirectory() as td:
            target = write_card_preview(card, Path(td) / "preview.json")
            loaded = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(loaded["schema_version"], CARD_SCHEMA_VERSION)

    def test_cli_generates_local_preview_without_token(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            summary_path = root / "notification_summary_slim.json"
            output_path = root / "card_preview.json"
            summary_path.write_text(
                json.dumps(self.summary, ensure_ascii=False),
                encoding="utf-8",
            )
            env = dict(os.environ)
            for key in list(env):
                if "TOKEN" in key.upper() or "SECRET" in key.upper():
                    env.pop(key, None)
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "netaiops.ai_analysis_card_builder",
                    "--summary-file",
                    str(summary_path),
                    "--output",
                    str(output_path),
                    "--compact",
                ],
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(output_path.is_file())
            loaded = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["schema_version"], CARD_SCHEMA_VERSION)

    def test_builder_source_has_no_sender_or_token_access(self):
        source_path = Path("netaiops/ai_analysis_card_builder.py")
        source = source_path.read_text(encoding="utf-8")
        self.assertNotIn("send_dongdong", source)
        self.assertNotIn("requests.post", source)
        self.assertNotIn("httpx.post", source)
        self.assertNotIn("os.environ", source)
        self.assertNotIn("getenv(", source)
        self.assertNotIn("token", source.lower())
        self.assertNotIn("secret", source.lower())


if __name__ == "__main__":
    unittest.main()
