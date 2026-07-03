import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netaiops.ai_analysis_card_sender import (
    AiAnalysisCardConfig,
    build_ai_card_request_payload,
    load_ai_card_config,
    parse_success,
    redacted_config,
    send_ai_analysis_card,
)


class _FakeResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return b'{"code":"200","msg":"success"}'


class AiAnalysisCardSenderTests(unittest.TestCase):
    def setUp(self):
        self.config = AiAnalysisCardConfig(
            card_api_url="https://example.invalid/universalCard/",
            service_account="800619",
            service_token="secret-token",
            appid="D619",
            group_id="62800",
        )
        self.card = {
            "title": "NetAIOps告警分析 - Cisco接口状态异常",
            "header": {"template": "default"},
            "fields": [
                {"label": "告警状态", "value": "告警中"},
                {"label": "设备", "value": "SW01（10.0.0.1）"},
                {"label": "当前判断", "value": "接口状态异常"},
                {"label": "处理建议", "value": "1. 查看接口状态\n2. 查看日志"},
                {"label": "详情链接", "value": "http://example/evidence-ui/rid001"},
            ],
        }

    def test_payload_matches_universal_card_api(self):
        payload = build_ai_card_request_payload(self.card, self.config)
        self.assertEqual(payload["appId"], "D619")
        self.assertEqual(payload["toGroupId"], "62800")
        self.assertEqual(payload["msgType"], "universalCard")
        detail = json.loads(payload["detail"])
        self.assertEqual(detail["config"]["appId"], payload["appId"])
        self.assertEqual(detail["header"]["template"], "default")
        self.assertTrue(any(item.get("tag") == "action" for item in detail["elements"]))
        self.assertNotIn("secret-token", json.dumps(payload, ensure_ascii=False))

    def test_recommendations_are_rendered_as_one_multiline_row(self):
        payload = build_ai_card_request_payload(self.card, self.config)
        detail = json.loads(payload["detail"])
        advice_rows = [
            item
            for item in detail["elements"]
            if item.get("tag") == "div"
            and item.get("fields")
            and item["fields"][0]["text"].get("prefix") == "处理建议："
        ]

        self.assertEqual(len(advice_rows), 1)
        text = advice_rows[0]["fields"][0]["text"]
        self.assertEqual(text["prefix"], "处理建议：")
        self.assertEqual(text["content"], "1. 查看接口状态\n2. 查看日志")
        self.assertIn("\n", text["content"])
        self.assertEqual(text["content"].count("处理建议："), 0)

    def test_load_config_and_redact_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ai.env"
            path.write_text(
                "\n".join(
                    [
                        "AI_DONGDONG_CARD_API_URL=https://example.invalid/card",
                        "AI_DONGDONG_SERVICE_ACCOUNT=800619",
                        "AI_DONGDONG_SERVICE_TOKEN=abc123",
                        "AI_DONGDONG_APPID=D619",
                        "AI_DONGDONG_GROUP_ID=62800",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            cfg = load_ai_card_config(str(path))
            redacted = redacted_config(cfg)
            self.assertEqual(cfg.group_id, "62800")
            self.assertEqual(redacted["service_token"], "***REDACTED***")
            self.assertNotIn("abc123", json.dumps(redacted))

    def test_placeholder_token_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ai.env"
            path.write_text(
                "AI_DONGDONG_CARD_API_URL=https://example.invalid/card\n"
                "AI_DONGDONG_SERVICE_ACCOUNT=800619\n"
                "AI_DONGDONG_SERVICE_TOKEN=REPLACE_ME\n"
                "AI_DONGDONG_APPID=D619\n"
                "AI_DONGDONG_GROUP_ID=62800\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_ai_card_config(str(path))

    def test_send_success(self):
        with patch("urllib.request.urlopen", return_value=_FakeResponse()):
            result = send_ai_analysis_card(self.card, config=self.config)
        self.assertTrue(result["ok"])
        self.assertTrue(result["sent"])
        self.assertEqual(result["business_code"], "200")
        self.assertEqual(result["group_id"], "62800")

    def test_parse_success(self):
        self.assertEqual(parse_success('{"code":"200","msg":"success"}', 200)[0], True)
        self.assertEqual(parse_success('{"code":"5001000","msg":"invalid"}', 200)[0], False)
        self.assertEqual(parse_success("not-json", 200)[2], "non_json_response")


if __name__ == "__main__":
    unittest.main()
