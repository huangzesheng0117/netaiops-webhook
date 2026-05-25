import unittest
from unittest.mock import patch

import httpx

from netaiops.llm_client import _build_endpoint_configs, _extract_json_text, call_llm


class FakeResponse:
    def __init__(self, status_code=200, payload=None, headers=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("bad status", request=None, response=None)

    def json(self):
        return self._payload


class FakeClient:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def post(self, url, headers=None, json=None):
        if self.error:
            raise self.error
        return self.response


class TestLLMClientResilience(unittest.TestCase):
    def test_extract_json_from_fenced_text(self):
        self.assertEqual(_extract_json_text("```json\n{\"summary\":\"ok\"}\n```"), "{\"summary\":\"ok\"}")

    def test_build_endpoint_configs_keeps_primary_model_endpoint(self):
        cfg = {
            "base_url": "http://primary/v1",
            "endpoints": [
                {"name": "long", "base_url": "http://long/v1", "timeout": 300},
            ],
            "timeout": 60,
        }
        endpoints = _build_endpoint_configs(cfg)
        self.assertEqual(endpoints[0]["name"], "primary")
        self.assertEqual(endpoints[1]["name"], "long")
        self.assertEqual(endpoints[1]["timeout"], 300)

    def test_call_llm_success_records_metadata(self):
        payload = {
            "model": "qwen3-max",
            "choices": [
                {
                    "message": {"content": "{\"summary\":\"ok\",\"confidence\":\"high\"}"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }
        cfg = {
            "llm": {
                "enabled": True,
                "provider": "openai_compatible",
                "base_url": "http://llm/v1",
                "model": "qwen3-max",
                "timeout": 60,
            }
        }
        fake = FakeClient(FakeResponse(payload=payload, headers={"X-Channel-Name": "local"}))
        with patch("netaiops.llm_client.httpx.Client", return_value=fake):
            result = call_llm("prompt", cfg)

        self.assertEqual(result["analysis"]["summary"], "ok")
        self.assertEqual(result["llm_metadata"]["call_status"], "success")
        self.assertEqual(result["llm_metadata"]["parse_status"], "ok")
        self.assertEqual(result["llm_metadata"]["channel_name"], "local")
        self.assertEqual(result["llm_metadata"]["usage"]["total_tokens"], 15)

    def test_call_llm_parse_failure_degrades_instead_of_raising(self):
        payload = {
            "model": "qwen3-max",
            "choices": [
                {
                    "message": {"content": "this is not json"},
                    "finish_reason": "stop",
                }
            ],
        }
        cfg = {
            "llm": {
                "enabled": True,
                "provider": "openai_compatible",
                "base_url": "http://llm/v1",
                "model": "qwen3-max",
                "timeout": 60,
            }
        }
        fake = FakeClient(FakeResponse(payload=payload))
        with patch("netaiops.llm_client.httpx.Client", return_value=fake):
            result = call_llm("prompt", cfg)

        self.assertEqual(result["llm_metadata"]["parse_status"], "json_parse_failed")
        self.assertIn("LLM 分析未能生成标准结构化结果", result["analysis"]["summary"])

    def test_call_llm_fallback_to_second_endpoint_after_transport_error(self):
        good_payload = {
            "model": "qwen3-max",
            "choices": [
                {
                    "message": {"content": "{\"summary\":\"fallback ok\"}"},
                    "finish_reason": "stop",
                }
            ],
        }
        cfg = {
            "llm": {
                "enabled": True,
                "provider": "openai_compatible",
                "endpoints": [
                    {"name": "primary", "base_url": "http://primary/v1"},
                    {"name": "backup", "base_url": "http://backup/v1"},
                ],
                "model": "qwen3-max",
                "timeout": 60,
                "retry": 0,
            }
        }
        bad_client = FakeClient(error=httpx.ConnectError("connect failed"))
        good_client = FakeClient(FakeResponse(payload=good_payload))

        with patch("netaiops.llm_client.httpx.Client", side_effect=[bad_client, good_client]):
            result = call_llm("prompt", cfg)

        self.assertEqual(result["analysis"]["summary"], "fallback ok")
        self.assertEqual(result["llm_metadata"]["endpoint_name"], "backup")
        self.assertEqual(result["llm_metadata"]["endpoint_index"], 1)


if __name__ == "__main__":
    unittest.main()
