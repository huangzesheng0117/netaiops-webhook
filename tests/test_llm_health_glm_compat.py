import unittest
from unittest.mock import patch
from netaiops.llm_client import check_llm_health

class FakeResponse:
    status_code = 200
    headers = {"X-Channel-Name": "unit-test-glm"}
    def raise_for_status(self):
        return None
    def json(self):
        return {
            "model": "glm-5.2",
            "choices": [{
                "finish_reason": "stop",
                "message": {"content": '{"summary":"ok","confidence":"high"}'},
            }],
        }

class FakeClient:
    payloads = []
    def __init__(self, *args, **kwargs):
        pass
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        return False
    def post(self, url, headers=None, json=None):
        self.__class__.payloads.append(json)
        return FakeResponse()

class LlmHealthGlmCompatibilityTests(unittest.TestCase):
    def setUp(self):
        FakeClient.payloads = []
    def _run(self, configured_max_tokens):
        config = {"llm": {
            "enabled": True,
            "provider": "openai_compatible",
            "model": "glm-5.2",
            "base_url": "http://llm.example/v1",
            "max_tokens": configured_max_tokens,
            "timeout": 60,
        }}
        with patch("netaiops.llm_client.httpx.Client", FakeClient):
            return check_llm_health(config, include_models=False, chat_smoke=True)
    def test_health_smoke_raises_small_config_to_1200(self):
        result = self._run(128)
        self.assertEqual(result["overall_status"], "ok")
        self.assertEqual(FakeClient.payloads[0]["max_tokens"], 1200)
        endpoint = result["endpoints"][0]
        self.assertEqual(endpoint["chat_smoke_max_tokens"], 1200)
        self.assertEqual(endpoint["chat_finish_reason"], "stop")
        self.assertEqual(endpoint["chat_reported_model"], "glm-5.2")
    def test_health_smoke_preserves_larger_config(self):
        result = self._run(1800)
        self.assertEqual(result["overall_status"], "ok")
        self.assertEqual(FakeClient.payloads[0]["max_tokens"], 1800)
        self.assertEqual(result["endpoints"][0]["chat_smoke_max_tokens"], 1800)

if __name__ == "__main__":
    unittest.main()
