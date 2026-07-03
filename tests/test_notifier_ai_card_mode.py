import os
import unittest

import netaiops.notifier as notifier


class NotifierAiCardModeTests(unittest.TestCase):
    def setUp(self):
        self.originals = {
            "get_notify_settings": notifier.get_notify_settings,
            "should_send_notification": notifier.should_send_notification,
            "generate_notification_payload": notifier.generate_notification_payload,
            "build_notification_text": notifier.build_notification_text,
            "write_slim_notification_summary": notifier.write_slim_notification_summary,
            "build_ai_analysis_card": notifier.build_ai_analysis_card,
            "send_ai_analysis_card": notifier.send_ai_analysis_card,
            "send_dongdong_message": notifier.send_dongdong_message,
        }
        self.old_env = os.environ.get("AI_NOTIFICATION_MODE")

    def tearDown(self):
        for name, value in self.originals.items():
            setattr(notifier, name, value)
        if self.old_env is None:
            os.environ.pop("AI_NOTIFICATION_MODE", None)
        else:
            os.environ["AI_NOTIFICATION_MODE"] = self.old_env

    def _common(self, settings=None):
        cfg = {
            "enabled": True,
            "provider": "dongdong",
            "notification_mode": "slim",
            "ai_notification_mode": "card",
            "ai_card_fallback_to_text": True,
        }
        if settings:
            cfg.update(settings)
        notifier.get_notify_settings = lambda: cfg
        notifier.should_send_notification = lambda request_id: True
        notifier.generate_notification_payload = lambda request_id: {"title": "Full title", "request_id": request_id}
        notifier.build_notification_text = lambda payload: "FULL TEXT"
        notifier.write_slim_notification_summary = lambda request_id: {
            "output_file": "",
            "summary": {
                "schema_version": "v10.notification_summary.slim.v1",
                "request_id": request_id,
                "title": "Slim title",
                "alert_status": "firing",
                "device": "SW01（10.0.0.1）",
                "object": "Gi1/0/1",
                "alert_content": "接口状态异常",
                "judgement": "接口当前状态异常",
                "recommendations": ["核查接口状态"],
                "evidence_summary": "设备取证已完成",
                "detail_url": f"http://example/evidence-ui/{request_id}",
                "text": f"标题：Slim title\n详情：http://example/evidence-ui/{request_id}",
            },
        }
        notifier.build_ai_analysis_card = lambda summary: {"title": summary["title"], "fields": []}

    def test_default_delivery_mode_is_card(self):
        os.environ.pop("AI_NOTIFICATION_MODE", None)
        self.assertEqual(notifier.get_ai_delivery_mode({}), "card")

    def test_card_success_does_not_send_text(self):
        self._common()
        called = {"text": 0}
        notifier.send_ai_analysis_card = lambda card, config_path: {"ok": True, "sent": True, "business_code": "200"}
        notifier.send_dongdong_message = lambda title, detail: called.__setitem__("text", called["text"] + 1)
        result = notifier.send_notification("rid-card-ok")
        self.assertTrue(result["sent"])
        self.assertEqual(result["delivery_mode"], "card")
        self.assertFalse(result["fallback_used"])
        self.assertEqual(called["text"], 0)

    def test_card_failure_falls_back_to_text(self):
        self._common()
        notifier.send_ai_analysis_card = lambda card, config_path: {
            "ok": False,
            "sent": False,
            "business_msg": "invalid card",
        }
        notifier.send_dongdong_message = lambda title, detail: {"ok": True, "sent": True}
        result = notifier.send_notification("rid-card-fallback")
        self.assertTrue(result["sent"])
        self.assertEqual(result["delivery_mode"], "text_fallback")
        self.assertTrue(result["fallback_used"])
        self.assertIn("invalid card", result["card_error"])

    def test_text_mode_bypasses_card(self):
        self._common({"ai_notification_mode": "text"})
        called = {"card": 0}
        notifier.send_ai_analysis_card = lambda card, config_path: called.__setitem__("card", called["card"] + 1)
        notifier.send_dongdong_message = lambda title, detail: {"ok": True, "sent": True}
        result = notifier.send_notification("rid-text")
        self.assertTrue(result["sent"])
        self.assertEqual(result["delivery_mode"], "text")
        self.assertEqual(called["card"], 0)

    def test_card_failure_without_fallback_returns_failure(self):
        self._common({"ai_card_fallback_to_text": False})
        notifier.send_ai_analysis_card = lambda card, config_path: {
            "ok": False,
            "sent": False,
            "business_msg": "denied",
        }
        notifier.send_dongdong_message = lambda title, detail: self.fail("text fallback must not run")
        result = notifier.send_notification("rid-no-fallback")
        self.assertFalse(result["sent"])
        self.assertEqual(result["delivery_mode"], "card")
        self.assertFalse(result["fallback_used"])


if __name__ == "__main__":
    unittest.main()
