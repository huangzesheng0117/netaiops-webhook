import sys
import types
import unittest
import importlib.util


def _install_stub_module(name, **attrs):
    if importlib.util.find_spec(name) is not None:
        return
    mod = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(mod, key, value)
    sys.modules[name] = mod


_install_stub_module(
    "netaiops.dongdong_sender",
    send_dongdong_message=lambda title, detail: {"ok": True, "sent": True, "title": title, "detail": detail},
)
_install_stub_module(
    "netaiops.request_summary",
    get_request_summary=lambda request_id: {
        "execution": {"status": "completed"},
        "review": {"status": "completed"},
    },
)
_install_stub_module(
    "netaiops.settings",
    get_notify_settings=lambda: {"enabled": True, "provider": "dongdong"},
)
_install_stub_module(
    "netaiops.notification_payload",
    generate_notification_payload=lambda request_id: {"request_id": request_id, "title": "Full Title"},
    build_notification_text=lambda payload: "FULL TEXT",
)

import netaiops.notifier as notifier


class NotifierSlimModeTests(unittest.TestCase):
    def setUp(self):
        self._orig_write_slim = notifier.write_slim_notification_summary
        self._orig_send = notifier.send_dongdong_message
        self._orig_settings = notifier.get_notify_settings
        self._orig_should = notifier.should_send_notification
        self._orig_payload = notifier.generate_notification_payload
        self._orig_text = notifier.build_notification_text

    def tearDown(self):
        notifier.write_slim_notification_summary = self._orig_write_slim
        notifier.send_dongdong_message = self._orig_send
        notifier.get_notify_settings = self._orig_settings
        notifier.should_send_notification = self._orig_should
        notifier.generate_notification_payload = self._orig_payload
        notifier.build_notification_text = self._orig_text

    def _patch_common(self, *, mode=None):
        settings = {"enabled": True, "provider": "dongdong"}
        if mode is not None:
            settings["notification_mode"] = mode
        notifier.get_notify_settings = lambda: settings
        notifier.should_send_notification = lambda request_id: True
        notifier.generate_notification_payload = lambda request_id: {
            "request_id": request_id,
            "title": "Full Title",
            "target": {"family": "interface_or_link_utilization_high"},
        }
        notifier.build_notification_text = lambda payload: "FULL TEXT\n命令清单：show interface x\nPrometheus窗口证据：query_range"

    def test_default_mode_is_slim(self):
        self.assertEqual(notifier.get_notification_mode({}), "slim")

    def test_full_mode_uses_legacy_text(self):
        self._patch_common(mode="full")
        sent = {}

        def fake_send(title, detail):
            sent["title"] = title
            sent["detail"] = detail
            return {"ok": True, "sent": True}

        notifier.send_dongdong_message = fake_send
        result = notifier.send_notification("rid001")
        self.assertTrue(result["sent"])
        self.assertEqual(result["notification_mode"], "full")
        self.assertIn("命令清单", sent["detail"])
        self.assertIn("Prometheus窗口证据", sent["detail"])

    def test_slim_mode_sends_summary_text(self):
        self._patch_common()
        sent = {}

        def fake_write(request_id):
            return {
                "status": "ok",
                "request_id": request_id,
                "output_file": f"/tmp/{request_id}/notification_summary_slim.json",
                "summary": {
                    "title": "Slim Title",
                    "text": "标题：Slim Title\n判断：一句话判断\n详情：http://x/evidence-ui/rid002",
                    "detail_url": "http://x/evidence-ui/rid002",
                    "safety": {
                        "full_commands_included": False,
                        "full_metrics_included": False,
                        "raw_payload_included": False,
                    },
                },
            }

        def fake_send(title, detail):
            sent["title"] = title
            sent["detail"] = detail
            return {"ok": True, "sent": True}

        notifier.write_slim_notification_summary = fake_write
        notifier.send_dongdong_message = fake_send
        result = notifier.send_notification("rid002")
        self.assertTrue(result["sent"])
        self.assertEqual(result["notification_mode"], "slim")
        self.assertEqual(sent["title"], "Slim Title")
        self.assertIn("详情：http://x/evidence-ui/rid002", sent["detail"])
        self.assertNotIn("命令清单", sent["detail"])
        self.assertNotIn("query_range", sent["detail"])
        self.assertTrue(result["slim_summary_file"].endswith("notification_summary_slim.json"))

    def test_slim_failure_falls_back_to_full_text(self):
        self._patch_common()
        sent = {}

        def bad_write(request_id):
            raise RuntimeError("summary build failed")

        def fake_send(title, detail):
            sent["title"] = title
            sent["detail"] = detail
            return {"ok": True, "sent": True}

        notifier.write_slim_notification_summary = bad_write
        notifier.send_dongdong_message = fake_send
        result = notifier.send_notification("rid003")
        self.assertTrue(result["sent"])
        self.assertEqual(result["notification_mode"], "full_fallback")
        self.assertIn("summary build failed", result["slim_error"])
        self.assertIn("命令清单", sent["detail"])

    def test_disabled_notify_does_not_build_slim(self):
        called = {"slim": False}
        notifier.get_notify_settings = lambda: {"enabled": False, "provider": "dongdong"}

        def fake_write(request_id):
            called["slim"] = True
            return {}

        notifier.write_slim_notification_summary = fake_write
        result = notifier.send_notification("rid004")
        self.assertFalse(result["sent"])
        self.assertEqual(result["reason"], "notify_disabled")
        self.assertFalse(called["slim"])


if __name__ == "__main__":
    unittest.main()
