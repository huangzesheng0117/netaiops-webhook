import asyncio
import copy
import json
import tempfile
import unittest
from pathlib import Path

import app as app_module


class FakeRequest:
    def __init__(self, payload):
        self.payload = payload

    async def json(self):
        return self.payload


class FakeBackgroundTasks:
    def __init__(self):
        self.tasks = []

    def add_task(self, func, *args, **kwargs):
        self.tasks.append((func, args, kwargs))


def build_payload(status="firing", fingerprint="batch14-1-unit-fingerprint"):
    return {
        "status": status,
        "receiver": "batch14-1-unit-test",
        "groupKey": "{}:{alertname=\"Batch14.1直接轻量入口限流测试\"}",
        "alerts": [
            {
                "status": status,
                "fingerprint": fingerprint,
                "labels": {
                    "alertname": "Batch14.1直接轻量入口限流测试",
                    "ip": "10.187.251.101",
                    "sysName": "SH16-G03-DCI-BN-SW01",
                    "test_id": "batch14_1_unit",
                },
                "annotations": {
                    "description": "Batch14.1 direct light alert rate-limit unit test",
                    "for_duration": "1m",
                },
            }
        ],
    }


class DirectLightAlertRateLimitTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        self.old_light_dir = app_module.LIGHT_ALERT_DIR
        self.old_raw_dir = app_module.LIGHT_ALERT_RAW_DIR
        self.old_notify_dir = app_module.LIGHT_ALERT_NOTIFY_DIR

        app_module.LIGHT_ALERT_DIR = root / "light_alerts"
        app_module.LIGHT_ALERT_RAW_DIR = app_module.LIGHT_ALERT_DIR / "raw"
        app_module.LIGHT_ALERT_NOTIFY_DIR = app_module.LIGHT_ALERT_DIR / "notify"
        app_module.LIGHT_ALERT_RAW_DIR.mkdir(parents=True, exist_ok=True)
        app_module.LIGHT_ALERT_NOTIFY_DIR.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        app_module.LIGHT_ALERT_DIR = self.old_light_dir
        app_module.LIGHT_ALERT_RAW_DIR = self.old_raw_dir
        app_module.LIGHT_ALERT_NOTIFY_DIR = self.old_notify_dir
        self.tempdir.cleanup()

    def call_route(self, payload):
        background = FakeBackgroundTasks()
        response = asyncio.run(
            app_module.light_alert_alertmanager(FakeRequest(payload), background)
        )
        return response, background

    def read_notify_result(self, response):
        path = Path(response["notify_file"])
        self.assertTrue(path.exists(), path)
        return json.loads(path.read_text(encoding="utf-8"))

    def test_direct_route_firing_duplicate_resolved_lifecycle(self):
        firing = build_payload(status="firing")

        first, first_background = self.call_route(copy.deepcopy(firing))
        self.assertEqual(first["status"], "accepted")
        self.assertEqual(first["notification_count"], 1)
        self.assertEqual(first["sent_count"], 1)
        self.assertEqual(first["throttled_count"], 0)
        self.assertEqual(len(first_background.tasks), 1)
        self.assertEqual(
            first["rate_limit_decisions"][0]["reason"],
            "firing_first_or_expired",
        )

        first_file = self.read_notify_result(first)
        self.assertEqual(first_file["sent_count"], 1)
        self.assertEqual(first_file["throttled_count"], 0)
        self.assertEqual(
            first_file["direct_rate_limit_policy"]["firing_throttle_seconds"],
            3600,
        )

        duplicate, duplicate_background = self.call_route(copy.deepcopy(firing))
        self.assertEqual(duplicate["notification_count"], 1)
        self.assertEqual(duplicate["sent_count"], 0)
        self.assertEqual(duplicate["throttled_count"], 1)
        self.assertEqual(len(duplicate_background.tasks), 0)
        self.assertEqual(
            duplicate["rate_limit_decisions"][0]["reason"],
            "firing_throttled",
        )
        self.assertGreaterEqual(
            duplicate["rate_limit_decisions"][0]["remaining_seconds"],
            1,
        )

        resolved_payload = build_payload(status="resolved")
        resolved, resolved_background = self.call_route(resolved_payload)
        self.assertEqual(resolved["sent_count"], 1)
        self.assertEqual(resolved["throttled_count"], 0)
        self.assertEqual(len(resolved_background.tasks), 1)
        self.assertEqual(
            resolved["rate_limit_decisions"][0]["reason"],
            "resolved_cleared_firing_throttle",
        )
        self.assertTrue(
            resolved["rate_limit_decisions"][0]["cleared_firing_throttle"]
        )

        # resolved 清理后，同 fingerprint 再次 firing 应允许发送。
        after_resolved, after_resolved_background = self.call_route(
            copy.deepcopy(firing)
        )
        self.assertEqual(after_resolved["sent_count"], 1)
        self.assertEqual(after_resolved["throttled_count"], 0)
        self.assertEqual(len(after_resolved_background.tasks), 1)
        self.assertEqual(
            after_resolved["rate_limit_decisions"][0]["reason"],
            "firing_first_or_expired",
        )

    def test_different_fingerprints_are_independent(self):
        first, _ = self.call_route(build_payload(fingerprint="fp-a"))
        second, _ = self.call_route(build_payload(fingerprint="fp-b"))
        self.assertEqual(first["sent_count"], 1)
        self.assertEqual(second["sent_count"], 1)
        self.assertNotEqual(
            first["rate_limit_decisions"][0]["key"],
            second["rate_limit_decisions"][0]["key"],
        )


if __name__ == "__main__":
    unittest.main()
