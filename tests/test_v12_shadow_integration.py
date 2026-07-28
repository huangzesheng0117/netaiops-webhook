from __future__ import annotations

import asyncio
import inspect
import json
import os
import socket
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from pydantic import ValidationError

from netaiops.v12.atomic_writer import AtomicJsonWriter
from netaiops.v12.shadow_audit_store import (
    ShadowAuditStore,
)
from netaiops.v12.shadow_contracts import (
    LegacyDeliverySnapshot,
    ShadowIntegrationSettings,
    ShadowPipelineResult,
    ShadowStatus,
)
from netaiops.v12.shadow_integration import (
    ShadowIntegrationController,
    shadow_audit_fingerprint,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = (
    PROJECT_ROOT / "tests/fixtures/v12/shadow"
)
REQUEST_ID = "req-batch-m-001"
NOW = datetime(2026, 7, 27, 8, 0, tzinfo=timezone.utc)
LEGACY_REF = (
    f"artifact://{REQUEST_ID}/legacy_notification/legacy-m"
)
REPORT_REF = (
    f"report://{REQUEST_ID}/report_artifact/report-m"
)


def fixture(name: str) -> dict:
    return json.loads(
        (FIXTURE_ROOT / name).read_text(encoding="utf-8")
    )


def snapshot(
    *,
    route: str = "/webhook/alertmanager",
    completed: bool = True,
    notification_count: int = 1,
) -> LegacyDeliverySnapshot:
    return LegacyDeliverySnapshot(
        request_id=REQUEST_ID,
        route=route,
        alert_status="firing",
        legacy_completed=completed,
        legacy_notification_count=notification_count,
        legacy_notification_ref=(
            LEGACY_REF if notification_count else None
        ),
        captured_at=NOW,
        legacy_metadata={
            "token": "DO-NOT-LEAK",
            "legacy_result": "sent",
        },
    )


class FakeRunner:
    def __init__(
        self,
        result=None,
        *,
        error: Exception | None = None,
        delay: float = 0.0,
    ) -> None:
        self.result = result or {
            "schema_version": "v12.1",
            "request_id": REQUEST_ID,
            "final_state": "completed",
            "artifact_refs": [REPORT_REF],
            "report_generated": True,
            "trace_written": False,
            "notification_sent": False,
            "notification_count": 0,
            "second_card_sent": False,
            "production_card_replaced": False,
            "production_glm_called": False,
            "mcp_called": False,
            "tool_called": False,
            "automatic_followup_queries": False,
            "external_calls": [],
        }
        self.error = error
        self.delay = delay
        self.calls = 0
        self.requests = []

    async def run(self, request):
        self.calls += 1
        self.requests.append(request)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error is not None:
            raise self.error
        return self.result


class BrokenStore:
    def persist(self, audit):
        raise OSError("store unavailable")


class ShadowIntegrationTests(unittest.TestCase):
    fixture_names = (
        "disabled.json",
        "invalid_side_effect_failed_open.json",
        "light_route_skipped.json",
        "main_route_completed.json",
        "timeout_failed_open.json",
    )

    def execute(
        self,
        controller: ShadowIntegrationController,
        value: LegacyDeliverySnapshot | None = None,
        **kwargs,
    ):
        return asyncio.run(
            controller.run_after_legacy(
                value or snapshot(),
                **kwargs,
            )
        )

    def enabled_settings(
        self,
        **updates,
    ) -> ShadowIntegrationSettings:
        values = {
            "enabled": True,
            "timeout_ms": 1000,
        }
        values.update(updates)
        return ShadowIntegrationSettings(**values)

    def test_fixture_set_is_complete(self) -> None:
        names = tuple(
            path.name
            for path in sorted(FIXTURE_ROOT.glob("*.json"))
        )
        self.assertEqual(names, self.fixture_names)

    def test_settings_default_disabled(self) -> None:
        settings = ShadowIntegrationSettings()
        self.assertFalse(settings.enabled)

    def test_settings_mode_is_shadow(self) -> None:
        self.assertEqual(
            ShadowIntegrationSettings().mode,
            "shadow",
        )

    def test_settings_fail_open_is_true(self) -> None:
        self.assertTrue(
            ShadowIntegrationSettings().fail_open_to_legacy
        )

    def test_settings_send_notification_is_false(self) -> None:
        self.assertFalse(
            ShadowIntegrationSettings().send_notification
        )

    def test_settings_replace_card_is_false(self) -> None:
        self.assertFalse(
            ShadowIntegrationSettings().replace_production_card
        )

    def test_settings_rca_is_disabled(self) -> None:
        self.assertFalse(
            ShadowIntegrationSettings().rca_enabled
        )

    def test_light_route_is_excluded(self) -> None:
        self.assertIn(
            "/light-alert/alertmanager",
            ShadowIntegrationSettings().excluded_routes,
        )

    def test_main_route_is_allowed(self) -> None:
        self.assertIn(
            "/webhook/alertmanager",
            ShadowIntegrationSettings().allowed_routes,
        )

    def test_route_overlap_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            ShadowIntegrationSettings(
                allowed_routes=("/same",),
                excluded_routes=("/same",),
            )

    def test_fail_open_false_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            ShadowIntegrationSettings(
                fail_open_to_legacy=False
            )

    def test_send_notification_true_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            ShadowIntegrationSettings(
                send_notification=True
            )

    def test_replace_card_true_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            ShadowIntegrationSettings(
                replace_production_card=True
            )

    def test_rca_true_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            ShadowIntegrationSettings(
                rca_enabled=True
            )

    def test_disabled_fixture(self) -> None:
        runner = FakeRunner()
        audit = self.execute(
            ShadowIntegrationController(
                runner=runner,
                utcnow=lambda: NOW,
            )
        )
        expected = fixture("disabled.json")
        for key, value in expected.items():
            actual = getattr(audit, key)
            if hasattr(actual, "value"):
                actual = actual.value
            self.assertEqual(actual, value)
        self.assertEqual(runner.calls, 0)

    def test_light_route_fixture(self) -> None:
        runner = FakeRunner()
        audit = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=runner,
                utcnow=lambda: NOW,
            ),
            snapshot(route="/light-alert/alertmanager"),
        )
        expected = fixture("light_route_skipped.json")
        for key, value in expected.items():
            actual = getattr(audit, key)
            if hasattr(actual, "value"):
                actual = actual.value
            self.assertEqual(actual, value)
        self.assertEqual(runner.calls, 0)

    def test_unknown_route_is_skipped(self) -> None:
        runner = FakeRunner()
        audit = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=runner,
                utcnow=lambda: NOW,
            ),
            snapshot(route="/other"),
        )
        self.assertEqual(
            audit.status,
            ShadowStatus.SKIPPED_ROUTE,
        )
        self.assertEqual(runner.calls, 0)

    def test_legacy_incomplete_is_skipped(self) -> None:
        runner = FakeRunner()
        audit = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=runner,
                utcnow=lambda: NOW,
            ),
            snapshot(completed=False),
        )
        self.assertEqual(
            audit.status,
            ShadowStatus.SKIPPED_LEGACY_INCOMPLETE,
        )
        self.assertEqual(runner.calls, 0)

    def test_main_route_completed_fixture(self) -> None:
        runner = FakeRunner()
        audit = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=runner,
                utcnow=lambda: NOW,
            )
        )
        expected = fixture("main_route_completed.json")
        for key, value in expected.items():
            actual = getattr(audit, key)
            if hasattr(actual, "value"):
                actual = actual.value
            self.assertEqual(actual, value)
        self.assertEqual(runner.calls, 1)

    def test_runner_receives_request_id(self) -> None:
        runner = FakeRunner()
        self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=runner,
                utcnow=lambda: NOW,
            )
        )
        self.assertEqual(
            runner.requests[0].request_id,
            REQUEST_ID,
        )

    def test_runner_receives_legacy_count(self) -> None:
        runner = FakeRunner()
        self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=runner,
                utcnow=lambda: NOW,
            ),
            snapshot(notification_count=2),
        )
        self.assertEqual(
            runner.requests[0].legacy_notification_count,
            2,
        )

    def test_input_refs_are_sorted_unique(self) -> None:
        runner = FakeRunner()
        audit = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=runner,
                utcnow=lambda: NOW,
            ),
            input_refs=[REPORT_REF, REPORT_REF],
        )
        self.assertEqual(audit.status, ShadowStatus.COMPLETED)
        self.assertEqual(
            runner.requests[0].input_refs,
            [REPORT_REF],
        )

    def test_input_snapshot_is_redacted(self) -> None:
        runner = FakeRunner()
        self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=runner,
                utcnow=lambda: NOW,
            ),
            input_snapshot={
                "token": "DO-NOT-LEAK",
                "raw_payload": {"secret": "DO-NOT-LEAK"},
            },
        )
        serialized = json.dumps(
            runner.requests[0].input_snapshot,
            ensure_ascii=False,
            sort_keys=True,
        )
        self.assertNotIn("DO-NOT-LEAK", serialized)
        self.assertIn("[REDACTED]", serialized)
        self.assertIn("[OMITTED]", serialized)

    def test_missing_runner_fails_open(self) -> None:
        audit = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                utcnow=lambda: NOW,
            )
        )
        self.assertEqual(audit.status, ShadowStatus.FAILED_OPEN)
        self.assertEqual(audit.error_code, "shadow_runner_missing")

    def test_runner_exception_fails_open(self) -> None:
        audit = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=FakeRunner(error=RuntimeError("boom")),
                utcnow=lambda: NOW,
            )
        )
        self.assertEqual(audit.status, ShadowStatus.FAILED_OPEN)
        self.assertEqual(audit.error_code, "shadow_runner_failed")

    def test_timeout_fixture(self) -> None:
        clock = iter(
            [
                NOW,
                NOW + timedelta(milliseconds=20),
            ]
        )
        audit = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(timeout_ms=100),
                runner=FakeRunner(delay=0.2),
                utcnow=lambda: next(clock),
            )
        )
        expected = fixture("timeout_failed_open.json")
        for key, value in expected.items():
            actual = getattr(audit, key)
            if hasattr(actual, "value"):
                actual = actual.value
            self.assertEqual(actual, value)

    def test_invalid_notification_side_effect_fails_open(self) -> None:
        result = FakeRunner().result
        result["notification_sent"] = True
        audit = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=FakeRunner(result=result),
                utcnow=lambda: NOW,
            )
        )
        expected = fixture(
            "invalid_side_effect_failed_open.json"
        )
        for key, value in expected.items():
            actual = getattr(audit, key)
            if hasattr(actual, "value"):
                actual = actual.value
            self.assertEqual(actual, value)

    def test_nonzero_shadow_notification_count_fails_open(self) -> None:
        result = FakeRunner().result
        result["notification_count"] = 1
        audit = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=FakeRunner(result=result),
                utcnow=lambda: NOW,
            )
        )
        self.assertEqual(audit.status, ShadowStatus.FAILED_OPEN)

    def test_second_card_side_effect_fails_open(self) -> None:
        result = FakeRunner().result
        result["second_card_sent"] = True
        audit = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=FakeRunner(result=result),
                utcnow=lambda: NOW,
            )
        )
        self.assertEqual(audit.status, ShadowStatus.FAILED_OPEN)

    def test_card_replacement_fails_open(self) -> None:
        result = FakeRunner().result
        result["production_card_replaced"] = True
        audit = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=FakeRunner(result=result),
                utcnow=lambda: NOW,
            )
        )
        self.assertEqual(audit.status, ShadowStatus.FAILED_OPEN)

    def test_production_glm_side_effect_fails_open(self) -> None:
        result = FakeRunner().result
        result["production_glm_called"] = True
        audit = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=FakeRunner(result=result),
                utcnow=lambda: NOW,
            )
        )
        self.assertEqual(audit.status, ShadowStatus.FAILED_OPEN)

    def test_mcp_side_effect_fails_open(self) -> None:
        result = FakeRunner().result
        result["mcp_called"] = True
        audit = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=FakeRunner(result=result),
                utcnow=lambda: NOW,
            )
        )
        self.assertEqual(audit.status, ShadowStatus.FAILED_OPEN)

    def test_tool_side_effect_fails_open(self) -> None:
        result = FakeRunner().result
        result["tool_called"] = True
        audit = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=FakeRunner(result=result),
                utcnow=lambda: NOW,
            )
        )
        self.assertEqual(audit.status, ShadowStatus.FAILED_OPEN)

    def test_external_calls_fail_open(self) -> None:
        result = FakeRunner().result
        result["external_calls"] = [{"kind": "network"}]
        audit = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=FakeRunner(result=result),
                utcnow=lambda: NOW,
            )
        )
        self.assertEqual(audit.status, ShadowStatus.FAILED_OPEN)

    def test_request_id_mismatch_fails_open(self) -> None:
        result = FakeRunner().result
        result["request_id"] = "req-other"
        audit = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=FakeRunner(result=result),
                utcnow=lambda: NOW,
            )
        )
        self.assertEqual(audit.status, ShadowStatus.FAILED_OPEN)

    def test_audit_always_preserves_legacy(self) -> None:
        statuses = []
        for controller in (
            ShadowIntegrationController(utcnow=lambda: NOW),
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=FakeRunner(),
                utcnow=lambda: NOW,
            ),
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=FakeRunner(error=RuntimeError("x")),
                utcnow=lambda: NOW,
            ),
        ):
            statuses.append(self.execute(controller))
        self.assertTrue(
            all(item.legacy_preserved for item in statuses)
        )

    def test_audit_notification_delta_is_zero(self) -> None:
        audit = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=FakeRunner(),
                utcnow=lambda: NOW,
            )
        )
        self.assertEqual(audit.notification_count_delta, 0)
        self.assertEqual(audit.shadow_notification_count, 0)

    def test_audit_never_replaces_card(self) -> None:
        audit = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=FakeRunner(),
                utcnow=lambda: NOW,
            )
        )
        self.assertFalse(audit.production_card_replaced)
        self.assertFalse(audit.second_card_sent)

    def test_audit_store_writes_atomic_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / "requests"
            locks = Path(temporary) / "locks"

            def factory(root):
                return AtomicJsonWriter(
                    root,
                    lock_root=locks,
                )

            store = ShadowAuditStore(
                base,
                writer_factory=factory,
            )
            audit = self.execute(
                ShadowIntegrationController(
                    settings=self.enabled_settings(),
                    runner=FakeRunner(),
                    audit_store=store,
                    utcnow=lambda: NOW,
                )
            )
            path = (
                base
                / REQUEST_ID
                / "v12"
                / "shadow_integration.json"
            )
            self.assertTrue(path.is_file())
            self.assertTrue(audit.trace_written)

    def test_audit_store_file_mode_is_0640(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / "requests"
            locks = Path(temporary) / "locks"

            def factory(root):
                return AtomicJsonWriter(
                    root,
                    lock_root=locks,
                )

            store = ShadowAuditStore(
                base,
                writer_factory=factory,
            )
            self.execute(
                ShadowIntegrationController(
                    settings=self.enabled_settings(),
                    runner=FakeRunner(),
                    audit_store=store,
                    utcnow=lambda: NOW,
                )
            )
            path = (
                base
                / REQUEST_ID
                / "v12"
                / "shadow_integration.json"
            )
            self.assertEqual(
                stat.S_IMODE(path.stat().st_mode),
                0o640,
            )

    def test_store_failure_fails_open(self) -> None:
        audit = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=FakeRunner(),
                audit_store=BrokenStore(),
                utcnow=lambda: NOW,
            )
        )
        self.assertEqual(audit.status, ShadowStatus.FAILED_OPEN)
        self.assertTrue(audit.legacy_preserved)

    def test_store_does_not_touch_legacy_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / "requests"
            request_root = base / REQUEST_ID
            request_root.mkdir(parents=True)
            legacy = request_root / "evidence_bundle.json"
            legacy.write_text('{"legacy":true}\n', encoding="utf-8")
            locks = Path(temporary) / "locks"

            def factory(root):
                return AtomicJsonWriter(
                    root,
                    lock_root=locks,
                )

            store = ShadowAuditStore(
                base,
                writer_factory=factory,
            )
            self.execute(
                ShadowIntegrationController(
                    settings=self.enabled_settings(),
                    runner=FakeRunner(),
                    audit_store=store,
                    utcnow=lambda: NOW,
                )
            )
            self.assertEqual(
                legacy.read_text(encoding="utf-8"),
                '{"legacy":true}\n',
            )

    def test_fingerprint_is_stable(self) -> None:
        first = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=FakeRunner(),
                utcnow=lambda: NOW,
            )
        )
        second = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=FakeRunner(),
                utcnow=lambda: NOW,
            )
        )
        self.assertEqual(
            shadow_audit_fingerprint(first),
            shadow_audit_fingerprint(second),
        )

    def test_duration_is_nonnegative(self) -> None:
        audit = self.execute(
            ShadowIntegrationController(
                settings=self.enabled_settings(),
                runner=FakeRunner(),
                utcnow=lambda: NOW,
            )
        )
        self.assertGreaterEqual(audit.duration_ms, 0)

    def test_naive_clock_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.execute(
                ShadowIntegrationController(
                    utcnow=lambda: datetime(
                        2026,
                        7,
                        27,
                        8,
                        0,
                    ),
                )
            )

    def test_async_runner_protocol(self) -> None:
        self.assertTrue(
            inspect.iscoroutinefunction(FakeRunner.run)
        )

    def test_controller_does_not_create_network_socket(self) -> None:
        controller = ShadowIntegrationController(
            settings=self.enabled_settings(),
            runner=FakeRunner(),
            utcnow=lambda: NOW,
        )
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            with mock.patch.object(
                socket,
                "socket",
                side_effect=AssertionError("network forbidden"),
            ):
                audit = loop.run_until_complete(
                    controller.run_after_legacy(snapshot())
                )
        finally:
            asyncio.set_event_loop(None)
            loop.close()
        self.assertEqual(audit.status, ShadowStatus.COMPLETED)

    def test_production_modules_have_no_external_clients(self) -> None:
        paths = (
            PROJECT_ROOT / "netaiops/v12/shadow_contracts.py",
            PROJECT_ROOT / "netaiops/v12/shadow_audit_store.py",
            PROJECT_ROOT / "netaiops/v12/shadow_integration.py",
        )
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in paths
        ).lower()
        for token in (
            "import requests",
            "import httpx",
            "import socket",
            "import subprocess",
            "fastmcp(",
            "elasticsearch(",
            "send_notification(",
            "send_dongdong(",
            "openai(",
        ):
            self.assertNotIn(token, text)

    def test_no_free_loop_or_retry(self) -> None:
        paths = (
            PROJECT_ROOT / "netaiops/v12/shadow_contracts.py",
            PROJECT_ROOT / "netaiops/v12/shadow_audit_store.py",
            PROJECT_ROOT / "netaiops/v12/shadow_integration.py",
        )
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in paths
        )
        for token in (
            "while True",
            "retry(",
            "followup_query(",
            "supplement_evidence(",
        ):
            self.assertNotIn(token, text)


if __name__ == "__main__":
    unittest.main()
