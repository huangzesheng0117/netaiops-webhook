from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import yaml

from netaiops.v12.p1_shadow_canary import (
    DEFAULT_ALLOWED_FAMILIES,
    P1CanaryError,
    P1CanaryState,
    P1RequestInput,
    P1Settings,
    P1_SCHEMA_VERSION,
    _summary_for_audit,
    _legacy_notification_count,
    _recursive_true_keys,
    collect_p1_observations,
    evaluate_p1_gate,
    load_p1_settings,
    run_p1_after_legacy_safe,
)
from netaiops.v12.atomic_writer import AtomicJsonWriter
from netaiops.v12.shadow_contracts import ShadowStatus


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def settings(**updates):
    values = {
        "schema_version": P1_SCHEMA_VERSION,
        "activation_id": "p1-test",
        "enabled": True,
        "mode": "shadow",
        "fail_open_to_legacy": True,
        "reuse_existing_evidence": True,
        "notifications_use_v12": False,
        "rca_enabled": False,
        "logs_enabled": False,
        "knowledge_enabled": False,
        "activated_at": datetime.now(timezone.utc),
        "canary_window_minutes": 60,
        "max_canary_requests": 20,
        "allowed_families": DEFAULT_ALLOWED_FAMILIES,
        "total_timeout_seconds": 45,
        "agent_timeout_seconds": 15,
        "minimum_completed_for_gate": 3,
    }
    values.update(updates)
    return P1Settings(**values)


def write_runtime(path: Path, **updates):
    raw_updates = dict(updates.pop("_raw", {}))
    value = settings(**updates)
    payload = {
        "schema_version": value.schema_version,
        "activation_id": value.activation_id,
        "enabled": value.enabled,
        "mode": value.mode,
        "fail_open_to_legacy": value.fail_open_to_legacy,
        "reuse_existing_evidence": value.reuse_existing_evidence,
        "notifications_use_v12": value.notifications_use_v12,
        "rca_enabled": value.rca_enabled,
        "logs_enabled": value.logs_enabled,
        "knowledge_enabled": value.knowledge_enabled,
        "activated_at": value.activated_at.isoformat(),
        "canary_window_minutes": value.canary_window_minutes,
        "max_canary_requests": value.max_canary_requests,
        "allowed_families": list(value.allowed_families),
        "total_timeout_seconds": value.total_timeout_seconds,
        "agent_timeout_seconds": value.agent_timeout_seconds,
        "minimum_completed_for_gate": value.minimum_completed_for_gate,
    }
    payload.update(raw_updates)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(payload, sort_keys=False),
        encoding="utf-8",
    )


class P1SettingsTests(unittest.TestCase):
    def test_default_families_are_frozen(self):
        self.assertEqual(
            DEFAULT_ALLOWED_FAMILIES,
            (
                "interface_status_or_flap",
                "interface_or_link_utilization_high",
                "interface_traffic_anomaly",
                "interface_or_link_traffic_drop",
            ),
        )

    def test_valid_settings_pass(self):
        settings().validate_frozen_boundary()

    def test_schema_drift_fails(self):
        with self.assertRaises(P1CanaryError):
            settings(schema_version="bad").validate_frozen_boundary()

    def test_mode_drift_fails(self):
        with self.assertRaises(P1CanaryError):
            settings(mode="primary").validate_frozen_boundary()

    def test_fail_open_false_fails(self):
        with self.assertRaises(P1CanaryError):
            settings(
                fail_open_to_legacy=False
            ).validate_frozen_boundary()

    def test_reuse_false_fails(self):
        with self.assertRaises(P1CanaryError):
            settings(
                reuse_existing_evidence=False
            ).validate_frozen_boundary()

    def test_notifications_true_fails(self):
        with self.assertRaises(P1CanaryError):
            settings(
                notifications_use_v12=True
            ).validate_frozen_boundary()

    def test_rca_true_fails(self):
        with self.assertRaises(P1CanaryError):
            settings(rca_enabled=True).validate_frozen_boundary()

    def test_logs_true_fails(self):
        with self.assertRaises(P1CanaryError):
            settings(logs_enabled=True).validate_frozen_boundary()

    def test_knowledge_true_fails(self):
        with self.assertRaises(P1CanaryError):
            settings(
                knowledge_enabled=True
            ).validate_frozen_boundary()

    def test_empty_families_fail(self):
        with self.assertRaises(P1CanaryError):
            settings(
                allowed_families=()
            ).validate_frozen_boundary()

    def test_max_requests_low_fails(self):
        with self.assertRaises(P1CanaryError):
            settings(
                max_canary_requests=0
            ).validate_frozen_boundary()

    def test_max_requests_high_fails(self):
        with self.assertRaises(P1CanaryError):
            settings(
                max_canary_requests=101
            ).validate_frozen_boundary()

    def test_window_low_fails(self):
        with self.assertRaises(P1CanaryError):
            settings(
                canary_window_minutes=0
            ).validate_frozen_boundary()

    def test_window_high_fails(self):
        with self.assertRaises(P1CanaryError):
            settings(
                canary_window_minutes=1441
            ).validate_frozen_boundary()

    def test_total_timeout_low_fails(self):
        with self.assertRaises(P1CanaryError):
            settings(
                total_timeout_seconds=4
            ).validate_frozen_boundary()

    def test_total_timeout_high_fails(self):
        with self.assertRaises(P1CanaryError):
            settings(
                total_timeout_seconds=61
            ).validate_frozen_boundary()

    def test_agent_timeout_low_fails(self):
        with self.assertRaises(P1CanaryError):
            settings(
                agent_timeout_seconds=0
            ).validate_frozen_boundary()

    def test_minimum_completed_exceeds_max_fails(self):
        with self.assertRaises(P1CanaryError):
            settings(
                minimum_completed_for_gate=21
            ).validate_frozen_boundary()

    def test_active_now_true(self):
        self.assertTrue(settings().active_now)

    def test_active_now_false_when_expired(self):
        value = settings(
            activated_at=(
                datetime.now(timezone.utc)
                - timedelta(hours=2)
            ),
            canary_window_minutes=30,
        )
        self.assertFalse(value.active_now)


class P1ConfigTests(unittest.TestCase):
    def test_missing_config_returns_none(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.assertIsNone(
                load_p1_settings(
                    Path(temporary) / "missing.yaml"
                )
            )

    def test_valid_config_loads(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.yaml"
            write_runtime(path)
            self.assertEqual(
                load_p1_settings(path).activation_id,
                "p1-test",
            )

    def test_unknown_config_key_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.yaml"
            write_runtime(
                path,
                _raw={"unknown_key": True},
            )
            with self.assertRaises(P1CanaryError):
                load_p1_settings(path)

    def test_naive_activated_at_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.yaml"
            write_runtime(
                path,
                _raw={"activated_at": "2026-07-30T00:00:00"},
            )
            with self.assertRaises(P1CanaryError):
                load_p1_settings(path)

    def test_symlink_config_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.yaml"
            write_runtime(target)
            link = root / "runtime.yaml"
            link.symlink_to(target)
            with self.assertRaises(P1CanaryError):
                load_p1_settings(link)

    def test_runtime_example_is_safe(self):
        raw = yaml.safe_load(
            (
                PROJECT_ROOT
                / "config"
                / "v12_p1_shadow.example.yaml"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(raw["enabled"])
        self.assertEqual(raw["mode"], "shadow")
        self.assertTrue(raw["fail_open_to_legacy"])
        self.assertTrue(raw["reuse_existing_evidence"])
        self.assertFalse(raw["notifications_use_v12"])
        self.assertFalse(raw["rca_enabled"])
        self.assertFalse(raw["logs_enabled"])
        self.assertFalse(raw["knowledge_enabled"])


class P1StateTests(unittest.TestCase):
    def test_claim_first_request(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = P1CanaryState(
                Path(temporary) / "state.json"
            )
            self.assertEqual(
                state.claim(settings(), "p1-request-1"),
                (True, "claimed"),
            )

    def test_duplicate_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = P1CanaryState(
                Path(temporary) / "state.json"
            )
            state.claim(settings(), "p1-request-1")
            self.assertEqual(
                state.claim(settings(), "p1-request-1"),
                (False, "duplicate_request"),
            )

    def test_limit_is_enforced(self):
        with tempfile.TemporaryDirectory() as temporary:
            value = settings(max_canary_requests=1)
            state = P1CanaryState(
                Path(temporary) / "state.json"
            )
            state.claim(value, "p1-request-1")
            self.assertEqual(
                state.claim(value, "p1-request-2"),
                (False, "max_canary_requests_reached"),
            )

    def test_activation_change_resets_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = P1CanaryState(
                Path(temporary) / "state.json"
            )
            state.claim(settings(), "p1-request-1")
            changed = settings(activation_id="p1-test-2")
            self.assertEqual(
                state.claim(changed, "p1-request-1"),
                (True, "claimed"),
            )

    def test_record_outcome(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            state = P1CanaryState(path)
            state.claim(settings(), "p1-request-1")
            state.record(
                settings(),
                "p1-request-1",
                "completed",
            )
            payload = json.loads(
                path.read_text(encoding="utf-8")
            )
            self.assertEqual(
                payload["outcomes"]["p1-request-1"],
                "completed",
            )


class P1BoundaryTests(unittest.TestCase):
    def test_notification_count_from_sent_count(self):
        self.assertEqual(
            _legacy_notification_count({"sent_count": 2}),
            2,
        )

    def test_notification_count_from_ok(self):
        self.assertEqual(
            _legacy_notification_count({"ok": True}),
            1,
        )

    def test_notification_count_default_zero(self):
        self.assertEqual(_legacy_notification_count({}), 0)

    def test_recursive_true_keys_detects_external_call(self):
        self.assertEqual(
            _recursive_true_keys(
                {"nested": {"prometheus_mcp_called": True}}
            ),
            {"prometheus_mcp_called"},
        )

    def test_recursive_true_keys_ignores_false(self):
        self.assertEqual(
            _recursive_true_keys(
                {"notification_sent": False}
            ),
            set(),
        )

    def test_p1_source_has_no_network_clients(self):
        text = (
            PROJECT_ROOT
            / "netaiops"
            / "v12"
            / "p1_shadow_canary.py"
        ).read_text(encoding="utf-8").lower()
        for token in (
            "import requests",
            "import httpx",
            "urllib.request",
            "socket.create_connection",
            "subprocess.",
            "send_notification(",
            "send_dongdong(",
            "fastmcp(",
            "openai(",
        ):
            self.assertNotIn(token, text)

    def test_p1_source_does_not_read_logs(self):
        text = (
            PROJECT_ROOT
            / "netaiops"
            / "v12"
            / "p1_shadow_canary.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("collect_log_evidence", text)
        self.assertNotIn("search_logs(", text)

    def test_app_schedules_v12_primary_after_legacy_notification(self):
        text = (
            PROJECT_ROOT / "app.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "def v4_execution_result(\n"
            "    request_id: str,\n"
            "    payload: dict,\n"
            "    background_tasks: BackgroundTasks,\n"
            "):",
            text,
        )
        notify = text.find(
            "notify_result = send_notification(request_id)"
        )
        primary = text.find(
            "background_tasks.add_task(\n"
            "        run_v12_primary_after_legacy_safe,"
        )
        self.assertGreater(notify, 0)
        self.assertGreater(primary, notify)
        self.assertNotIn("run_p1_after_legacy_safe,", text)

    def test_app_does_not_replace_notify_result(self):
        text = (
            PROJECT_ROOT / "app.py"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            text.count(
                "notify_result = send_notification(request_id)"
            ),
            1,
        )

    def test_runtime_config_is_gitignored(self):
        text = (
            PROJECT_ROOT / ".gitignore"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "config/v12_p1_shadow.yaml",
            text,
        )


class P1SafeEntryTests(unittest.TestCase):
    def test_disabled_when_runtime_file_missing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = run_p1_after_legacy_safe(
                request_id="p1-request-1",
                project_root=root,
                runtime_config=root / "missing.yaml",
                trace_root=root / "traces",
                state_file=root / "state.json",
            )
            self.assertEqual(result["status"], "disabled")
            self.assertFalse(result["external_calls"])

    def test_inactive_window_does_not_read_request(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "runtime.yaml"
            write_runtime(
                config,
                activated_at=(
                    datetime.now(timezone.utc)
                    - timedelta(hours=2)
                ),
                canary_window_minutes=30,
            )
            result = run_p1_after_legacy_safe(
                request_id="p1-request-1",
                project_root=root,
                runtime_config=config,
                trace_root=root / "traces",
                state_file=root / "state.json",
            )
            self.assertEqual(
                result["status"],
                "inactive_window",
            )

    def test_invalid_runtime_fails_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "runtime.yaml"
            config.write_text(
                "enabled: true\nunknown: true\n",
                encoding="utf-8",
            )
            result = run_p1_after_legacy_safe(
                request_id="p1-request-1",
                project_root=root,
                runtime_config=config,
                trace_root=root / "traces",
                state_file=root / "state.json",
            )
            self.assertEqual(result["status"], "failed_open")
            self.assertTrue(result["legacy_preserved"])
            self.assertEqual(
                result["notification_count_delta"],
                0,
            )

    def test_missing_request_artifact_is_recorded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "runtime.yaml"
            traces = root / "traces"
            state = root / "state.json"
            write_runtime(config)
            result = run_p1_after_legacy_safe(
                request_id="p1-request-1",
                project_root=root,
                runtime_config=config,
                trace_root=traces,
                state_file=state,
            )
            self.assertEqual(result["status"], "failed_open")
            record = json.loads(
                (
                    traces
                    / "p1-request-1"
                    / "v12"
                    / "p1_canary.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(record["status"], "failed_open")
            self.assertFalse(record["artifact_complete"])
            self.assertIsInstance(record["started_at"], str)
            self.assertIsInstance(record["finished_at"], str)

    def test_success_summary_is_json_serializable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            now = datetime.now(timezone.utc)
            request_input = P1RequestInput(
                request_id="p1-request-1",
                source="alertmanager",
                raw_payload={},
                normalized_event={},
                event_count=1,
                family="interface_status_or_flap",
                alert_status="firing",
            )
            audit = SimpleNamespace(
                status=ShadowStatus.COMPLETED,
                reason="shadow_completed",
                error_code=None,
                started_at=now,
                finished_at=now,
                duration_ms=0,
                legacy_preserved=True,
                fail_open_to_legacy=True,
                legacy_notification_count=1,
            )
            summary = _summary_for_audit(
                settings=settings(),
                request_input=request_input,
                audit=audit,
                trace_root=root / "traces",
            )
            self.assertIsInstance(summary["started_at"], str)
            self.assertIsInstance(summary["finished_at"], str)
            path = AtomicJsonWriter(root / "output").write_json(
                "p1_canary.json",
                summary,
            )
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                loaded["started_at"],
                now.isoformat(),
            )


class P1ObservationTests(unittest.TestCase):
    def write_record(
        self,
        root: Path,
        request_id: str,
        **updates,
    ):
        payload = {
            "schema_version": P1_SCHEMA_VERSION,
            "activation_id": "p1-test",
            "request_id": request_id,
            "family": "interface_status_or_flap",
            "status": "completed",
            "duration_ms": 100,
            "judge_status": "partial",
            "missing_evidence": ["logs", "knowledge"],
            "fallback_to_legacy": False,
            "artifact_complete": True,
            "notification_count_delta": 0,
            "second_card_sent": False,
            "production_card_replaced": False,
            "external_calls": {
                "production_glm": False,
                "prometheus_mcp": False,
                "netmiko_mcp": False,
                "evidence_mcp": False,
                "ops_es_api": False,
                "analytics_mcp": False,
                "fastmcp": False,
                "elasticsearch_direct": False,
                "notification": False,
            },
        }
        payload.update(updates)
        directory = root / request_id / "v12"
        directory.mkdir(parents=True)
        (directory / "p1_canary.json").write_text(
            json.dumps(payload),
            encoding="utf-8",
        )

    def test_empty_observations(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = collect_p1_observations(
                trace_root=temporary,
                activation_id="p1-test",
            )
            self.assertEqual(result["record_count"], 0)

    def test_completed_observation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_record(root, "p1-request-1")
            result = collect_p1_observations(
                trace_root=root,
                activation_id="p1-test",
            )
            self.assertEqual(result["completed_count"], 1)
            self.assertEqual(result["failed_open_count"], 0)
            self.assertEqual(result["success_rate"], 1.0)

    def test_activation_filter(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_record(
                root,
                "p1-request-1",
                activation_id="other",
            )
            result = collect_p1_observations(
                trace_root=root,
                activation_id="p1-test",
            )
            self.assertEqual(result["record_count"], 0)

    def test_missing_distribution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_record(root, "p1-request-1")
            result = collect_p1_observations(
                trace_root=root,
                activation_id="p1-test",
            )
            self.assertEqual(
                result["missing_evidence_distribution"],
                {"knowledge": 1, "logs": 1},
            )

    def test_external_violation_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_record(
                root,
                "p1-request-1",
                external_calls={"production_glm": True},
            )
            result = collect_p1_observations(
                trace_root=root,
                activation_id="p1-test",
            )
            self.assertEqual(
                result["external_call_violation_count"],
                1,
            )

    def test_notification_regression_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_record(
                root,
                "p1-request-1",
                notification_count_delta=1,
            )
            result = collect_p1_observations(
                trace_root=root,
                activation_id="p1-test",
            )
            self.assertEqual(
                result["notification_regression_count"],
                1,
            )

    def test_incomplete_artifact_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_record(
                root,
                "p1-request-1",
                artifact_complete=False,
            )
            result = collect_p1_observations(
                trace_root=root,
                activation_id="p1-test",
            )
            self.assertEqual(
                result["artifact_incomplete_count"],
                1,
            )

    def test_average_duration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_record(
                root,
                "p1-request-1",
                duration_ms=100,
            )
            self.write_record(
                root,
                "p1-request-2",
                duration_ms=300,
            )
            result = collect_p1_observations(
                trace_root=root,
                activation_id="p1-test",
            )
            self.assertEqual(
                result["average_duration_ms"],
                200.0,
            )


class P1GateTests(unittest.TestCase):
    def healthy(self):
        return {
            "completed_count": 3,
            "failed_open_count": 0,
            "external_call_violation_count": 0,
            "notification_regression_count": 0,
            "artifact_incomplete_count": 0,
        }

    def test_healthy_gate_passes(self):
        result = evaluate_p1_gate(
            self.healthy(),
            minimum_completed=3,
        )
        self.assertEqual(result["status"], "passed")

    def test_minimum_completed_gate(self):
        value = self.healthy()
        value["completed_count"] = 2
        result = evaluate_p1_gate(
            value,
            minimum_completed=3,
        )
        self.assertIn(
            "minimum_completed_not_reached",
            result["violations"],
        )

    def test_failed_open_gate(self):
        value = self.healthy()
        value["failed_open_count"] = 1
        result = evaluate_p1_gate(
            value,
            minimum_completed=3,
        )
        self.assertIn(
            "failed_open_detected",
            result["violations"],
        )

    def test_external_call_gate(self):
        value = self.healthy()
        value["external_call_violation_count"] = 1
        result = evaluate_p1_gate(
            value,
            minimum_completed=3,
        )
        self.assertIn(
            "external_call_detected",
            result["violations"],
        )

    def test_notification_gate(self):
        value = self.healthy()
        value["notification_regression_count"] = 1
        result = evaluate_p1_gate(
            value,
            minimum_completed=3,
        )
        self.assertIn(
            "notification_regression_detected",
            result["violations"],
        )

    def test_artifact_gate(self):
        value = self.healthy()
        value["artifact_incomplete_count"] = 1
        result = evaluate_p1_gate(
            value,
            minimum_completed=3,
        )
        self.assertIn(
            "artifact_incomplete",
            result["violations"],
        )


# ===== Batch P1 sentinel regression begin =====
class P1AlertmanagerSentinelTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def payload(status="firing", ends_at="0001-01-01T00:00:00Z"):
        return {
            "receiver": "p1-test",
            "status": status,
            "alerts": [{
                "status": status,
                "labels": {
                    "alertname": "InterfaceDown",
                    "instance": "P1-TEST-SW",
                    "ip": "192.0.2.21",
                    "interface": "Ethernet1/1",
                },
                "annotations": {"summary": "Interface is down."},
                "startsAt": "2026-07-30T02:00:00+00:00",
                "endsAt": ends_at,
                "fingerprint": "p1sentinel001",
            }],
        }

    async def triage(self, payload):
        from netaiops.v12.agents.triage_agent import TriageAgent
        from netaiops.v12.execution_context import AgentInvocation
        from netaiops.v12.state_machine import OrchestrationState
        from netaiops.v12.status import AgentName
        return await TriageAgent(
            source="alertmanager",
            payload=payload,
            received_at=datetime(
                2026, 7, 30, 2, 0, 1, tzinfo=timezone.utc
            ),
        ).run(AgentInvocation(
            request_id="p1-sentinel-test",
            agent_name=AgentName.TRIAGE,
            orchestration_state=OrchestrationState.TRIAGE,
            prior_output_refs=(),
            prior_outputs={},
        ))

    async def test_firing_zero_end_is_ignored(self):
        from netaiops.v12.status import AgentStatus
        outcome = await self.triage(self.payload())
        self.assertNotEqual(outcome.status, AgentStatus.FAILED)
        self.assertIsNone(outcome.output["unified_event"]["ends_at"])
        self.assertIn(
            "ends_at_open_sentinel_ignored",
            {item.code for item in outcome.warnings},
        )

    async def test_resolved_real_end_is_preserved(self):
        from netaiops.v12.status import AgentStatus
        outcome = await self.triage(self.payload(
            status="resolved",
            ends_at="2026-07-30T02:05:00+00:00",
        ))
        self.assertNotEqual(outcome.status, AgentStatus.FAILED)
        self.assertEqual(
            outcome.output["unified_event"]["ends_at"],
            "2026-07-30T02:05:00Z",
        )
# ===== Batch P1 sentinel regression end =====

if __name__ == "__main__":
    unittest.main()
