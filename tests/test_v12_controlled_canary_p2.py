from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from netaiops.v12.p2_controlled_canary import (
    DEFAULT_ALLOWED_FAMILIES,
    P2CallKind,
    P2CallLedger,
    P2CanaryPolicy,
    P2ContractError,
    P2Settings,
    load_p2_settings,
    offline_contract_report,
)


def settings_dict(**updates):
    now = datetime.now(timezone.utc)
    value = {
        "schema_version": "v12-p2-controlled-canary-1",
        "activation_id": "p2-test",
        "enabled": False,
        "mode": "shadow",
        "fail_open_to_legacy": True,
        "notifications_use_v12": False,
        "logs_enabled": False,
        "knowledge_enabled": False,
        "metrics_real_calls_enabled": False,
        "device_real_calls_enabled": False,
        "rca_real_calls_enabled": False,
        "reuse_existing_evidence_before_real_call": True,
        "activated_at": now.isoformat(),
        "canary_window_minutes": 60,
        "max_canary_requests": 3,
        "minimum_completed_for_gate": 3,
        "allowed_families": list(DEFAULT_ALLOWED_FAMILIES),
        "total_timeout_seconds": 60,
        "metrics_timeout_seconds": 15,
        "device_timeout_seconds": 20,
        "rca_timeout_seconds": 25,
        "max_metrics_calls_per_request": 0,
        "max_device_calls_per_request": 0,
        "max_rca_calls_per_request": 0,
        "max_total_external_calls_per_request": 3,
        "promql_generation_allowed": False,
        "command_generation_allowed": False,
        "dsl_generation_allowed": False,
        "write_commands_allowed": False,
        "arbitrary_tool_selection_allowed": False,
        "automatic_followup_queries_allowed": False,
    }
    value.update(updates)
    return value


def load_dict(value):
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "p2.yaml"
        path.write_text(
            yaml.safe_dump(
                value,
                sort_keys=False,
                allow_unicode=True,
            ),
            encoding="utf-8",
        )
        return load_p2_settings(path)


def active_settings(**updates):
    value = settings_dict(
        enabled=True,
        metrics_real_calls_enabled=True,
        max_metrics_calls_per_request=1,
        activated_at=(
            datetime.now(timezone.utc)
            - timedelta(minutes=1)
        ).isoformat(),
    )
    value.update(updates)
    return load_dict(value)


class P2SettingsTests(unittest.TestCase):
    def test_example_shape_is_disabled(self):
        settings = load_dict(settings_dict())
        self.assertIsNotNone(settings)
        self.assertFalse(settings.enabled)
        self.assertFalse(settings.real_calls_enabled)

    def test_offline_report_has_no_external_calls(self):
        report = offline_contract_report(
            load_dict(settings_dict())
        )
        self.assertEqual(report["status"], "pass")
        self.assertFalse(any(report["external_calls"].values()))

    def test_unknown_key_is_rejected(self):
        value = settings_dict()
        value["unexpected"] = True
        with self.assertRaises(P2ContractError):
            load_dict(value)

    def test_secret_like_key_is_rejected(self):
        value = settings_dict()
        value["token"] = "not-allowed"
        with self.assertRaises(P2ContractError):
            load_dict(value)

    def test_unknown_family_is_rejected(self):
        with self.assertRaises(P2ContractError):
            load_dict(
                settings_dict(
                    allowed_families=[
                        "interface_status_or_flap",
                        "routing_neighbor_down",
                    ]
                )
            )

    def test_duplicate_family_is_rejected(self):
        with self.assertRaises(P2ContractError):
            load_dict(
                settings_dict(
                    allowed_families=[
                        "interface_status_or_flap",
                        "interface_status_or_flap",
                    ]
                )
            )

    def test_notifications_must_remain_disabled(self):
        with self.assertRaises(P2ContractError):
            load_dict(
                settings_dict(
                    notifications_use_v12=True
                )
            )

    def test_logs_and_knowledge_must_remain_disabled(self):
        with self.assertRaises(P2ContractError):
            load_dict(settings_dict(logs_enabled=True))
        with self.assertRaises(P2ContractError):
            load_dict(
                settings_dict(knowledge_enabled=True)
            )

    def test_generators_and_write_commands_are_rejected(self):
        fields = (
            "promql_generation_allowed",
            "command_generation_allowed",
            "dsl_generation_allowed",
            "write_commands_allowed",
            "arbitrary_tool_selection_allowed",
            "automatic_followup_queries_allowed",
        )
        for field in fields:
            with self.subTest(field=field):
                with self.assertRaises(P2ContractError):
                    load_dict(settings_dict(**{field: True}))

    def test_disabled_source_requires_zero_budget(self):
        with self.assertRaises(P2ContractError):
            load_dict(
                settings_dict(
                    max_device_calls_per_request=1
                )
            )

    def test_enabled_source_requires_one_call_budget(self):
        with self.assertRaises(P2ContractError):
            load_dict(
                settings_dict(
                    enabled=True,
                    metrics_real_calls_enabled=True,
                    max_metrics_calls_per_request=0,
                )
            )

    def test_enabled_requires_real_source(self):
        with self.assertRaises(P2ContractError):
            load_dict(settings_dict(enabled=True))

    def test_disabled_cannot_enable_real_source(self):
        with self.assertRaises(P2ContractError):
            load_dict(
                settings_dict(
                    metrics_real_calls_enabled=True,
                    max_metrics_calls_per_request=1,
                )
            )

    def test_max_canary_requests_is_three(self):
        with self.assertRaises(P2ContractError):
            load_dict(
                settings_dict(max_canary_requests=4)
            )


class P2PolicyTests(unittest.TestCase):
    def test_inactive_policy_denies(self):
        settings = load_dict(settings_dict())
        decision = P2CanaryPolicy(settings).evaluate(
            request_id="request-1",
            family="interface_status_or_flap",
            event_count=1,
            alert_status="firing",
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "runtime_inactive")

    def test_active_policy_allows_approved_firing_event(self):
        settings = active_settings()
        decision = P2CanaryPolicy(settings).evaluate(
            request_id="request-1",
            family="interface_status_or_flap",
            event_count=1,
            alert_status="firing",
        )
        self.assertTrue(decision.allowed)

    def test_policy_rejects_multi_event(self):
        settings = active_settings()
        decision = P2CanaryPolicy(settings).evaluate(
            request_id="request-1",
            family="interface_status_or_flap",
            event_count=2,
            alert_status="firing",
        )
        self.assertEqual(decision.reason, "single_event_required")

    def test_policy_rejects_resolved(self):
        settings = active_settings()
        decision = P2CanaryPolicy(settings).evaluate(
            request_id="request-1",
            family="interface_status_or_flap",
            event_count=1,
            alert_status="resolved",
        )
        self.assertEqual(
            decision.reason,
            "only_firing_is_allowed",
        )

    def test_policy_rejects_unapproved_family(self):
        settings = active_settings()
        decision = P2CanaryPolicy(settings).evaluate(
            request_id="request-1",
            family="routing_neighbor_down",
            event_count=1,
            alert_status="firing",
        )
        self.assertEqual(
            decision.reason,
            "family_not_allowlisted",
        )


class P2LedgerTests(unittest.TestCase):
    def test_one_metrics_call_can_be_reserved(self):
        settings = active_settings()
        ledger = P2CallLedger(
            settings=settings,
            request_id="request-1",
            family="interface_status_or_flap",
        )
        record = ledger.reserve(
            P2CallKind.METRICS,
            operation_id="metrics-fixed-plan",
            provider="fake-prometheus",
        )
        self.assertEqual(record.ordinal_total, 1)
        self.assertEqual(
            ledger.snapshot()["total_calls"],
            1,
        )

    def test_duplicate_or_second_metrics_call_is_rejected(self):
        settings = active_settings()
        ledger = P2CallLedger(
            settings=settings,
            request_id="request-1",
            family="interface_status_or_flap",
        )
        ledger.reserve(
            P2CallKind.METRICS,
            operation_id="metrics-fixed-plan",
            provider="fake-prometheus",
        )
        with self.assertRaises(P2ContractError):
            ledger.reserve(
                P2CallKind.METRICS,
                operation_id="metrics-fixed-plan-2",
                provider="fake-prometheus",
            )

    def test_disabled_device_call_is_rejected(self):
        settings = active_settings()
        ledger = P2CallLedger(
            settings=settings,
            request_id="request-1",
            family="interface_status_or_flap",
        )
        with self.assertRaises(P2ContractError):
            ledger.reserve(
                P2CallKind.DEVICE,
                operation_id="device-plan",
                provider="fake-netmiko",
            )

    def test_unapproved_family_is_rejected(self):
        settings = active_settings()
        ledger = P2CallLedger(
            settings=settings,
            request_id="request-1",
            family="routing_neighbor_down",
        )
        with self.assertRaises(P2ContractError):
            ledger.reserve(
                P2CallKind.METRICS,
                operation_id="metrics-fixed-plan",
                provider="fake-prometheus",
            )


if __name__ == "__main__":
    unittest.main()
