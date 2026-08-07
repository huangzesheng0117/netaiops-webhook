from __future__ import annotations

import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from netaiops.degraded_delivery import (
    run_blocked_safe_delivery,
    should_run_blocked_safe_delivery,
)
from netaiops.interface_target_guard import (
    apply_interface_guard_to_policy,
    apply_interface_target_guard,
)
from netaiops.processor import (
    extract_notify_result_from_pipeline_result,
    maybe_run_v12_primary_independent,
)
from netaiops.review_builder import (
    build_conclusion,
    build_recommendations,
)


class InterfaceTargetGuardTests(unittest.TestCase):
    def test_cjk_alert_text_is_not_accepted_as_interface(self):
        scope, candidates, guard = apply_interface_target_guard(
            event={
                "family": "interface_packet_loss_or_discards_high",
                "alarm_type": "错包数-入向",
                "object_name": "错包数-入向",
            },
            family_result={
                "family": "interface_packet_loss_or_discards_high",
            },
            target_scope={
                "interface": "错包数-入向",
                "ifName": "错包数-入向",
            },
            execution_candidates=[
                {
                    "order": 1,
                    "command": "show interface 错包数-入向",
                }
            ],
        )
        self.assertEqual(scope["interface"], "")
        self.assertEqual(candidates, [])
        self.assertEqual(guard["status"], "blocked")
        self.assertEqual(
            guard["policy_reason"],
            "interface_target_invalid",
        )

        policy = apply_interface_guard_to_policy(
            {
                "auto_confirm_allowed": True,
                "reasons": [],
                "checked_items": {},
            },
            guard,
        )
        self.assertFalse(policy["auto_confirm_allowed"])
        self.assertIn(
            "interface_target_invalid",
            policy["reasons"],
        )

    def test_valid_interface_and_command_are_preserved(self):
        scope, candidates, guard = apply_interface_target_guard(
            event={
                "family": "interface_or_link_utilization_high",
                "alarm_type": "链路利用率高",
                "object_name": "GigabitEthernet2/0/2",
            },
            family_result={
                "family": "interface_or_link_utilization_high",
            },
            target_scope={"interface": "GigabitEthernet2/0/2"},
            execution_candidates=[
                {
                    "order": 1,
                    "command": "show interface GigabitEthernet2/0/2",
                }
            ],
        )
        self.assertEqual(
            scope["interface"],
            "GigabitEthernet2/0/2",
        )
        self.assertEqual(len(candidates), 1)
        self.assertEqual(guard["status"], "valid")


class DegradedDeliveryTests(unittest.TestCase):
    def test_vendor_block_is_eligible_for_degraded_delivery(self):
        decision = should_run_blocked_safe_delivery(
            {
                "policy_result": {
                    "auto_confirm_allowed": False,
                    "reasons": ["vendor_not_supported"],
                }
            }
        )
        self.assertTrue(decision["eligible"])

    def test_duplicate_throttle_does_not_bypass_suppression(self):
        decision = should_run_blocked_safe_delivery(
            {
                "policy_result": {
                    "auto_confirm_allowed": False,
                    "reasons": [
                        "vendor_not_supported",
                        "cooldown_duplicate_alert",
                    ],
                }
            }
        )
        self.assertFalse(decision["eligible"])
        self.assertEqual(
            decision["reason"],
            "delivery_suppressed_by_alert_throttle",
        )

    def test_blocked_safe_delivery_posts_empty_command_callback(self):
        calls = []

        def fake_sender(**kwargs):
            calls.append(kwargs)
            return {
                "status_code": 200,
                "response_text": json.dumps(
                    {
                        "notify_result": {
                            "ok": True,
                            "sent": True,
                        }
                    }
                ),
            }

        with tempfile.TemporaryDirectory() as temporary:
            result = run_blocked_safe_delivery(
                "20260805_120000_000001_testabcd",
                {
                    "target_scope": {"device_ip": "10.0.0.1"},
                    "classification": {},
                    "playbook": {},
                    "family_result": {
                        "family": "interface_status_or_flap",
                    },
                    "capability_plan": {},
                    "execution_source": "playbook",
                    "readonly_only": True,
                    "guard_result": {"all_readonly": True},
                    "policy_result": {
                        "auto_confirm_allowed": False,
                        "reasons": ["vendor_not_supported"],
                    },
                },
                base_dir=Path(temporary),
                callback_sender=fake_sender,
            )
        self.assertTrue(result["invoked"])
        self.assertEqual(len(calls), 1)
        payload = calls[0]["payload"]
        self.assertEqual(payload["command_results"], [])
        self.assertTrue(payload["blocked_safe"]["active"])


class ReviewBlockedSafeTests(unittest.TestCase):
    def test_review_explains_device_evidence_was_not_executed(self):
        execution = {
            "blocked_safe": {
                "active": True,
                "reason_codes": [
                    "vendor_not_supported",
                    "interface_target_invalid",
                ],
            },
            "execution_status": "failed",
        }
        conclusion = build_conclusion(
            execution,
            {
                "total": 0,
                "completed": 0,
                "failed": 0,
                "partial": 0,
                "hard_error": 0,
            },
            "interface_status_or_flap",
        )
        recommendations = build_recommendations(
            execution,
            {
                "total": 0,
                "completed": 0,
                "failed": 0,
                "partial": 0,
                "hard_error": 0,
            },
            "interface_status_or_flap",
        )
        self.assertEqual(
            conclusion["review_status"],
            "needs_attention",
        )
        self.assertIn("安全门禁", conclusion["conclusion"])
        self.assertTrue(recommendations)


class IndependentV12EntryTests(unittest.TestCase):
    def test_notify_result_is_extracted_from_callback_response(self):
        pipeline_result = {
            "ok": True,
            "result": {
                "degraded_delivery_result": {
                    "callback_result": {
                        "response_text": json.dumps(
                            {
                                "notify_result": {
                                    "ok": True,
                                    "sent": True,
                                }
                            }
                        )
                    }
                }
            },
        }
        notify = extract_notify_result_from_pipeline_result(
            pipeline_result
        )
        self.assertEqual(notify["sent"], True)

    def test_independent_entry_runs_even_for_failed_pipeline_result(self):
        calls = []

        def fake_primary(**kwargs):
            calls.append(kwargs)
            return {
                "status": "failed_open",
                "reason": "synthetic",
            }

        result = maybe_run_v12_primary_independent(
            "20260805_120000_000001_testabcd",
            {
                "ok": False,
                "result": None,
                "error": "pipeline stopped",
            },
            primary_runner=fake_primary,
        )
        self.assertEqual(result["status"], "failed_open")
        self.assertEqual(len(calls), 1)


class PipelineIntegrationTests(unittest.TestCase):
    def test_pipeline_routes_policy_block_to_degraded_delivery(self):
        import netaiops.pipeline as pipeline

        plan = {
            "plan_file": "/tmp/test.plan.json",
            "plan_data": {
                "request_id": "test-request",
                "plan_status": "generated",
                "policy_result": {
                    "auto_confirm_allowed": False,
                    "reasons": ["vendor_not_supported"],
                },
            },
        }
        fake_prom = types.ModuleType(
            "netaiops.prometheus_runtime_sidecar"
        )
        fake_prom.run_prometheus_evidence_sidecar_for_plan_result = (
            lambda **kwargs: {
                "ok": True,
                "plan_result": plan,
            }
        )
        with patch.dict(
            "sys.modules",
            {
                "netaiops.prometheus_runtime_sidecar": fake_prom,
            },
        ), patch.object(
            pipeline,
            "generate_plan_for_request_id",
            return_value=plan,
        ), patch.object(
            pipeline,
            "run_blocked_safe_delivery",
            return_value={"eligible": True, "invoked": True},
        ) as degraded, patch.object(
            pipeline,
            "get_request_summary",
            return_value={},
        ):
            result = pipeline.run_pipeline_for_request_id(
                "test-request",
                auto_confirm=True,
                auto_dispatch=True,
            )
        degraded.assert_called_once()
        self.assertTrue(
            result["degraded_delivery_result"]["invoked"]
        )


if __name__ == "__main__":
    unittest.main()
