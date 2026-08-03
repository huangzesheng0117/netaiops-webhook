from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from netaiops.v12.p2_real_canary import (
    DANGEROUS_COMMAND_RE,
    EXPECTED_CALL_KINDS,
    EXPECTED_TRACE_FILES,
    P2RealCanaryError,
    _compact_rca_prompt,
    _private_target_ip,
    _validate_mcp_endpoint,
    build_active_p2_settings,
    validate_mock_rca_fixture,
)
from netaiops.v12.schema_validator import build_evidence_ref


class P2RealBoundaryTests(unittest.TestCase):
    def test_active_settings_enable_exact_three_sources(self):
        settings = build_active_p2_settings("p2-test")
        self.assertTrue(settings.enabled)
        self.assertTrue(settings.metrics_real_calls_enabled)
        self.assertTrue(settings.device_real_calls_enabled)
        self.assertTrue(settings.rca_real_calls_enabled)
        self.assertFalse(settings.logs_enabled)
        self.assertFalse(settings.knowledge_enabled)
        self.assertFalse(settings.notifications_use_v12)
        self.assertEqual(
            settings.max_total_external_calls_per_request,
            3,
        )

    def test_real_settings_allow_one_call_per_source(self):
        settings = build_active_p2_settings("p2-test")
        self.assertEqual(
            settings.max_metrics_calls_per_request,
            1,
        )
        self.assertEqual(
            settings.max_device_calls_per_request,
            1,
        )
        self.assertEqual(
            settings.max_rca_calls_per_request,
            1,
        )

    def test_expected_call_kinds_are_exact(self):
        self.assertEqual(
            [item.value for item in EXPECTED_CALL_KINDS],
            [
                "prometheus_mcp",
                "netmiko_mcp",
                "glm_rca",
            ],
        )

    def test_private_target_ip_accepts_production_range(self):
        self.assertTrue(_private_target_ip("10.191.97.137"))

    def test_private_target_ip_rejects_test_net_and_loopback(self):
        self.assertFalse(_private_target_ip("192.0.2.10"))
        self.assertFalse(_private_target_ip("127.0.0.1"))

    def test_prometheus_endpoint_is_exact(self):
        _validate_mcp_endpoint(
            "http://10.191.97.137:10001/sse",
            expected_port=10001,
            label="Prometheus MCP",
        )

    def test_netmiko_endpoint_is_exact(self):
        _validate_mcp_endpoint(
            "http://10.191.97.137:10000/sse",
            expected_port=10000,
            label="Netmiko MCP",
        )

    def test_unapproved_mcp_endpoint_is_rejected(self):
        values = (
            "http://10.191.97.137:10002/mcp",
            "http://127.0.0.1:10001/sse",
            "http://user:pass@10.191.97.137:10001/sse",
        )
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(P2RealCanaryError):
                    _validate_mcp_endpoint(
                        value,
                        expected_port=10001,
                        label="Prometheus MCP",
                    )

    def test_dangerous_commands_are_rejected(self):
        commands = (
            "configure terminal",
            "clear counters",
            "reload",
            "show interface ; reload",
            "show interface && clear counters",
            "sudo show interface",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertIsNotNone(
                    DANGEROUS_COMMAND_RE.search(command)
                )

    def test_readonly_show_command_not_matched_as_dangerous(self):
        self.assertIsNone(
            DANGEROUS_COMMAND_RE.search(
                "show interface Ethernet1/1"
            )
        )

    def test_trace_contract_contains_p2_files(self):
        self.assertIn("p2_canary.json", EXPECTED_TRACE_FILES)
        self.assertIn(
            "shadow_integration.json",
            EXPECTED_TRACE_FILES,
        )
        self.assertNotIn(
            "p1_canary.json",
            EXPECTED_TRACE_FILES,
        )


class P2RCAContractTests(unittest.TestCase):
    def test_mock_fixture_uses_valid_evidence_ref(self):
        request_id = "p2-test-request"
        reference = build_evidence_ref(
            request_id,
            "device",
            "fixture-1",
        )
        payload = validate_mock_rca_fixture(
            request_id=request_id,
            evidence_ref=reference,
        )
        self.assertEqual(
            payload["candidates"][0][
                "supporting_evidence_refs"
            ],
            [reference],
        )

    def test_mock_fixture_rejects_foreign_ref(self):
        reference = build_evidence_ref(
            "foreign-request",
            "device",
            "fixture-1",
        )
        with self.assertRaises(P2RealCanaryError):
            validate_mock_rca_fixture(
                request_id="p2-test-request",
                evidence_ref=reference,
            )

    def test_mock_fixture_caps_confidence(self):
        request_id = "p2-test-request"
        reference = build_evidence_ref(
            request_id,
            "metrics",
            "fixture-1",
        )
        payload = validate_mock_rca_fixture(
            request_id=request_id,
            evidence_ref=reference,
            confidence_cap=0.4,
        )
        self.assertLessEqual(
            payload["candidates"][0]["confidence"],
            0.4,
        )

    def test_rca_prompt_has_frozen_boundaries(self):
        request_id = "p2-test-request"
        reference = build_evidence_ref(
            request_id,
            "device",
            "fixture-1",
        )
        prompt = _compact_rca_prompt(
            event={
                "alert_name": "InterfaceTrafficDrop",
                "family": "interface_traffic_anomaly",
                "device": {"ip": "10.0.0.1"},
                "alert_object": {
                    "kind": "interface",
                    "name": "Ethernet1/1",
                },
                "labels": {},
                "annotations": {},
            },
            bundle={
                "evidence": {
                    "metrics": {
                        "status": "no_data",
                        "summary": "no data",
                        "facts": {},
                        "scope": {},
                        "reason": "no_data",
                        "evidence_refs": [],
                    },
                    "device": {
                        "status": "success",
                        "summary": "device success",
                        "facts": {},
                        "scope": {},
                        "reason": None,
                        "evidence_refs": [reference],
                    },
                    "logs": {
                        "status": "not_available",
                        "summary": "disabled",
                        "facts": {},
                        "scope": {},
                        "reason": "not approved",
                        "evidence_refs": [],
                    },
                }
            },
            judge={
                "status": "partial",
                "rca_allowed": True,
                "confidence_cap": 0.65,
                "missing_required_sources": ["metrics"],
                "missing_optional_sources": [
                    "logs",
                    "knowledge",
                ],
                "evidence_refs": [reference],
                "conflicts": [],
            },
        )
        self.assertIn(reference, prompt)
        self.assertIn("不得调用工具", prompt)
        self.assertIn("confidence_cap=0.65", prompt)


if __name__ == "__main__":
    unittest.main()
