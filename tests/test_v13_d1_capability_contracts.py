from __future__ import annotations

import unittest

from pydantic import ValidationError

from netaiops.v13.capability_contracts import (
    DeviceCapabilityRequest,
    MetricsCapabilityRequest,
    build_capability_dedup_key,
    build_plan_fingerprint,
    build_template_fingerprint,
)


class V13D1CapabilityContractsTest(unittest.TestCase):
    def metrics(self, **overrides):
        data = {
            "request_id": "req-v13-d1-contract",
            "family": "interface_status_or_flap",
            "capability": "query_prometheus_metric_window",
            "target": {"device_ip": "10.0.0.1", "interface": "Gi1/0/1"},
            "plan_fingerprint": build_plan_fingerprint({"plan": "A"}),
            "template_fingerprint": build_template_fingerprint(
                "interface_status_window",
                {"lookback_minutes": 5, "step_seconds": 60},
            ),
            "query_template_id": "interface_status_window",
        }
        data.update(overrides)
        return MetricsCapabilityRequest(**data)

    def device(self, **overrides):
        data = {
            "request_id": "req-v13-d1-device-contract",
            "family": "interface_status_or_flap",
            "capability": "show_interface_detail",
            "target": {"device_ip": "10.0.0.1", "interface": "Gi1/0/1"},
            "plan_fingerprint": build_plan_fingerprint({"plan": "A"}),
            "template_fingerprint": build_template_fingerprint(
                "show_interface_detail",
                {"interface": "Gi1/0/1"},
            ),
            "command_template_id": "show_interface_detail",
            "playbook_id": "interface_status_or_flap",
        }
        data.update(overrides)
        return DeviceCapabilityRequest(**data)

    def test_metrics_contract_forbids_raw_promql(self):
        payload = self.metrics().model_dump(mode="json")
        payload["query"] = "up"
        with self.assertRaises(ValidationError):
            MetricsCapabilityRequest(**payload)

    def test_device_contract_forbids_raw_command(self):
        payload = self.device().model_dump(mode="json")
        payload["command"] = "show version"
        with self.assertRaises(ValidationError):
            DeviceCapabilityRequest(**payload)

    def test_device_contract_freezes_readonly_and_generation_flags(self):
        payload = self.device().model_dump(mode="json")
        payload["readonly_only"] = False
        with self.assertRaises(ValidationError):
            DeviceCapabilityRequest(**payload)

        payload = self.device().model_dump(mode="json")
        payload["command_generation_allowed"] = True
        with self.assertRaises(ValidationError):
            DeviceCapabilityRequest(**payload)

    def test_dedup_key_is_stable_across_target_key_order(self):
        first = self.metrics(target={"device_ip": "10.0.0.1", "interface": "Gi1/0/1"})
        second = self.metrics(target={"interface": "Gi1/0/1", "device_ip": "10.0.0.1"})
        self.assertEqual(
            build_capability_dedup_key(first),
            build_capability_dedup_key(second),
        )

    def test_dedup_key_changes_with_family(self):
        first = self.metrics(family="interface_status_or_flap")
        second = self.metrics(family="interface_traffic_anomaly")
        self.assertNotEqual(
            build_capability_dedup_key(first),
            build_capability_dedup_key(second),
        )

    def test_dedup_key_changes_with_plan_fingerprint(self):
        first = self.metrics(plan_fingerprint=build_plan_fingerprint({"plan": "A"}))
        second = self.metrics(plan_fingerprint=build_plan_fingerprint({"plan": "B"}))
        self.assertNotEqual(
            build_capability_dedup_key(first),
            build_capability_dedup_key(second),
        )

    def test_sensitive_target_values_are_sanitized(self):
        request = self.metrics(
            target={
                "device_ip": "10.0.0.1",
                "password": "must-not-persist",
            }
        )
        self.assertEqual(request.target["password"], "[REDACTED]")


if __name__ == "__main__":
    unittest.main()
