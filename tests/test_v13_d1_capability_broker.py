from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path

from netaiops.v12.contracts import EvidenceEnvelope
from netaiops.v12.schema_validator import build_evidence_ref
from netaiops.v12.status import EvidenceSource, EvidenceStatus
from netaiops.v13.capability_broker import (
    CapabilityExecutionError,
    EvidenceCapabilityBroker,
)
from netaiops.v13.capability_contracts import (
    DeviceCapabilityRequest,
    MetricsCapabilityRequest,
    build_capability_dedup_key,
    build_plan_fingerprint,
    build_template_fingerprint,
)


class V13D1CapabilityBrokerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="v13-d1-broker-")
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def metrics(self, request_id="req-v13-d1-metrics", **overrides):
        data = {
            "request_id": request_id,
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

    def device(self, request_id="req-v13-d1-device", **overrides):
        data = {
            "request_id": request_id,
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

    @staticmethod
    def success_envelope(request):
        evidence_ref = build_evidence_ref(
            request.request_id,
            request.source,
            f"ev-{build_capability_dedup_key(request)[:16]}",
        )
        return EvidenceEnvelope(
            schema_version="v12.1",
            request_id=request.request_id,
            source=EvidenceSource(request.source),
            evidence_kind="evidence",
            status=EvidenceStatus.SUCCESS,
            summary="fixture success",
            facts={"fixture": True},
            scope={"family": request.family},
            evidence_refs=[evidence_ref],
            collected_at="2026-08-26T06:00:00+00:00",
        )

    @staticmethod
    def no_data_envelope(request):
        return EvidenceEnvelope(
            schema_version="v12.1",
            request_id=request.request_id,
            source=EvidenceSource(request.source),
            evidence_kind="evidence",
            status=EvidenceStatus.NO_DATA,
            summary="fixture no data",
            facts={"matched_total": 0},
            scope={"family": request.family},
            collected_at="2026-08-26T06:00:00+00:00",
        )

    @staticmethod
    def unavailable_envelope(request):
        return EvidenceEnvelope(
            schema_version="v12.1",
            request_id=request.request_id,
            source=EvidenceSource(request.source),
            evidence_kind="evidence",
            status=EvidenceStatus.NOT_AVAILABLE,
            summary="fixture not available",
            facts={},
            scope={"family": request.family},
            collected_at="2026-08-26T06:00:00+00:00",
            reason="fixture_source_not_available",
        )

    def test_same_request_metrics_executes_once_then_reuses(self):
        broker = EvidenceCapabilityBroker(self.root)
        request = self.metrics()
        calls = {"count": 0}

        def executor(req, attempt):
            calls["count"] += 1
            return self.success_envelope(req)

        first = broker.execute(request, executor)
        second = broker.execute(request, executor)
        self.assertEqual(calls["count"], 1)
        self.assertTrue(first.external_call_performed)
        self.assertEqual(second.action, "reused_checkpoint")
        self.assertFalse(second.external_call_performed)

    def test_same_request_device_executes_once_then_reuses(self):
        broker = EvidenceCapabilityBroker(self.root)
        request = self.device()
        calls = {"count": 0}

        def executor(req, attempt):
            calls["count"] += 1
            return self.success_envelope(req)

        broker.execute(request, executor)
        broker.execute(request, executor)
        self.assertEqual(calls["count"], 1)

    def test_same_target_different_family_is_not_deduped(self):
        broker = EvidenceCapabilityBroker(self.root)
        calls = {"count": 0}
        first = self.metrics(request_id="req-v13-family")
        second = self.metrics(
            request_id="req-v13-family",
            family="interface_traffic_anomaly",
        )

        def executor(req, attempt):
            calls["count"] += 1
            return self.success_envelope(req)

        broker.execute(first, executor)
        broker.execute(second, executor)
        self.assertEqual(calls["count"], 2)

    def test_same_family_different_plan_is_not_deduped(self):
        broker = EvidenceCapabilityBroker(self.root)
        calls = {"count": 0}
        first = self.metrics(request_id="req-v13-plan")
        second = self.metrics(
            request_id="req-v13-plan",
            plan_fingerprint=build_plan_fingerprint({"plan": "B"}),
        )

        def executor(req, attempt):
            calls["count"] += 1
            return self.success_envelope(req)

        broker.execute(first, executor)
        broker.execute(second, executor)
        self.assertEqual(calls["count"], 2)

    def test_success_checkpoint_is_reused_after_broker_restart(self):
        request = self.metrics(request_id="req-v13-restart")
        calls = {"count": 0}

        def executor(req, attempt):
            calls["count"] += 1
            return self.success_envelope(req)

        EvidenceCapabilityBroker(self.root).execute(request, executor)
        second = EvidenceCapabilityBroker(self.root).execute(request, executor)
        self.assertEqual(calls["count"], 1)
        self.assertEqual(second.action, "reused_checkpoint")

    def test_failed_is_retried_once_then_exhausted_and_reused(self):
        broker = EvidenceCapabilityBroker(self.root)
        request = self.metrics(request_id="req-v13-failed", max_attempts=2)
        calls = {"count": 0}

        def executor(req, attempt):
            calls["count"] += 1
            raise CapabilityExecutionError("failed", "fixture_failed", "fixture failed")

        first = broker.execute(request, executor)
        second = broker.execute(request, executor)
        third = broker.execute(request, executor)
        self.assertEqual(calls["count"], 2)
        self.assertFalse(first.checkpoint.terminal)
        self.assertTrue(second.checkpoint.terminal)
        self.assertEqual(third.action, "reused_checkpoint")
        self.assertFalse(third.external_call_performed)

    def test_timeout_has_one_bounded_retry_then_success(self):
        broker = EvidenceCapabilityBroker(self.root)
        request = self.metrics(request_id="req-v13-timeout", max_attempts=2)
        calls = {"count": 0}

        def executor(req, attempt):
            calls["count"] += 1
            if attempt == 1:
                raise CapabilityExecutionError("timeout", "fixture_timeout", "fixture timeout")
            return self.success_envelope(req)

        first = broker.execute(request, executor)
        second = broker.execute(request, executor)
        third = broker.execute(request, executor)
        self.assertEqual(first.checkpoint.status, "timeout")
        self.assertEqual(second.action, "retried")
        self.assertEqual(second.checkpoint.status, "success")
        self.assertEqual(third.action, "reused_checkpoint")
        self.assertEqual(calls["count"], 2)

    def test_no_data_is_terminal_and_not_normalized_to_success(self):
        broker = EvidenceCapabilityBroker(self.root)
        request = self.metrics(request_id="req-v13-no-data")
        calls = {"count": 0}

        def executor(req, attempt):
            calls["count"] += 1
            return self.no_data_envelope(req)

        first = broker.execute(request, executor)
        second = broker.execute(request, executor)
        self.assertEqual(first.checkpoint.status, "no_data")
        self.assertEqual(first.checkpoint.envelope.status, EvidenceStatus.NO_DATA)
        self.assertEqual(second.action, "reused_checkpoint")
        self.assertEqual(calls["count"], 1)

    def test_not_available_is_terminal_and_preserves_reason(self):
        broker = EvidenceCapabilityBroker(self.root)
        request = self.metrics(request_id="req-v13-not-available")
        calls = {"count": 0}

        def executor(req, attempt):
            calls["count"] += 1
            return self.unavailable_envelope(req)

        first = broker.execute(request, executor)
        broker.execute(request, executor)
        self.assertEqual(first.checkpoint.status, "not_available")
        self.assertEqual(
            first.checkpoint.envelope.reason,
            "fixture_source_not_available",
        )
        self.assertEqual(calls["count"], 1)

    def test_policy_blocked_does_not_call_executor(self):
        broker = EvidenceCapabilityBroker(self.root)
        request = self.device(
            request_id="req-v13-policy",
            safety_policy_allowed=False,
            safety_policy_reasons=["fixture_block"],
        )
        calls = {"count": 0}

        def executor(req, attempt):
            calls["count"] += 1
            return self.success_envelope(req)

        first = broker.execute(request, executor)
        second = broker.execute(request, executor)
        self.assertEqual(calls["count"], 0)
        self.assertEqual(first.action, "policy_blocked")
        self.assertEqual(first.checkpoint.status, "policy_blocked")
        self.assertEqual(first.checkpoint.envelope.status, EvidenceStatus.SKIPPED)
        self.assertEqual(second.action, "reused_checkpoint")

    def test_concurrent_same_key_is_serialized_to_one_execution(self):
        request = self.metrics(request_id="req-v13-concurrent")
        calls = {"count": 0}
        calls_lock = threading.Lock()
        decisions = []
        errors = []

        def executor(req, attempt):
            with calls_lock:
                calls["count"] += 1
            time.sleep(0.1)
            return self.success_envelope(req)

        def worker():
            try:
                broker = EvidenceCapabilityBroker(self.root)
                decisions.append(broker.execute(request, executor))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        self.assertFalse(errors)
        self.assertEqual(calls["count"], 1)
        self.assertEqual(len(decisions), 2)
        self.assertEqual(
            sorted(item.action for item in decisions),
            ["executed", "reused_checkpoint"],
        )


if __name__ == "__main__":
    unittest.main()
