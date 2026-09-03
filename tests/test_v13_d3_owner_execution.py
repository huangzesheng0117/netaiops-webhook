from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from netaiops.v12.contracts import EvidenceEnvelope
from netaiops.v12.schema_validator import build_evidence_ref
from netaiops.v12.status import EvidenceSource, EvidenceStatus
from netaiops.v13.capability_broker import EvidenceCapabilityBroker
from netaiops.v13.capability_contracts import (
    DeviceCapabilityRequest,
    MetricsCapabilityRequest,
    build_plan_fingerprint,
    build_template_fingerprint,
)
from netaiops.v13.evidence_owners import DeviceEvidenceOwner, MetricsEvidenceOwner
from netaiops.v13.legacy_call_fence import LegacyCallFence


class OwnerExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.broker = EvidenceCapabilityBroker(root / "checkpoints")
        self.fence = LegacyCallFence(root / "trace")
        self.plan_fp = build_plan_fingerprint({"plan": "fixture"})

    def tearDown(self):
        self.tmp.cleanup()

    def _envelope(self, request, source, counter):
        counter[source] = counter.get(source, 0) + 1
        return EvidenceEnvelope(
            schema_version="v12.1",
            request_id=request.request_id,
            source=EvidenceSource(source),
            evidence_kind="evidence",
            status=EvidenceStatus.SUCCESS,
            summary="fixture",
            facts={"external": False},
            scope={"fixture": True},
            evidence_refs=[
                build_evidence_ref(request.request_id, source, f"fixture-{source}")
            ],
            collected_at=datetime.now(timezone.utc),
        )

    def test_metrics_owner_executes_once_then_reuses(self):
        req = MetricsCapabilityRequest(
            request_id="d3-metrics-1",
            family="interface_status_or_flap",
            capability="query_prometheus_metric_window",
            target={"device_ip": "10.0.0.1", "interface": "Gi1/0/1"},
            plan_fingerprint=self.plan_fp,
            template_fingerprint=build_template_fingerprint("prometheus:fixture"),
            query_template_id="prometheus:fixture",
        )
        calls = {}
        owner = MetricsEvidenceOwner(broker=self.broker, fence=self.fence)
        first = owner.execute(req, lambda r, a: self._envelope(r, "metrics", calls))
        second = owner.execute(req, lambda r, a: self._envelope(r, "metrics", calls))
        self.assertTrue(first.owner_record.external_call_performed)
        self.assertFalse(second.owner_record.external_call_performed)
        self.assertEqual(second.owner_record.decision_action, "reused_checkpoint")
        self.assertEqual(calls.get("metrics"), 1)
        self.assertEqual(self.fence.legacy_action(req.request_id, "metrics"), "skip_duplicate")
        self.assertEqual(first.owner_record.owner, "metrics_agent")
        self.assertEqual(first.owner_record.owner_count, 1)

    def test_device_owner_executes_once_then_reuses(self):
        req = DeviceCapabilityRequest(
            request_id="d3-device-1",
            family="interface_status_or_flap",
            capability="show_interface_detail",
            target={"device_ip": "10.0.0.1", "interface": "Gi1/0/1"},
            plan_fingerprint=self.plan_fp,
            template_fingerprint=build_template_fingerprint("playbook:fixture"),
            command_template_id="playbook:fixture",
            playbook_id="fixture_playbook",
            safety_policy_allowed=True,
        )
        calls = {}
        owner = DeviceEvidenceOwner(broker=self.broker, fence=self.fence)
        first = owner.execute(req, lambda r, a: self._envelope(r, "device", calls))
        second = owner.execute(req, lambda r, a: self._envelope(r, "device", calls))
        self.assertTrue(first.owner_record.external_call_performed)
        self.assertFalse(second.owner_record.external_call_performed)
        self.assertEqual(calls.get("device"), 1)
        self.assertEqual(self.fence.legacy_action(req.request_id, "device"), "skip_duplicate")
        self.assertEqual(first.owner_record.owner, "device_agent")

    def test_device_policy_block_never_executes(self):
        req = DeviceCapabilityRequest(
            request_id="d3-device-blocked",
            family="interface_status_or_flap",
            capability="show_interface_detail",
            target={"device_ip": "10.0.0.1", "interface": "INVALID"},
            plan_fingerprint=self.plan_fp,
            template_fingerprint=build_template_fingerprint("playbook:blocked"),
            command_template_id="playbook:blocked",
            playbook_id="fixture_playbook",
            safety_policy_allowed=False,
            safety_policy_reasons=["invalid_interface"],
        )
        calls = {"device": 0}
        owner = DeviceEvidenceOwner(broker=self.broker, fence=self.fence)
        result = owner.execute(req, lambda r, a: (_ for _ in ()).throw(AssertionError("must not run")))
        self.assertEqual(result.owner_record.decision_action, "policy_blocked")
        self.assertFalse(result.owner_record.external_call_performed)
        self.assertEqual(calls["device"], 0)
        self.assertEqual(result.owner_record.evidence_status, EvidenceStatus.SKIPPED)
        self.assertEqual(self.fence.legacy_action(req.request_id, "device"), "skip_duplicate")

    def test_different_plan_fingerprint_is_different_identity(self):
        common = dict(
            request_id="d3-plan-fp",
            family="interface_status_or_flap",
            capability="query_prometheus_metric_window",
            target={"device_ip": "10.0.0.1", "interface": "Gi1/0/1"},
            template_fingerprint=build_template_fingerprint("prometheus:fixture"),
            query_template_id="prometheus:fixture",
        )
        req1 = MetricsCapabilityRequest(plan_fingerprint=build_plan_fingerprint({"v": 1}), **common)
        req2 = MetricsCapabilityRequest(plan_fingerprint=build_plan_fingerprint({"v": 2}), **common)
        calls = {}
        owner = MetricsEvidenceOwner(broker=self.broker, fence=self.fence)
        one = owner.execute(req1, lambda r, a: self._envelope(r, "metrics", calls))
        two = owner.execute(req2, lambda r, a: self._envelope(r, "metrics", calls))
        self.assertNotEqual(one.owner_record.dedup_key, two.owner_record.dedup_key)
        self.assertEqual(calls.get("metrics"), 2)


if __name__ == "__main__":
    unittest.main()
