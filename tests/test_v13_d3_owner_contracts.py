from __future__ import annotations

import unittest
from datetime import datetime, timezone

from pydantic import ValidationError

from netaiops.v12.status import EvidenceStatus
from netaiops.v13.evidence_owner_contracts import EvidenceOwnerRecord


class OwnerContractTests(unittest.TestCase):
    def _base(self):
        return dict(
            request_id="d3-contract-1",
            family="interface_status_or_flap",
            source="metrics",
            owner="metrics_agent",
            capability="query_prometheus_metric_window",
            dedup_key="a" * 64,
            checkpoint_ref="artifact://d3-contract-1/capability_checkpoint/cp-aaaaaaaaaaaaaaaaaaaaaaaa",
            decision_action="executed",
            evidence_status=EvidenceStatus.SUCCESS,
            external_call_performed=True,
            completed_at=datetime.now(timezone.utc),
        )

    def test_metrics_owner_record(self):
        record = EvidenceOwnerRecord(**self._base())
        self.assertEqual(record.owner_count, 1)
        self.assertFalse(record.legacy_active_call_allowed)
        self.assertFalse(record.write_command_executed)

    def test_wrong_owner_rejected(self):
        raw = self._base()
        raw["owner"] = "device_agent"
        with self.assertRaises(ValidationError):
            EvidenceOwnerRecord(**raw)

    def test_nonapproved_family_rejected(self):
        raw = self._base()
        raw["family"] = "device_cpu_high"
        with self.assertRaises(ValidationError):
            EvidenceOwnerRecord(**raw)

    def test_extra_raw_promql_field_rejected(self):
        raw = self._base()
        raw["promql"] = "up"
        with self.assertRaises(ValidationError):
            EvidenceOwnerRecord(**raw)

    def test_extra_raw_command_field_rejected(self):
        raw = self._base()
        raw["command"] = "show version"
        with self.assertRaises(ValidationError):
            EvidenceOwnerRecord(**raw)


if __name__ == "__main__":
    unittest.main()
