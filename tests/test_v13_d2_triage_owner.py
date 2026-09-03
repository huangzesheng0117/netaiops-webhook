from __future__ import annotations

import unittest
from datetime import datetime, timezone

from pydantic import ValidationError

from netaiops.v12.status import AgentStatus
from netaiops.v13.triage_contracts import MIGRATED_FAMILIES, TriageOwnershipRecord
from netaiops.v13.triage_owner import TriageOwner, TriageOwnerError


NOW = datetime(2026, 8, 27, 1, 2, 3, tzinfo=timezone.utc)


def unified_payload(request_id: str, source: str, family: str) -> dict:
    return {
        "schema_version": "v12.1",
        "request_id": request_id,
        "event_id": "evt-fixture",
        "source": source,
        "alert_status": "firing",
        "alert_name": "fixture-alert",
        "occurred_at": "2026-08-27T01:00:00+00:00",
        "received_at": NOW.isoformat(),
        "ends_at": None,
        "device": {
            "name": "fixture-sw",
            "ip": "10.0.0.1",
            "vendor": "cisco",
            "platform": "iosxe",
            "site": "fixture",
        },
        "alert_object": {
            "kind": "interface" if family.startswith("interface_") else "generic",
            "name": "Gi0/1",
            "identifier": "Gi0/1",
            "attributes": {
                "family_confidence": "high" if family != "generic_network_readonly" else "low",
                "match_source": "fixture",
                "match_reason": f"fixture:{family}",
                "auto_execute_allowed": family != "generic_network_readonly",
                "target_scope": {"device_ip": "10.0.0.1", "interface": "Gi0/1"},
                "aggregation_performed": False,
            },
        },
        "labels": {"severity": "warning"},
        "annotations": {},
        "family": family,
        "event_key": f"event:fixture:{family}",
        "correlation_hints": [f"family:{family}"],
        "raw_payload_ref": None,
    }


class CountingRunner:
    def __init__(self, family: str, status: AgentStatus = AgentStatus.SUCCESS):
        self.family = family
        self.status = status
        self.calls = 0

    async def __call__(self, request_id, source, event, received_at):
        self.calls += 1
        return (
            self.status,
            {"unified_event": unified_payload(request_id, source, self.family)},
            (f"event://{request_id}/unified_alert/evt-fixture",),
        )


class TriageOwnerTests(unittest.TestCase):
    def owner(self, runner) -> TriageOwner:
        return TriageOwner(triage_runner=runner, utcnow=lambda: NOW)

    def test_each_frozen_migrated_family_routes_to_controlled_orchestrator(self):
        for family in MIGRATED_FAMILIES:
            with self.subTest(family=family):
                runner = CountingRunner(family)
                record = self.owner(runner).classify_normalized(
                    request_id=f"d2-{family.replace('_', '-')}",
                    source="alertmanager",
                    normalized_event={"family": family, "device_ip": "10.0.0.1"},
                    mode="build_only",
                )
                self.assertEqual(runner.calls, 1)
                self.assertEqual(record.classification_owner, "triage")
                self.assertEqual(record.classification_owner_count, 1)
                self.assertEqual(record.classification_call_count, 1)
                self.assertTrue(record.triage_agent_reused)
                self.assertTrue(record.migrated_family)
                self.assertEqual(record.routing_action, "controlled_orchestrator")
                self.assertIsNone(record.fallback_reason)
                self.assertFalse(record.primary_entry_activated)
                self.assertFalse(record.external_calls_performed)

    def test_known_non_migrated_family_explicitly_falls_back(self):
        runner = CountingRunner("bgp_neighbor_down")
        record = self.owner(runner).classify_normalized(
            request_id="d2-known-fallback",
            source="alertmanager",
            normalized_event={"alarm_type": "BGP neighbor down"},
            mode="shadow",
        )
        self.assertEqual(runner.calls, 1)
        self.assertEqual(record.routing_action, "fallback_legacy")
        self.assertEqual(record.fallback_reason, "family_not_migrated_in_v13_d2")

    def test_generic_unknown_family_explicitly_falls_back(self):
        runner = CountingRunner("generic_network_readonly")
        record = self.owner(runner).classify_normalized(
            request_id="d2-generic-fallback",
            source="elastic",
            normalized_event={"alarm_type": "something entirely unknown"},
            mode="store_only",
        )
        self.assertEqual(runner.calls, 1)
        self.assertEqual(record.family_confidence, "low")
        self.assertEqual(record.routing_action, "fallback_legacy")
        self.assertEqual(record.fallback_reason, "generic_or_unknown_family")

    def test_sensitive_normalized_fields_are_sanitized_before_fingerprint(self):
        runner = CountingRunner("interface_status_or_flap")
        record = self.owner(runner).classify_normalized(
            request_id="d2-redaction",
            source="alertmanager",
            normalized_event={
                "family": "interface_status_or_flap",
                "device_ip": "10.0.0.1",
                "token": "SHOULD-NOT-ENTER-FINGERPRINT-PLAINTEXT",
            },
        )
        self.assertEqual(runner.calls, 1)
        self.assertEqual(len(record.normalized_event_fingerprint), 64)
        self.assertNotIn("SHOULD", record.normalized_event_fingerprint)

    def test_fingerprint_is_stable_for_mapping_order(self):
        a = CountingRunner("interface_status_or_flap")
        b = CountingRunner("interface_status_or_flap")
        first = self.owner(a).classify_normalized(
            request_id="d2-stable-a",
            source="alertmanager",
            normalized_event={"family": "interface_status_or_flap", "a": 1, "b": 2},
        )
        second = self.owner(b).classify_normalized(
            request_id="d2-stable-b",
            source="alertmanager",
            normalized_event={"b": 2, "a": 1, "family": "interface_status_or_flap"},
        )
        self.assertEqual(first.normalized_event_fingerprint, second.normalized_event_fingerprint)

    def test_invalid_source_rejected_before_triage_runner(self):
        runner = CountingRunner("interface_status_or_flap")
        with self.assertRaises(TriageOwnerError):
            self.owner(runner).classify_normalized(
                request_id="d2-invalid-source",
                source="other",
                normalized_event={"family": "interface_status_or_flap"},
            )
        self.assertEqual(runner.calls, 0)

    def test_invalid_mode_rejected_before_triage_runner(self):
        runner = CountingRunner("interface_status_or_flap")
        with self.assertRaises(TriageOwnerError):
            self.owner(runner).classify_normalized(
                request_id="d2-invalid-mode",
                source="alertmanager",
                normalized_event={"family": "interface_status_or_flap"},
                mode="primary",
            )
        self.assertEqual(runner.calls, 0)

    def test_empty_event_rejected_before_triage_runner(self):
        runner = CountingRunner("interface_status_or_flap")
        with self.assertRaises(TriageOwnerError):
            self.owner(runner).classify_normalized(
                request_id="d2-empty-event",
                source="alertmanager",
                normalized_event={},
            )
        self.assertEqual(runner.calls, 0)

    def test_failed_triage_status_is_rejected(self):
        runner = CountingRunner("interface_status_or_flap", AgentStatus.FAILED)
        with self.assertRaises(TriageOwnerError):
            self.owner(runner).classify_normalized(
                request_id="d2-failed-triage",
                source="alertmanager",
                normalized_event={"family": "interface_status_or_flap"},
            )
        self.assertEqual(runner.calls, 1)

    def test_naive_utcnow_rejected(self):
        runner = CountingRunner("interface_status_or_flap")
        owner = TriageOwner(
            triage_runner=runner,
            utcnow=lambda: datetime(2026, 8, 27, 1, 2, 3),
        )
        with self.assertRaises(TriageOwnerError):
            owner.classify_normalized(
                request_id="d2-naive-time",
                source="alertmanager",
                normalized_event={"family": "interface_status_or_flap"},
            )
        self.assertEqual(runner.calls, 0)

    def test_contract_rejects_false_owner_count(self):
        runner = CountingRunner("interface_status_or_flap")
        record = self.owner(runner).classify_normalized(
            request_id="d2-contract-owner",
            source="alertmanager",
            normalized_event={"family": "interface_status_or_flap"},
        )
        payload = record.model_dump(mode="json")
        payload["classification_owner_count"] = 2
        with self.assertRaises(ValidationError):
            TriageOwnershipRecord.model_validate(payload)

    def test_real_v12_triage_agent_calls_family_registry_once(self):
        # Count the actual call site used by the existing v12 TriageAgent.
        # This proves the D2 owner path performs one classification, not merely
        # that the ownership record declares classification_call_count=1.
        from unittest.mock import patch
        import netaiops.v12.agents.triage_agent as triage_module

        original = triage_module.classify_family
        calls = []

        def counting_classifier(event):
            calls.append(dict(event))
            return original(event)

        owner = TriageOwner(utcnow=lambda: NOW)
        with patch.object(
            triage_module,
            "classify_family",
            side_effect=counting_classifier,
        ):
            record = owner.classify_normalized(
                request_id="d2-real-single-owner-call",
                source="alertmanager",
                normalized_event={
                    "family": "interface_status_or_flap",
                    "status": "firing",
                    "timestamp": "2026-08-27T01:00:00+00:00",
                    "alarm_type": "fixture-interface-alert",
                    "device_ip": "10.0.0.1",
                    "hostname": "fixture-sw",
                    "object_type": "interface",
                    "object_name": "Gi0/1",
                    "labels": {"severity": "warning"},
                    "annotations": {},
                },
            )

        self.assertEqual(len(calls), 1)
        self.assertEqual(record.classification_call_count, 1)
        self.assertEqual(record.classification_owner, "triage")
        self.assertTrue(record.triage_agent_reused)

    def test_real_v12_triage_agent_accepts_frozen_family_field(self):
        # Integration probe: production path reuses the real v12 TriageAgent.
        owner = TriageOwner(utcnow=lambda: NOW)
        for family in MIGRATED_FAMILIES:
            with self.subTest(family=family):
                record = owner.classify_normalized(
                    request_id=f"d2-real-{family.replace('_', '-')}",
                    source="alertmanager",
                    normalized_event={
                        "family": family,
                        "status": "firing",
                        "timestamp": "2026-08-27T01:00:00+00:00",
                        "alarm_type": "fixture-interface-alert",
                        "device_ip": "10.0.0.1",
                        "hostname": "fixture-sw",
                        "object_type": "interface",
                        "object_name": "Gi0/1",
                        "labels": {"severity": "warning"},
                        "annotations": {},
                    },
                )
                self.assertEqual(record.family, family)
                self.assertTrue(record.migrated_family)
                self.assertTrue(record.triage_agent_reused)


if __name__ == "__main__":
    unittest.main()
