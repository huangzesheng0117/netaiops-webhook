from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from netaiops.v13.triage_owner import TriageOwner
from netaiops.v13.triage_shadow import (
    TriageShadowError,
    TriageShadowStore,
    compare_with_persisted_legacy,
    legacy_family_from_plan,
)


NOW = datetime(2026, 8, 27, 2, 0, 0, tzinfo=timezone.utc)


def unified_payload(request_id: str, source: str, family: str) -> dict:
    return {
        "schema_version": "v12.1",
        "request_id": request_id,
        "event_id": "evt-shadow",
        "source": source,
        "alert_status": "firing",
        "alert_name": "fixture-alert",
        "occurred_at": "2026-08-27T01:00:00+00:00",
        "received_at": NOW.isoformat(),
        "ends_at": None,
        "device": {"name":"fixture-sw","ip":"10.0.0.1","vendor":"cisco","platform":"iosxe","site":"fixture"},
        "alert_object": {
            "kind": "interface" if family.startswith("interface_") else "generic",
            "name": "Gi0/1",
            "identifier": "Gi0/1",
            "attributes": {
                "family_confidence": "high" if family != "generic_network_readonly" else "low",
                "match_source": "fixture",
                "match_reason": f"fixture:{family}",
                "auto_execute_allowed": family != "generic_network_readonly",
                "target_scope": {"device_ip":"10.0.0.1"},
                "aggregation_performed": False,
            },
        },
        "labels": {"severity":"warning"},
        "annotations": {},
        "family": family,
        "event_key": f"event:fixture:{family}",
        "correlation_hints": [f"family:{family}"],
        "raw_payload_ref": None,
    }


def runner_for(family: str):
    async def runner(request_id, source, event, received_at):
        from netaiops.v12.status import AgentStatus
        return (
            AgentStatus.SUCCESS,
            {"unified_event": unified_payload(request_id, source, family)},
            (f"event://{request_id}/unified_alert/evt-shadow",),
        )
    return runner


class TriageShadowTests(unittest.TestCase):
    def record(self, family: str, request_id: str = "d2-shadow"):
        owner = TriageOwner(
            triage_runner=runner_for(family),
            utcnow=lambda: NOW,
        )
        return owner.classify_normalized(
            request_id=request_id,
            source="alertmanager",
            normalized_event={"family": family, "device_ip": "10.0.0.1"},
            mode="shadow",
        )

    def test_legacy_family_prefers_family_result(self):
        self.assertEqual(
            legacy_family_from_plan(
                {
                    "family_result": {"family": "interface_status_or_flap"},
                    "classification": {"family": "bgp_neighbor_down"},
                }
            ),
            "interface_status_or_flap",
        )

    def test_legacy_family_falls_back_to_classification_field(self):
        self.assertEqual(
            legacy_family_from_plan(
                {"classification": {"family": "interface_status_or_flap"}}
            ),
            "interface_status_or_flap",
        )

    def test_migrated_match_is_acceptable(self):
        record = self.record("interface_status_or_flap")
        comparison = compare_with_persisted_legacy(
            record,
            {"family_result": {"family": "interface_status_or_flap"}},
            utcnow=lambda: NOW,
        )
        self.assertEqual(comparison.comparison, "match")
        self.assertTrue(comparison.migration_acceptable)
        self.assertFalse(comparison.legacy_reclassification_performed)
        self.assertFalse(comparison.external_calls_performed)

    def test_migrated_mismatch_is_not_acceptable(self):
        record = self.record("interface_status_or_flap")
        comparison = compare_with_persisted_legacy(
            record,
            {"family_result": {"family": "interface_or_link_utilization_high"}},
            utcnow=lambda: NOW,
        )
        self.assertEqual(comparison.comparison, "mismatch")
        self.assertFalse(comparison.migration_acceptable)

    def test_migrated_missing_legacy_is_not_acceptable(self):
        record = self.record("interface_status_or_flap")
        comparison = compare_with_persisted_legacy(
            record,
            {},
            utcnow=lambda: NOW,
        )
        self.assertEqual(comparison.comparison, "legacy_missing")
        self.assertFalse(comparison.migration_acceptable)

    def test_non_migrated_fallback_remains_acceptable_for_shadow_boundary(self):
        record = self.record("bgp_neighbor_down")
        comparison = compare_with_persisted_legacy(
            record,
            {"family_result": {"family": "bgp_neighbor_down"}},
            utcnow=lambda: NOW,
        )
        self.assertEqual(comparison.comparison, "match")
        self.assertTrue(comparison.migration_acceptable)
        self.assertEqual(comparison.routing_action, "fallback_legacy")

    def test_store_writes_only_v13_trace_files(self):
        record = self.record("interface_status_or_flap", "d2-store")
        comparison = compare_with_persisted_legacy(
            record,
            {"family_result": {"family": "interface_status_or_flap"}},
            utcnow=lambda: NOW,
        )
        with tempfile.TemporaryDirectory(prefix="v13-d2-store-") as temp:
            root = Path(temp)
            store = TriageShadowStore(root)
            files = store.persist(record, comparison)
            self.assertEqual(
                set(files),
                {"triage_owner.json", "triage_shadow_comparison.json"},
            )
            directory = root / "d2-store" / "v13"
            self.assertTrue((directory / "triage_owner.json").is_file())
            self.assertTrue((directory / "triage_shadow_comparison.json").is_file())
            self.assertFalse((root / "d2-store" / "v12").exists())
            loaded = store.load("d2-store")
            self.assertEqual(
                loaded["triage_owner.json"]["classification_owner"], "triage"
            )
            self.assertEqual(
                loaded["triage_owner.json"]["classification_engine"],
                "family_registry",
            )

    def test_store_is_deterministically_replaceable_for_same_request(self):
        record = self.record("interface_status_or_flap", "d2-idempotent")
        comparison = compare_with_persisted_legacy(
            record,
            {"family_result": {"family": "interface_status_or_flap"}},
            utcnow=lambda: NOW,
        )
        with tempfile.TemporaryDirectory(prefix="v13-d2-idempotent-") as temp:
            store = TriageShadowStore(temp)
            store.persist(record, comparison)
            first = store.load("d2-idempotent")
            store.persist(record, comparison)
            second = store.load("d2-idempotent")
            self.assertEqual(first, second)

    def test_store_refuses_symlink_request_directory(self):
        record = self.record("interface_status_or_flap", "d2-symlink")
        comparison = compare_with_persisted_legacy(
            record,
            {"family_result": {"family": "interface_status_or_flap"}},
            utcnow=lambda: NOW,
        )
        with tempfile.TemporaryDirectory(prefix="v13-d2-symlink-") as temp:
            root = Path(temp)
            target = root / "real"
            target.mkdir()
            (root / "d2-symlink").symlink_to(target, target_is_directory=True)
            store = TriageShadowStore(root)
            with self.assertRaises(TriageShadowError):
                store.persist(record, comparison)

    def test_trace_does_not_copy_raw_payload(self):
        record = self.record("interface_status_or_flap", "d2-no-raw")
        comparison = compare_with_persisted_legacy(
            record,
            {"family_result": {"family": "interface_status_or_flap"}},
            utcnow=lambda: NOW,
        )
        payload = json.dumps(record.model_dump(mode="json"), ensure_ascii=False)
        # A contract-level raw_payload_ref field is allowed; the raw payload
        # body itself must never be copied into the D2 trace.
        self.assertNotIn('"raw_payload":', payload)
        self.assertNotIn("SHOULD-NOT-BE-PERSISTED", payload)
        self.assertFalse(comparison.external_calls_performed)


if __name__ == "__main__":
    unittest.main()
