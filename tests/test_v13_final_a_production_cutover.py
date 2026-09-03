from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from netaiops.classifier import classify_event_from_family_result
from netaiops.v12.contracts import EvidenceEnvelope
from netaiops.v12.schema_validator import build_evidence_ref
from netaiops.v12.status import EvidenceSource, EvidenceStatus
from netaiops.v13.capability_broker import EvidenceCapabilityBroker
from netaiops.v13.capability_contracts import MetricsCapabilityRequest, build_plan_fingerprint, build_template_fingerprint
from netaiops.v13.evidence_owners import MetricsEvidenceOwner
from netaiops.v13.legacy_call_fence import LegacyCallFence
from netaiops.v13.production_control import (
    MIGRATED_FAMILIES,
    owner_active_for_family,
    triage_mounted,
    validate_release_control,
)


NOW = datetime(2026, 9, 2, 8, 0, 0, tzinfo=timezone.utc)


def control(mode: str, single_family: str | None = None) -> dict:
    allowed = []
    if mode == "single_family":
        allowed = [single_family]
    elif mode == "three_family":
        allowed = list(MIGRATED_FAMILIES)
    return {
        "schema_version": "v13-release-control-1",
        "activation_id": f"fixture-{mode}",
        "mode": mode,
        "single_family": single_family,
        "allowed_owner_families": allowed,
        "triage_mounted": mode != "disabled",
        "owner_real_calls_enabled": mode in {"single_family", "three_family"},
        "fail_open_to_legacy": True,
        "notifications_use_v12": False,
        "logs_enabled": False,
        "knowledge_enabled": False,
        "updated_at": NOW.isoformat(),
    }


class FinalAProductionContractTests(unittest.TestCase):
    def test_control_modes_keep_safe_v13_boundary(self):
        disabled = validate_release_control(control("disabled"))
        self.assertFalse(triage_mounted(disabled))
        self.assertFalse(any(owner_active_for_family(f, disabled) for f in MIGRATED_FAMILIES))

        triage = validate_release_control(control("triage_only"))
        self.assertTrue(triage_mounted(triage))
        self.assertFalse(any(owner_active_for_family(f, triage) for f in MIGRATED_FAMILIES))

        single = validate_release_control(control("single_family", MIGRATED_FAMILIES[0]))
        self.assertTrue(owner_active_for_family(MIGRATED_FAMILIES[0], single))
        self.assertFalse(owner_active_for_family(MIGRATED_FAMILIES[1], single))

        full = validate_release_control(control("three_family"))
        self.assertEqual(full["allowed_owner_families"], list(MIGRATED_FAMILIES))
        self.assertTrue(all(owner_active_for_family(f, full) for f in MIGRATED_FAMILIES))
        self.assertTrue(full["fail_open_to_legacy"])
        self.assertFalse(full["notifications_use_v12"])
        self.assertFalse(full["logs_enabled"])
        self.assertFalse(full["knowledge_enabled"])

    def test_control_rejects_notifications_owner_change(self):
        value = control("three_family")
        value["notifications_use_v12"] = True
        with self.assertRaises(ValueError):
            validate_release_control(value)

    def test_control_rejects_unapproved_family(self):
        value = control("single_family", MIGRATED_FAMILIES[0])
        value["single_family"] = "bgp_neighbor_down"
        value["allowed_owner_families"] = ["bgp_neighbor_down"]
        with self.assertRaises(ValueError):
            validate_release_control(value)

    def test_classifier_can_reuse_canonical_family_without_registry_call(self):
        event = {"vendor": "cisco", "source": "alertmanager", "alarm_type": "fixture"}
        family = {
            "family": "interface_status_or_flap",
            "legacy_playbook_type": "interface_flap",
            "family_confidence": "high",
            "match_reason": "fixture",
            "auto_execute_allowed": True,
        }
        with patch("netaiops.classifier.classify_family", side_effect=AssertionError("must not call")):
            result = classify_event_from_family_result(event, family)
        self.assertEqual(result["family"], "interface_status_or_flap")
        self.assertEqual(result["legacy_playbook_type"], "interface_flap")

    def test_owner_fence_is_active_before_real_executor_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            broker = EvidenceCapabilityBroker(root / "checkpoints")
            fence = LegacyCallFence(root / "trace")
            owner = MetricsEvidenceOwner(broker=broker, fence=fence, utcnow=lambda: NOW)
            request = MetricsCapabilityRequest(
                request_id="v13-final-a-fence",
                family="interface_status_or_flap",
                capability="query_prometheus_metric_window",
                target={"device_ip": "10.0.0.1", "interface": "Gi1/0/1"},
                plan_fingerprint=build_plan_fingerprint({"plan": "fixture"}),
                template_fingerprint=build_template_fingerprint("prometheus:fixture"),
                query_template_id="prometheus:fixture",
                max_attempts=1,
            )

            def executor(req, attempt):
                self.assertEqual(fence.legacy_action(req.request_id, "metrics"), "skip_duplicate")
                return EvidenceEnvelope(
                    schema_version="v12.1",
                    request_id=req.request_id,
                    source=EvidenceSource.METRICS,
                    evidence_kind="evidence",
                    status=EvidenceStatus.SUCCESS,
                    summary="fixture",
                    facts={"external": False},
                    scope={"fixture": True},
                    evidence_refs=[build_evidence_ref(req.request_id, "metrics", "fixture")],
                    collected_at=NOW,
                )

            result = owner.execute(request, executor)
            self.assertEqual(result.owner_record.decision_action, "executed")
            self.assertEqual(fence.legacy_action(request.request_id, "metrics"), "skip_duplicate")

    def test_owner_checkpoint_reuse_does_not_invoke_executor_twice(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            broker = EvidenceCapabilityBroker(root / "checkpoints")
            fence = LegacyCallFence(root / "trace")
            owner = MetricsEvidenceOwner(broker=broker, fence=fence, utcnow=lambda: NOW)
            request = MetricsCapabilityRequest(
                request_id="v13-final-a-reuse",
                family="interface_status_or_flap",
                capability="query_prometheus_metric_window",
                target={"device_ip": "10.0.0.1", "interface": "Gi1/0/1"},
                plan_fingerprint=build_plan_fingerprint({"plan": "fixture"}),
                template_fingerprint=build_template_fingerprint("prometheus:fixture"),
                query_template_id="prometheus:fixture",
                max_attempts=1,
            )
            calls = 0

            def executor(req, attempt):
                nonlocal calls
                calls += 1
                return EvidenceEnvelope(
                    schema_version="v12.1",
                    request_id=req.request_id,
                    source=EvidenceSource.METRICS,
                    evidence_kind="evidence",
                    status=EvidenceStatus.SUCCESS,
                    summary="fixture",
                    facts={"calls": calls},
                    scope={"fixture": True},
                    collected_at=NOW,
                )

            first = owner.execute(request, executor)
            second = owner.execute(request, executor)
            self.assertEqual(calls, 1)
            self.assertEqual(first.owner_record.decision_action, "executed")
            self.assertEqual(second.owner_record.decision_action, "reused_checkpoint")
            self.assertFalse(second.owner_record.external_call_performed)

    def test_source_mount_tokens_present(self):
        root = Path("/opt/netaiops-webhook")
        # In production this test runs from the installed project.  For package
        # review it also documents the exact cutover call sites that must exist.
        if not root.exists():
            self.skipTest("production project root unavailable")
        required = {
            "app.py": "_v13_mount_triage_safe",
            "netaiops/plan_builder.py": "load_canonical_family_result",
            "netaiops/pipeline.py": "run_metrics_owner_for_plan_result",
            "agent_runner/runner.py": "v13_device_owner_results_reused",
        }
        for rel, token in required.items():
            text = (root / rel).read_text(encoding="utf-8")
            self.assertIn(token, text, rel)


if __name__ == "__main__":
    unittest.main()
