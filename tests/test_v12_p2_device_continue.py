from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType

from netaiops.v12.adapters.prometheus_evidence_adapter import (
    NormalizedPrometheusEvidence,
)
from netaiops.v12.contracts import ContractNotice
from netaiops.v12.execution_context import AgentOutcome
from netaiops.v12.p2_device_continue import (
    PINNED_COMMAND,
    PINNED_COMMAND_SHA256,
    P2ContinueError,
    _redact_text,
    adjust_plan_for_continuation,
    deserialize_outcome,
    remap_metrics_outcome,
    sanitize_device_target,
    serialize_outcome,
)
from netaiops.v12.p2_real_canary import P2CanarySample
from netaiops.v12.schema_validator import build_contract_ref
from netaiops.v12.status import (
    AgentStatus,
    EvidenceStatus,
)


def sample() -> P2CanarySample:
    return P2CanarySample(
        original_request_id="20260727_145842_790277_86d84bf2",
        source="alertmanager",
        family="interface_status_or_flap",
        raw_payload={"alerts": [{}]},
        normalized_event={},
        legacy_plan={},
        target_scope={
            "vendor": "CISCO",
            "platform": "",
            "hostname": "10.186.96.51:9116",
            "instance": "10.186.96.51:9116",
            "device_ip": "10.187.251.61",
            "ip": "10.187.251.61",
            "interface": "Ethernet1/1",
            "if_name": "Ethernet1/1",
            "ifName": "Ethernet1/1",
            "object_name": "uplink",
            "job": "SW-CISCO-NXOS-OOB-EMC",
        },
        command_candidate={
            "command": PINNED_COMMAND,
            "readonly": True,
            "timeout_sec": 30,
        },
        metrics_profile="interface_down_status",
        metrics_query_name="oper_status",
        metrics_target={},
        raw_path="/tmp/raw.json",
        normalized_path="/tmp/normalized.json",
        plan_path="/tmp/plan.json",
        discovery_mode="historical_real_target",
    )


class TargetSanitizationTests(unittest.TestCase):
    def test_exporter_hostname_is_removed(self):
        target = sanitize_device_target(sample())
        self.assertNotIn("hostname", target)

    def test_exporter_instance_is_removed(self):
        target = sanitize_device_target(sample())
        self.assertNotIn("instance", target)

    def test_real_device_ip_and_interface_remain(self):
        target = sanitize_device_target(sample())
        self.assertEqual(target["device_ip"], "10.187.251.61")
        self.assertEqual(target["interface"], "Ethernet1/1")

    def test_pinned_command_hash_is_exact(self):
        import hashlib

        self.assertEqual(
            hashlib.sha256(
                PINNED_COMMAND.encode("utf-8")
            ).hexdigest(),
            PINNED_COMMAND_SHA256,
        )


class MetricsReuseTests(unittest.TestCase):
    def normalized(self, status=EvidenceStatus.SUCCESS):
        return NormalizedPrometheusEvidence(
            status=status,
            summary="existing metrics",
            facts=MappingProxyType({"query_name": "oper_status"}),
            scope=MappingProxyType(
                {
                    "device_ip": "10.187.251.61",
                    "if_name": "Ethernet1/1",
                }
            ),
            evidence_refs=(),
            warnings=(),
            errors=(),
            collected_at=datetime.now(timezone.utc),
            reason=None,
            source_artifact_ref=build_contract_ref(
                "artifact",
                "20260727_145842_790277_86d84bf2",
                "prometheus_evidence",
                "fixture",
            ),
            source_filename="fixture.prometheus_evidence.json",
        )

    def test_reused_metrics_has_no_external_call(self):
        outcome = remap_metrics_outcome(
            request_id="p2-continue-test",
            original_request_id=(
                "20260727_145842_790277_86d84bf2"
            ),
            normalized=self.normalized(),
        )
        self.assertEqual(outcome.external_calls, ())
        self.assertFalse(
            outcome.output["prometheus_mcp_called"]
        )

    def test_reused_success_has_new_request_ref(self):
        outcome = remap_metrics_outcome(
            request_id="p2-continue-test",
            original_request_id=(
                "20260727_145842_790277_86d84bf2"
            ),
            normalized=self.normalized(),
        )
        self.assertTrue(
            all(
                "p2-continue-test" in ref
                for ref in outcome.output_refs
            )
        )

    def test_no_data_reuse_is_partial_agent_status(self):
        outcome = remap_metrics_outcome(
            request_id="p2-continue-test",
            original_request_id=(
                "20260727_145842_790277_86d84bf2"
            ),
            normalized=self.normalized(
                EvidenceStatus.NO_DATA
            ),
        )
        self.assertEqual(outcome.status, AgentStatus.PARTIAL)


class ContinuationPlanTests(unittest.TestCase):
    def test_metrics_becomes_optional_device_remains_required(self):
        plan_ref = build_contract_ref(
            "plan",
            "p2-continue-test",
            "evidence_plan",
            "fixture",
        )
        outcome = AgentOutcome(
            status=AgentStatus.SUCCESS,
            output_refs=(plan_ref,),
            output={
                "evidence_plan": {
                    "schema_version": "v12.1",
                    "request_id": "p2-continue-test",
                    "plan_ref": plan_ref,
                    "planner_mode": "deterministic",
                    "family": "interface_status_or_flap",
                    "selected_playbook": None,
                    "sources": [
                        {
                            "source": "metrics",
                            "required": True,
                            "capability_ids": [],
                            "existing_artifact_refs": [],
                            "constraints": {},
                            "max_items": 1,
                        },
                        {
                            "source": "device",
                            "required": True,
                            "capability_ids": [],
                            "existing_artifact_refs": [],
                            "constraints": {},
                            "max_items": 1,
                        },
                    ],
                    "readonly_only": True,
                    "created_at": (
                        datetime.now(timezone.utc).isoformat()
                    ),
                }
            },
        )
        metrics_ref = build_contract_ref(
            "artifact",
            "p2-continue-test",
            "existing_metrics_artifact",
            "fixture",
        )
        adjusted = adjust_plan_for_continuation(
            outcome,
            metrics_ref,
        )
        sources = {
            item["source"]: item
            for item in adjusted.output[
                "evidence_plan"
            ]["sources"]
        }
        self.assertFalse(sources["metrics"]["required"])
        self.assertTrue(sources["device"]["required"])


class CheckpointTests(unittest.TestCase):
    def test_outcome_round_trip(self):
        notice = ContractNotice(
            code="fixture_warning",
            message="fixture",
            stage="test",
        )
        outcome = AgentOutcome(
            status=AgentStatus.PARTIAL,
            output_refs=(),
            output={"ok": True},
            warnings=(notice,),
        )
        restored = deserialize_outcome(
            serialize_outcome(
                outcome,
                checkpoint_kind="fixture",
                real_call_count=0,
            )
        )
        self.assertEqual(restored.status, AgentStatus.PARTIAL)
        self.assertEqual(restored.output["ok"], True)

    def test_error_text_is_redacted(self):
        value = _redact_text(
            "token=abc123 password:hello failure"
        )
        self.assertNotIn("abc123", value)
        self.assertNotIn("hello", value)

    def test_wrong_device_is_rejected(self):
        value = sample()
        bad = replace(
            value,
            target_scope={
                **dict(value.target_scope),
                "device_ip": "10.0.0.1",
            },
        )
        with self.assertRaises(P2ContinueError):
            sanitize_device_target(bad)

    def test_wrong_interface_is_rejected(self):
        value = sample()
        bad = replace(
            value,
            target_scope={
                **dict(value.target_scope),
                "interface": "Ethernet1/2",
                "if_name": "Ethernet1/2",
                "ifName": "Ethernet1/2",
            },
        )
        with self.assertRaises(P2ContinueError):
            sanitize_device_target(bad)


if __name__ == "__main__":
    unittest.main()
