from __future__ import annotations

import asyncio
import copy
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from netaiops.v12.adapters.normalizer_adapter import (
    NormalizedEventSelectionError,
    NormalizerAdapter,
    UnsupportedAlertSourceError,
)
from netaiops.v12.agent_registry import AgentRegistry, AgentSpec
from netaiops.v12.agents.triage_agent import TriageAgent
from netaiops.v12.budget import BudgetPolicy
from netaiops.v12.execution_context import AgentInvocation, AgentOutcome
from netaiops.v12.orchestrator import DeterministicOrchestrator
from netaiops.v12.state_machine import OrchestrationState
from netaiops.v12.status import AgentName, AgentStatus


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = PROJECT_ROOT / "tests/fixtures/v12/triage"
FIXED_NOW = datetime(2026, 7, 15, 9, 0, tzinfo=timezone.utc)


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))


def invocation(
    request_id: str = "v12-triage-test",
    agent_name: AgentName = AgentName.TRIAGE,
) -> AgentInvocation:
    return AgentInvocation(
        request_id=request_id,
        agent_name=agent_name,
        orchestration_state=OrchestrationState.TRIAGE,
        prior_output_refs=(),
        prior_outputs={},
    )


def run_agent(
    fixture_name: str,
    *,
    source: str = "alertmanager",
    request_id: str = "v12-triage-test",
    event_index: int = 0,
) -> AgentOutcome:
    agent = TriageAgent(
        source=source,
        payload=load_fixture(fixture_name),
        event_index=event_index,
        received_at=FIXED_NOW,
    )
    return asyncio.run(agent.run(invocation(request_id)))


class NormalizerAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = NormalizerAdapter()

    def test_alertmanager_normalizer_is_reused(self) -> None:
        payload = load_fixture("alertmanager_cisco_interface.json")
        events = self.adapter.normalize("alertmanager", payload)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["source"], "alertmanager")
        self.assertEqual(events[0]["_v12_index"], 0)

    def test_elastic_normalizer_is_reused(self) -> None:
        payload = load_fixture("elastic_bgp_neighbor.json")
        events = self.adapter.normalize("elastic", payload)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["source"], "elastic")
        self.assertEqual(events[0]["_v12_document_id"], "elastic-doc-1")

    def test_alertmanager_metadata_is_attached(self) -> None:
        event = self.adapter.select_event(
            "alertmanager",
            load_fixture("alertmanager_resolved.json"),
        )
        self.assertEqual(event["_v12_fingerprint"], "resolved-interface-1")
        self.assertEqual(event["_v12_ends_at"], "2026-07-15T08:05:00+00:00")

    def test_payload_is_not_mutated(self) -> None:
        payload = load_fixture("alertmanager_cisco_interface.json")
        before = copy.deepcopy(payload)
        self.adapter.normalize("alertmanager", payload)
        self.assertEqual(payload, before)

    def test_unsupported_source_is_rejected(self) -> None:
        with self.assertRaises(UnsupportedAlertSourceError):
            self.adapter.normalize("webhook", {})

    def test_empty_result_is_rejected_by_select_event(self) -> None:
        with self.assertRaises(NormalizedEventSelectionError):
            self.adapter.select_event("alertmanager", {"alerts": []})

    def test_out_of_range_event_index_is_rejected(self) -> None:
        with self.assertRaises(NormalizedEventSelectionError):
            self.adapter.select_event(
                "alertmanager",
                load_fixture("alertmanager_cisco_interface.json"),
                event_index=2,
            )


class TriageAgentFixtureTests(unittest.TestCase):
    def assert_success_family(
        self,
        fixture_name: str,
        family: str,
        *,
        source: str = "alertmanager",
    ) -> dict:
        outcome = run_agent(fixture_name, source=source)
        self.assertIn(outcome.status, {AgentStatus.SUCCESS, AgentStatus.PARTIAL})
        event = outcome.output["unified_event"]
        self.assertEqual(event["schema_version"], "v12.1")
        self.assertEqual(event["family"], family)
        self.assertFalse(outcome.output["aggregation_performed"])
        self.assertTrue(outcome.output_refs[0].startswith("event://"))
        return event

    def test_cisco_interface_family(self) -> None:
        event = self.assert_success_family(
            "alertmanager_cisco_interface.json",
            "interface_status_or_flap",
        )
        self.assertEqual(event["alert_object"]["kind"], "interface")
        self.assertIn("Ethernet1/1", event["alert_object"]["name"])

    def test_cisco_hardware_family(self) -> None:
        event = self.assert_success_family(
            "alertmanager_cisco_hardware.json",
            "hardware_fan_abnormal",
        )
        self.assertEqual(event["alert_object"]["kind"], "hardware")

    def test_traffic_spike_family(self) -> None:
        event = self.assert_success_family(
            "alertmanager_traffic_spike.json",
            "interface_traffic_anomaly",
        )
        self.assertEqual(
            event["alert_object"]["attributes"]["aggregation_performed"],
            False,
        )

    def test_traffic_drop_family(self) -> None:
        event = self.assert_success_family(
            "alertmanager_traffic_drop.json",
            "interface_traffic_anomaly",
        )
        self.assertIn("突降", event["alert_name"])
        self.assertIn(
            "TenGigabitEthernet1/0/1",
            event["alert_object"]["name"],
        )

    def test_f5_family(self) -> None:
        event = self.assert_success_family(
            "alertmanager_f5_pool_member.json",
            "f5_pool_member_down",
        )
        self.assertEqual(event["device"]["vendor"].lower(), "f5")

    def test_fortigate_family(self) -> None:
        event = self.assert_success_family(
            "alertmanager_fortigate_cpu.json",
            "device_cpu_high",
        )
        self.assertEqual(event["device"]["vendor"].lower(), "fortigate")

    def test_elastic_family(self) -> None:
        event = self.assert_success_family(
            "elastic_bgp_neighbor.json",
            "bgp_neighbor_down",
            source="elastic",
        )
        self.assertEqual(event["source"], "elastic")

    def test_missing_fields_return_partial_valid_contract(self) -> None:
        outcome = run_agent("alertmanager_missing_fields.json")
        self.assertEqual(outcome.status, AgentStatus.PARTIAL)
        event = outcome.output["unified_event"]
        self.assertEqual(event["alert_name"], "unknown-alert")
        self.assertEqual(event["device"]["name"], "unknown-device")
        codes = {item.code for item in outcome.warnings}
        self.assertIn("alert_name_missing", codes)
        self.assertIn("device_identity_missing", codes)

    def test_no_device_ip_is_partial_but_keeps_hostname(self) -> None:
        outcome = run_agent("alertmanager_no_device_ip.json")
        self.assertEqual(outcome.status, AgentStatus.PARTIAL)
        event = outcome.output["unified_event"]
        self.assertEqual(event["device"]["name"], "SW-NO-IP")
        self.assertIsNone(event["device"]["ip"])
        self.assertIn(
            "hostname:SW-NO-IP",
            outcome.output["correlation_hints"],
        )

    def test_resolved_lifecycle_and_ends_at(self) -> None:
        event = self.assert_success_family(
            "alertmanager_resolved.json",
            "interface_status_or_flap",
        )
        self.assertEqual(event["alert_status"], "resolved")
        self.assertEqual(event["ends_at"], "2026-07-15T08:05:00Z")
        self.assertFalse(
            event["alert_object"]["attributes"]["auto_execute_allowed"]
        )

    def test_event_key_is_stable_across_lifecycle_change(self) -> None:
        payload = load_fixture("alertmanager_cisco_interface.json")
        firing = TriageAgent(
            source="alertmanager",
            payload=payload,
            received_at=FIXED_NOW,
        )
        resolved_payload = copy.deepcopy(payload)
        resolved_payload["alerts"][0]["status"] = "resolved"
        resolved = TriageAgent(
            source="alertmanager",
            payload=resolved_payload,
            received_at=FIXED_NOW,
        )
        first = asyncio.run(firing.run(invocation("stable-event-key")))
        second = asyncio.run(resolved.run(invocation("stable-event-key")))
        self.assertEqual(
            first.output["event_key"],
            second.output["event_key"],
        )

    def test_correlation_hints_are_unique(self) -> None:
        outcome = run_agent("alertmanager_cisco_interface.json")
        hints = outcome.output["correlation_hints"]
        self.assertEqual(len(hints), len(set(hints)))
        self.assertTrue(any(item.startswith("family:") for item in hints))
        self.assertTrue(any(item.startswith("event_key:") for item in hints))

    def test_authorization_label_is_redacted(self) -> None:
        payload = load_fixture("alertmanager_cisco_interface.json")
        payload["alerts"][0]["labels"]["authorization"] = "sample-value"
        agent = TriageAgent(
            source="alertmanager",
            payload=payload,
            received_at=FIXED_NOW,
        )
        outcome = asyncio.run(agent.run(invocation("redaction-test")))
        labels = outcome.output["unified_event"]["labels"]
        self.assertEqual(labels["authorization"], "[REDACTED]")

    def test_multi_alert_event_index_selection(self) -> None:
        payload = load_fixture("alertmanager_multi_alert.json")
        agent = TriageAgent(
            source="alertmanager",
            payload=payload,
            event_index=1,
            received_at=FIXED_NOW,
        )
        outcome = asyncio.run(agent.run(invocation("multi-alert-test")))
        self.assertIn(outcome.status, {AgentStatus.SUCCESS, AgentStatus.PARTIAL})
        self.assertEqual(
            outcome.output["unified_event"]["alert_name"],
            "Cisco Memory usage high",
        )


class TriageAgentBoundaryTests(unittest.TestCase):
    def test_wrong_agent_name_returns_failed(self) -> None:
        agent = TriageAgent(
            source="alertmanager",
            payload=load_fixture("alertmanager_cisco_interface.json"),
            received_at=FIXED_NOW,
        )
        outcome = asyncio.run(
            agent.run(invocation(agent_name=AgentName.STATIC_PLANNER))
        )
        self.assertEqual(outcome.status, AgentStatus.FAILED)
        self.assertEqual(outcome.errors[0].code, "triage_agent_name_mismatch")

    def test_naive_received_at_returns_failed(self) -> None:
        agent = TriageAgent(
            source="alertmanager",
            payload=load_fixture("alertmanager_cisco_interface.json"),
            received_at=datetime(2026, 7, 15, 9, 0),
        )
        outcome = asyncio.run(agent.run(invocation()))
        self.assertEqual(outcome.status, AgentStatus.FAILED)
        self.assertEqual(outcome.errors[0].code, "triage_received_at_naive")

    def test_unsupported_source_returns_failed(self) -> None:
        agent = TriageAgent(
            source="unknown",
            payload={},
            received_at=FIXED_NOW,
        )
        outcome = asyncio.run(agent.run(invocation()))
        self.assertEqual(outcome.status, AgentStatus.FAILED)
        self.assertEqual(outcome.errors[0].code, "triage_validation_failed")

    def test_empty_alerts_return_failed(self) -> None:
        agent = TriageAgent(
            source="alertmanager",
            payload={"alerts": []},
            received_at=FIXED_NOW,
        )
        outcome = asyncio.run(agent.run(invocation()))
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_raw_payload_ref_request_mismatch_returns_failed(self) -> None:
        agent = TriageAgent(
            source="alertmanager",
            payload=load_fixture("alertmanager_cisco_interface.json"),
            received_at=FIXED_NOW,
            raw_payload_ref="artifact://other-request/raw/payload",
        )
        outcome = asyncio.run(agent.run(invocation("current-request")))
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_naive_alert_timestamp_is_normalized_to_utc(self) -> None:
        payload = load_fixture("alertmanager_cisco_interface.json")
        payload["alerts"][0]["startsAt"] = "2026-07-15T08:00:00"
        agent = TriageAgent(
            source="alertmanager",
            payload=payload,
            received_at=FIXED_NOW,
        )
        outcome = asyncio.run(agent.run(invocation("naive-alert-time")))
        self.assertEqual(outcome.status, AgentStatus.PARTIAL)
        self.assertEqual(
            outcome.output["unified_event"]["occurred_at"],
            "2026-07-15T08:00:00Z",
        )

    def test_family_registry_is_called(self) -> None:
        agent = TriageAgent(
            source="alertmanager",
            payload=load_fixture("alertmanager_cisco_interface.json"),
            received_at=FIXED_NOW,
        )
        with patch(
            "netaiops.v12.agents.triage_agent.classify_family",
            return_value={
                "family": "generic_network_readonly",
                "family_confidence": "low",
                "match_source": "test",
                "match_reason": "test",
                "target_kind": "generic",
                "auto_execute_allowed": False,
                "target_scope": {},
            },
        ) as mocked:
            outcome = asyncio.run(agent.run(invocation("family-call-test")))
        mocked.assert_called_once()
        self.assertEqual(
            outcome.output["unified_event"]["family"],
            "generic_network_readonly",
        )

    def test_normalizer_adapter_is_called(self) -> None:
        class FakeAdapter:
            def __init__(self) -> None:
                self.called = False

            def select_event(self, source, payload, *, event_index=0):
                self.called = True
                return {
                    "source": "alertmanager",
                    "timestamp": "2026-07-15T08:00:00+00:00",
                    "alarm_type": "Interface down",
                    "status": "firing",
                    "hostname": "SW01",
                    "device_ip": "10.0.0.1",
                    "vendor": "cisco",
                    "object_type": "interface",
                    "object_name": "Ethernet1/1",
                    "raw_text": "interface Ethernet1/1 down",
                    "labels": {},
                    "annotations": {},
                }

        adapter = FakeAdapter()
        agent = TriageAgent(
            source="alertmanager",
            payload={},
            received_at=FIXED_NOW,
            adapter=adapter,
        )
        outcome = asyncio.run(agent.run(invocation("adapter-call-test")))
        self.assertTrue(adapter.called)
        self.assertIn(outcome.status, {AgentStatus.SUCCESS, AgentStatus.PARTIAL})

    def test_agent_source_has_no_external_client_imports(self) -> None:
        paths = (
            PROJECT_ROOT / "netaiops/v12/agents/triage_agent.py",
            PROJECT_ROOT / "netaiops/v12/adapters/normalizer_adapter.py",
        )
        forbidden = (
            "import requests",
            "import httpx",
            "import socket",
            "import subprocess",
            "urllib.request",
        )
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for value in forbidden:
                self.assertNotIn(value, text)

    def test_fixture_set_is_complete(self) -> None:
        expected = {
            "alertmanager_cisco_interface.json",
            "alertmanager_cisco_hardware.json",
            "alertmanager_traffic_spike.json",
            "alertmanager_traffic_drop.json",
            "alertmanager_f5_pool_member.json",
            "alertmanager_fortigate_cpu.json",
            "elastic_bgp_neighbor.json",
            "alertmanager_missing_fields.json",
            "alertmanager_no_device_ip.json",
            "alertmanager_resolved.json",
            "alertmanager_multi_alert.json",
        }
        actual = {path.name for path in FIXTURE_ROOT.glob("*.json")}
        self.assertEqual(actual, expected)

    def test_orchestrator_compatibility(self) -> None:
        class SuccessAgent:
            async def run(self, invocation):
                return AgentOutcome(status=AgentStatus.SUCCESS)

        registry = AgentRegistry()
        triage = TriageAgent(
            source="alertmanager",
            payload=load_fixture("alertmanager_cisco_interface.json"),
            received_at=FIXED_NOW,
        )
        for name in AgentName:
            registry.register(
                AgentSpec(
                    name=name,
                    agent=triage if name == AgentName.TRIAGE else SuccessAgent(),
                )
            )
        orchestrator = DeterministicOrchestrator(
            registry,
            budget_policy=BudgetPolicy(total_timeout_seconds=10),
        )
        result = orchestrator.run("triage-orchestrator-test")
        self.assertEqual(result.final_state.value, "completed")
        triage_output = result.outputs[AgentName.TRIAGE.value]
        self.assertFalse(triage_output["aggregation_performed"])


if __name__ == "__main__":
    unittest.main()
