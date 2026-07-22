from __future__ import annotations

import asyncio
import json
import os
import socket
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from netaiops.v12.adapters.device_evidence_adapter import (
    DeviceEvidenceAdapter,
    DeviceEvidenceAdapterError,
)
from netaiops.v12.agents.device_evidence_agent import DeviceEvidenceAgent
from netaiops.v12.contracts import EvidenceEnvelope, EvidencePlan, EvidenceSourcePlan
from netaiops.v12.execution_context import AgentInvocation
from netaiops.v12.state_machine import OrchestrationState
from netaiops.v12.status import AgentName, AgentStatus, EvidenceSource, EvidenceStatus


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = PROJECT_ROOT / "tests/fixtures/v12/device"
REQUEST_ID = "req-batch-g-001"
NOW = datetime(2026, 7, 22, 2, 0, tzinfo=timezone.utc)


def evidence_plan(
    *,
    request_id: str = REQUEST_ID,
    safety_allowed: bool = True,
    readonly_only: bool = True,
    command_generation_allowed: bool = False,
    include_device: bool = True,
    required: bool = True,
) -> dict:
    sources = [
        EvidenceSourcePlan(
            source=EvidenceSource.METRICS,
            required=False,
            constraints={
                "reuse_existing_evidence": True,
                "promql_generation_allowed": False,
            },
            max_items=1,
        ),
    ]
    if include_device:
        sources.append(
            EvidenceSourcePlan(
                source=EvidenceSource.DEVICE,
                required=required,
                capability_ids=["show_interface_detail"],
                constraints={
                    "readonly_only": readonly_only,
                    "command_generation_allowed": command_generation_allowed,
                    "safety_policy_allowed": safety_allowed,
                    "safety_policy_reasons": [] if safety_allowed else ["policy_blocked"],
                },
                max_items=5,
            )
        )
    sources.extend(
        [
            EvidenceSourcePlan(
                source=EvidenceSource.LOGS,
                required=False,
                constraints={"enabled": False, "reason": "logs_evidence_not_approved"},
                max_items=0,
            ),
            EvidenceSourcePlan(
                source=EvidenceSource.KNOWLEDGE,
                required=False,
                constraints={"enabled": False, "reason": "local_knowledge_base_not_built"},
                max_items=0,
            ),
        ]
    )
    return EvidencePlan(
        schema_version="v12.1",
        request_id=request_id,
        plan_ref=f"plan://{request_id}/evidence_plan/plan-g",
        planner_mode="deterministic",
        family="interface_status_or_flap",
        selected_playbook="cisco_interface_status",
        sources=sources,
        readonly_only=True,
        created_at=NOW,
    ).model_dump(mode="json")


def invocation(
    *,
    plan: dict | None = None,
    request_id: str = REQUEST_ID,
    agent_name: AgentName = AgentName.DEVICE_EVIDENCE,
) -> AgentInvocation:
    prior = {}
    if plan is not None:
        prior[AgentName.STATIC_PLANNER.value] = {"evidence_plan": plan}
    return AgentInvocation(
        request_id=request_id,
        agent_name=agent_name,
        orchestration_state=OrchestrationState.EVIDENCE_COLLECTION,
        prior_output_refs=(),
        prior_outputs=prior,
    )


class DeviceEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.callback_root = root / "callback"
        self.execution_root = root / "execution"
        self.callback_root.mkdir()
        self.execution_root.mkdir()

    def write_fixture(self, name: str, *, filename: str | None = None) -> Path:
        payload = json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))
        path = self.callback_root / (filename or f"{REQUEST_ID}.runner.result.json")
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path

    def adapter(self) -> DeviceEvidenceAdapter:
        return DeviceEvidenceAdapter(
            (self.callback_root, self.execution_root),
            utcnow=lambda: NOW,
        )

    def run_agent(
        self,
        *,
        plan: dict | None = None,
        request_id: str = REQUEST_ID,
        agent_name: AgentName = AgentName.DEVICE_EVIDENCE,
    ):
        agent = DeviceEvidenceAgent(adapter=self.adapter(), utcnow=lambda: NOW)
        return asyncio.run(
            agent.run(
                invocation(
                    plan=plan if plan is not None else evidence_plan(),
                    request_id=request_id,
                    agent_name=agent_name,
                )
            )
        )

    def test_all_commands_success(self) -> None:
        self.write_fixture("success.json")
        outcome = self.run_agent()
        self.assertEqual(outcome.status, AgentStatus.SUCCESS)
        envelope = EvidenceEnvelope.model_validate(outcome.output["device_evidence"])
        self.assertEqual(envelope.status, EvidenceStatus.SUCCESS)
        self.assertEqual(envelope.facts["counts"]["success"], 2)
        self.assertEqual(len(envelope.evidence_refs), 2)

    def test_partial_success(self) -> None:
        self.write_fixture("partial.json")
        outcome = self.run_agent()
        self.assertEqual(outcome.status, AgentStatus.PARTIAL)
        envelope = EvidenceEnvelope.model_validate(outcome.output["device_evidence"])
        self.assertEqual(envelope.status, EvidenceStatus.PARTIAL)
        self.assertEqual(envelope.facts["counts"]["success"], 1)
        self.assertEqual(envelope.facts["counts"]["failed"], 1)

    def test_invalid_input_is_hard_failure(self) -> None:
        self.write_fixture("invalid_input.json")
        outcome = self.run_agent()
        envelope = EvidenceEnvelope.model_validate(outcome.output["device_evidence"])
        self.assertEqual(outcome.status, AgentStatus.FAILED)
        self.assertEqual(envelope.status, EvidenceStatus.FAILED)
        fact = envelope.facts["results"][0]
        self.assertTrue(fact["hard_error"])
        self.assertEqual(fact["error_category"], "invalid_command")

    def test_permission_denied(self) -> None:
        self.write_fixture("permission_denied.json")
        envelope = EvidenceEnvelope.model_validate(self.run_agent().output["device_evidence"])
        self.assertEqual(envelope.status, EvidenceStatus.FAILED)
        self.assertEqual(envelope.facts["results"][0]["error_category"], "permission_denied")

    def test_empty_output(self) -> None:
        self.write_fixture("empty_output.json")
        envelope = EvidenceEnvelope.model_validate(self.run_agent().output["device_evidence"])
        self.assertEqual(envelope.status, EvidenceStatus.FAILED)
        self.assertEqual(envelope.facts["results"][0]["error_category"], "empty_output")

    def test_timeout(self) -> None:
        self.write_fixture("timeout.json")
        envelope = EvidenceEnvelope.model_validate(self.run_agent().output["device_evidence"])
        self.assertEqual(envelope.status, EvidenceStatus.FAILED)
        self.assertEqual(envelope.facts["results"][0]["error_category"], "timeout")

    def test_parser_failed(self) -> None:
        self.write_fixture("parser_failed.json")
        envelope = EvidenceEnvelope.model_validate(self.run_agent().output["device_evidence"])
        self.assertEqual(envelope.status, EvidenceStatus.FAILED)
        self.assertEqual(envelope.facts["parser_failure_count"], 1)
        self.assertEqual(envelope.facts["results"][0]["error_category"], "parser_failed")

    def test_mcp_unavailable_is_failed_without_calling_mcp(self) -> None:
        self.write_fixture("mcp_unavailable.json")
        outcome = self.run_agent()
        envelope = EvidenceEnvelope.model_validate(outcome.output["device_evidence"])
        self.assertEqual(envelope.status, EvidenceStatus.FAILED)
        self.assertEqual(envelope.facts["results"][0]["error_category"], "mcp_not_available")
        self.assertFalse(outcome.output["netmiko_mcp_called"])

    def test_missing_artifact_is_not_available(self) -> None:
        outcome = self.run_agent()
        self.assertEqual(outcome.status, AgentStatus.NOT_AVAILABLE)
        envelope = EvidenceEnvelope.model_validate(outcome.output["device_evidence"])
        self.assertEqual(envelope.status, EvidenceStatus.NOT_AVAILABLE)
        self.assertEqual(envelope.reason, "existing_device_execution_not_found")

    def test_optional_missing_artifact_is_not_available(self) -> None:
        outcome = self.run_agent(plan=evidence_plan(required=False))
        envelope = EvidenceEnvelope.model_validate(outcome.output["device_evidence"])
        self.assertEqual(envelope.status, EvidenceStatus.NOT_AVAILABLE)
        self.assertFalse(envelope.scope["required"])

    def test_safety_policy_denied_is_skipped(self) -> None:
        self.write_fixture("success.json")
        outcome = self.run_agent(plan=evidence_plan(safety_allowed=False))
        self.assertEqual(outcome.status, AgentStatus.SKIPPED)
        envelope = EvidenceEnvelope.model_validate(outcome.output["device_evidence"])
        self.assertEqual(envelope.status, EvidenceStatus.SKIPPED)
        self.assertEqual(envelope.reason, "device_safety_policy_not_allowed")

    def test_readonly_policy_is_mandatory(self) -> None:
        self.assertEqual(
            self.run_agent(plan=evidence_plan(readonly_only=False)).status,
            AgentStatus.FAILED,
        )

    def test_command_generation_must_be_disabled(self) -> None:
        self.assertEqual(
            self.run_agent(plan=evidence_plan(command_generation_allowed=True)).status,
            AgentStatus.FAILED,
        )

    def test_wrong_agent_name_fails(self) -> None:
        self.assertEqual(
            self.run_agent(agent_name=AgentName.METRICS_EVIDENCE).status,
            AgentStatus.FAILED,
        )

    def test_missing_plan_fails(self) -> None:
        agent = DeviceEvidenceAgent(adapter=self.adapter(), utcnow=lambda: NOW)
        outcome = asyncio.run(agent.run(invocation(plan=None)))
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_invalid_plan_fails(self) -> None:
        self.assertEqual(
            self.run_agent(plan={"schema_version": "v12.1"}).status,
            AgentStatus.FAILED,
        )

    def test_plan_request_mismatch_fails(self) -> None:
        outcome = self.run_agent(
            plan=evidence_plan(request_id="req-other-plan"),
            request_id=REQUEST_ID,
        )
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_device_source_missing_fails(self) -> None:
        self.assertEqual(
            self.run_agent(plan=evidence_plan(include_device=False)).status,
            AgentStatus.FAILED,
        )

    def test_artifact_request_mismatch_fails(self) -> None:
        self.write_fixture("request_mismatch.json")
        outcome = self.run_agent()
        self.assertEqual(outcome.status, AgentStatus.FAILED)
        self.assertTrue(outcome.errors)

    def test_summary_does_not_include_raw_output(self) -> None:
        self.write_fixture("sensitive.json")
        envelope = EvidenceEnvelope.model_validate(self.run_agent().output["device_evidence"])
        serialized = json.dumps(envelope.model_dump(mode="json"), ensure_ascii=False)
        self.assertNotIn("TEST_TOKEN_PLACEHOLDER", serialized)
        self.assertNotIn("interface Ethernet1/1", envelope.summary)
        self.assertNotIn("api_token", serialized)

    def test_facts_do_not_contain_command_or_raw_output_keys(self) -> None:
        self.write_fixture("success.json")
        envelope = EvidenceEnvelope.model_validate(self.run_agent().output["device_evidence"])
        keys = set()
        def walk(value):
            if isinstance(value, dict):
                keys.update(str(key).lower() for key in value)
                for item in value.values():
                    walk(item)
            elif isinstance(value, list):
                for item in value:
                    walk(item)
        walk(envelope.facts)
        for forbidden in ("command", "output", "error", "raw_output"):
            self.assertNotIn(forbidden, keys)

    def test_safe_parser_facts_are_retained(self) -> None:
        self.write_fixture("success.json")
        fact = EvidenceEnvelope.model_validate(
            self.run_agent().output["device_evidence"]
        ).facts["results"][0]
        self.assertIn("oper_status", fact["parsed_fact_keys"])
        self.assertEqual(fact["parsed_facts"]["oper_status"], "up")

    def test_sensitive_parser_keys_are_removed(self) -> None:
        self.write_fixture("sensitive.json")
        fact = EvidenceEnvelope.model_validate(
            self.run_agent().output["device_evidence"]
        ).facts["results"][0]
        self.assertNotIn("token", fact["parsed_fact_keys"])
        self.assertEqual(fact["parsed_facts"]["safe_state"], "present")

    def test_output_flags_are_frozen(self) -> None:
        self.write_fixture("success.json")
        output = self.run_agent().output
        self.assertTrue(output["reuse_existing_execution"])
        self.assertFalse(output["netmiko_mcp_called"])
        self.assertFalse(output["command_generation_performed"])
        self.assertFalse(output["write_command_executed"])
        self.assertFalse(output["raw_output_forwarded"])
        self.assertFalse(output["safety_policy_bypassed"])

    def test_external_calls_are_empty(self) -> None:
        self.write_fixture("success.json")
        self.assertEqual(self.run_agent().external_calls, ())

    def test_evidence_refs_are_stable(self) -> None:
        self.write_fixture("success.json")
        first = self.run_agent().output["device_evidence"]["evidence_refs"]
        second = self.run_agent().output["device_evidence"]["evidence_refs"]
        self.assertEqual(first, second)

    def test_source_artifact_ref_is_stable(self) -> None:
        self.write_fixture("success.json")
        first = self.run_agent().output["source_artifact_ref"]
        second = self.run_agent().output["source_artifact_ref"]
        self.assertEqual(first, second)
        self.assertTrue(first.startswith(f"artifact://{REQUEST_ID}/"))

    def test_latest_artifact_is_selected(self) -> None:
        older = self.write_fixture(
            "invalid_input.json",
            filename=f"old-{REQUEST_ID}.execution.json",
        )
        newer = self.execution_root / f"new-{REQUEST_ID}.execution.json"
        newer.write_text(
            (FIXTURE_ROOT / "success.json").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        os.utime(older, (1, 1))
        os.utime(newer, (2, 2))
        normalized = self.adapter().load_existing(REQUEST_ID)
        self.assertIsNotNone(normalized)
        self.assertEqual(normalized.status, EvidenceStatus.SUCCESS)

    def test_symlink_is_not_followed(self) -> None:
        outside = Path(self.temp.name) / "outside.json"
        outside.write_text(
            (FIXTURE_ROOT / "success.json").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        link = self.execution_root / f"{REQUEST_ID}.runner.result.json"
        link.symlink_to(outside)
        self.assertIsNone(self.adapter().load_existing(REQUEST_ID))

    def test_oversized_artifact_is_rejected(self) -> None:
        path = self.callback_root / f"{REQUEST_ID}.runner.result.json"
        path.write_text("x" * (8 * 1024 * 1024 + 1), encoding="utf-8")
        with self.assertRaises(DeviceEvidenceAdapterError):
            self.adapter().load_existing(REQUEST_ID)

    def test_non_list_command_results_is_rejected(self) -> None:
        path = self.callback_root / f"{REQUEST_ID}.runner.result.json"
        path.write_text(
            json.dumps({"request_id": REQUEST_ID, "command_results": {}}),
            encoding="utf-8",
        )
        with self.assertRaises(DeviceEvidenceAdapterError):
            self.adapter().load_existing(REQUEST_ID)

    def test_network_socket_is_not_used(self) -> None:
        self.write_fixture("success.json")
        agent = DeviceEvidenceAgent(adapter=self.adapter(), utcnow=lambda: NOW)
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            with mock.patch.object(
                socket,
                "socket",
                side_effect=AssertionError("network forbidden"),
            ):
                outcome = loop.run_until_complete(
                    agent.run(invocation(plan=evidence_plan()))
                )
        finally:
            asyncio.set_event_loop(None)
            loop.close()
        self.assertEqual(outcome.status, AgentStatus.SUCCESS)

    def test_production_modules_do_not_import_network_or_execution_clients(self) -> None:
        paths = [
            PROJECT_ROOT / "netaiops/v12/adapters/device_evidence_adapter.py",
            PROJECT_ROOT / "netaiops/v12/agents/device_evidence_agent.py",
        ]
        text = "\n".join(path.read_text(encoding="utf-8") for path in paths)
        for forbidden in (
            "import requests",
            "import httpx",
            "import subprocess",
            "import socket",
            "execute_commands(",
            "run_mcp_commands_placeholder(",
            "MCP_WRAPPER_CMD",
            "from agent_runner.executors import",
            "from netaiops.agent_client import",
        ):
            self.assertNotIn(forbidden, text)

    def test_no_write_command_or_cli_generation_in_output(self) -> None:
        self.write_fixture("success.json")
        output = self.run_agent().output
        serialized = json.dumps(dict(output), ensure_ascii=False, sort_keys=True).lower()
        self.assertNotIn('"commands"', serialized)
        self.assertNotIn('"command_templates"', serialized)
        self.assertFalse(output["command_generation_performed"])
        self.assertFalse(output["write_command_executed"])

    def test_evidence_envelope_contract_is_valid(self) -> None:
        self.write_fixture("success.json")
        envelope = EvidenceEnvelope.model_validate(self.run_agent().output["device_evidence"])
        self.assertEqual(envelope.source, EvidenceSource.DEVICE)
        self.assertEqual(envelope.evidence_kind, "evidence")

    def test_collected_at_is_timezone_aware(self) -> None:
        self.write_fixture("success.json")
        envelope = EvidenceEnvelope.model_validate(self.run_agent().output["device_evidence"])
        self.assertIsNotNone(envelope.collected_at.utcoffset())


if __name__ == "__main__":
    unittest.main()
