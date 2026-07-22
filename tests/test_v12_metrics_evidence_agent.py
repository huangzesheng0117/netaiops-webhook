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

from netaiops.v12.adapters.prometheus_evidence_adapter import (
    PrometheusEvidenceAdapter,
    PrometheusEvidenceAdapterError,
)
from netaiops.v12.agents.metrics_evidence_agent import MetricsEvidenceAgent
from netaiops.v12.contracts import EvidenceEnvelope, EvidencePlan
from netaiops.v12.execution_context import AgentInvocation
from netaiops.v12.state_machine import OrchestrationState
from netaiops.v12.status import AgentName, AgentStatus, EvidenceStatus


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = PROJECT_ROOT / "tests/fixtures/v12/metrics"
REQUEST_ID = "req-metrics-001"
NOW = datetime(2026, 7, 17, 0, 20, tzinfo=timezone.utc)


def fixture(name: str) -> dict:
    return json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))


def evidence_plan(
    *,
    request_id: str = REQUEST_ID,
    required: bool = True,
    reuse: bool = True,
    promql_allowed: bool = False,
) -> dict:
    return {
        "schema_version": "v12.1",
        "request_id": request_id,
        "plan_ref": (
            f"plan://{request_id}/evidence_plan/plan-metrics-001"
        ),
        "planner_mode": "deterministic",
        "family": "interface_traffic_anomaly",
        "selected_playbook": "cisco_interface_traffic_anomaly",
        "sources": [
            {
                "source": "metrics",
                "required": required,
                "capability_ids": ["query_prometheus_metric_window"],
                "constraints": {
                    "reuse_existing_evidence": reuse,
                    "promql_generation_allowed": promql_allowed,
                    "planner_mode": "deterministic",
                    "evidence_profile": "interface_traffic",
                    "query_names": ["in_bps", "out_bps"],
                },
                "max_items": 2,
            },
            {
                "source": "device",
                "required": True,
                "capability_ids": ["show_interface_detail"],
                "constraints": {
                    "readonly_only": True,
                    "command_generation_allowed": False,
                },
                "max_items": 1,
            },
            {
                "source": "logs",
                "required": False,
                "capability_ids": [],
                "constraints": {
                    "enabled": False,
                    "reason": "logs_evidence_not_approved",
                    "dsl_generation_allowed": False,
                },
                "max_items": 0,
            },
            {
                "source": "knowledge",
                "required": False,
                "capability_ids": [],
                "constraints": {
                    "enabled": False,
                    "reason": "local_knowledge_base_not_built",
                    "evidence_kind": "context",
                },
                "max_items": 0,
            },
        ],
        "readonly_only": True,
        "created_at": "2026-07-17T00:15:00+00:00",
    }


def invocation(
    *,
    agent_name: AgentName = AgentName.METRICS_EVIDENCE,
    plan: dict | None = None,
    request_id: str = REQUEST_ID,
) -> AgentInvocation:
    outputs = {}
    if plan is not None:
        outputs[AgentName.STATIC_PLANNER.value] = {
            "evidence_plan": plan,
        }
    return AgentInvocation(
        request_id=request_id,
        agent_name=agent_name,
        orchestration_state=OrchestrationState.EVIDENCE_COLLECTION,
        prior_output_refs=(),
        prior_outputs=outputs,
    )


class MetricsEvidenceAgentTests(unittest.TestCase):
    def write_fixture(
        self,
        root: Path,
        name: str,
        *,
        request_id: str = REQUEST_ID,
        filename_prefix: str = "alertmanager",
    ) -> Path:
        payload = fixture(name)
        path = (
            root
            / f"{filename_prefix}_{request_id}.prometheus_evidence.json"
        )
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return path

    def run_agent(
        self,
        root: Path,
        *,
        plan: dict | None = None,
    ):
        adapter = PrometheusEvidenceAdapter(root, utcnow=lambda: NOW)
        agent = MetricsEvidenceAgent(
            adapter=adapter,
            utcnow=lambda: NOW,
        )
        return asyncio.run(
            agent.run(
                invocation(plan=plan or evidence_plan())
            )
        )

    def test_success_maps_to_success_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.write_fixture(Path(tmp), "success.json")
            outcome = self.run_agent(Path(tmp))
        self.assertEqual(outcome.status, AgentStatus.SUCCESS)
        envelope = EvidenceEnvelope.model_validate(
            outcome.output["metrics_evidence"]
        )
        self.assertEqual(envelope.status, EvidenceStatus.SUCCESS)
        self.assertEqual(len(envelope.evidence_refs), 1)
        self.assertEqual(
            envelope.facts["successful_query_count"],
            1,
        )

    def test_success_evidence_ref_is_stable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_fixture(root, "success.json")
            first = self.run_agent(root)
            second = self.run_agent(root)
        self.assertEqual(
            first.output["metrics_evidence"]["evidence_refs"],
            second.output["metrics_evidence"]["evidence_refs"],
        )

    def test_no_data_maps_to_no_data_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.write_fixture(Path(tmp), "no_data.json")
            outcome = self.run_agent(Path(tmp))
        self.assertEqual(outcome.status, AgentStatus.PARTIAL)
        self.assertEqual(
            outcome.output["metrics_evidence"]["status"],
            "no_data",
        )
        self.assertEqual(
            outcome.output["metrics_evidence"]["evidence_refs"],
            [],
        )

    def test_timeout_maps_to_failed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.write_fixture(Path(tmp), "timeout.json")
            outcome = self.run_agent(Path(tmp))
        self.assertEqual(outcome.status, AgentStatus.FAILED)
        self.assertEqual(
            outcome.output["metrics_evidence"]["status"],
            "failed",
        )

    def test_mcp_failure_maps_to_failed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.write_fixture(Path(tmp), "mcp_failed.json")
            outcome = self.run_agent(Path(tmp))
        self.assertEqual(outcome.status, AgentStatus.FAILED)
        self.assertTrue(outcome.errors)

    def test_partial_query_success_maps_to_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.write_fixture(Path(tmp), "partial.json")
            outcome = self.run_agent(Path(tmp))
        self.assertEqual(outcome.status, AgentStatus.PARTIAL)
        facts = outcome.output["metrics_evidence"]["facts"]
        self.assertEqual(facts["successful_query_count"], 1)
        self.assertEqual(facts["no_data_query_count"], 1)

    def test_runtime_disabled_maps_to_not_available(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.write_fixture(Path(tmp), "runtime_disabled.json")
            outcome = self.run_agent(Path(tmp))
        self.assertEqual(outcome.status, AgentStatus.NOT_AVAILABLE)
        envelope = outcome.output["metrics_evidence"]
        self.assertEqual(envelope["status"], "not_available")
        self.assertEqual(envelope["reason"], "runtime sidecar disabled")

    def test_missing_required_artifact_is_not_available(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            outcome = self.run_agent(Path(tmp))
        self.assertEqual(outcome.status, AgentStatus.NOT_AVAILABLE)
        self.assertEqual(
            outcome.output["metrics_evidence"]["reason"],
            "existing_prometheus_evidence_not_found",
        )

    def test_missing_optional_artifact_has_explicit_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            outcome = self.run_agent(
                Path(tmp),
                plan=evidence_plan(required=False),
            )
        self.assertEqual(outcome.status, AgentStatus.NOT_AVAILABLE)
        self.assertEqual(
            outcome.output["metrics_evidence"]["reason"],
            "metrics_optional_existing_evidence_not_found",
        )

    def test_one_minute_step_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.write_fixture(Path(tmp), "success.json")
            outcome = self.run_agent(Path(tmp))
        result = outcome.output["metrics_evidence"]["facts"][
            "query_results"
        ][0]
        self.assertEqual(result["query_window"]["step"], "60s")
        warning_codes = {
            item.code for item in outcome.warnings
        }
        self.assertNotIn("metrics_step_not_1m", warning_codes)

    def test_non_one_minute_step_is_partial_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = fixture("success.json")
            payload["evidences"][0]["query_window"]["step"] = "30s"
            path = (
                root
                / f"alertmanager_{REQUEST_ID}.prometheus_evidence.json"
            )
            path.write_text(json.dumps(payload), encoding="utf-8")
            outcome = self.run_agent(root)
        self.assertEqual(outcome.status, AgentStatus.PARTIAL)
        self.assertIn(
            "metrics_step_not_1m",
            {item.code for item in outcome.warnings},
        )

    def test_sensitive_fields_and_raw_promql_are_filtered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.write_fixture(Path(tmp), "sensitive.json")
            outcome = self.run_agent(Path(tmp))
        serialized = json.dumps(
            dict(outcome.output),
            ensure_ascii=False,
            sort_keys=True,
        )
        for secret in (
            "TOP-LEVEL-SECRET",
            "PASSWORD-SECRET",
            "APIKEY-SECRET",
            "Bearer SECRET",
            "SESSION-SECRET",
            "RAW-SECRET-LOG",
            "SECRET-PROMQL",
        ):
            self.assertNotIn(secret, serialized)
        self.assertNotIn('"selected_query"', serialized)
        self.assertNotIn('"attempts"', serialized)

    def test_output_contains_no_generated_promql_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.write_fixture(Path(tmp), "success.json")
            outcome = self.run_agent(Path(tmp))

        forbidden_keys = {
            "promql",
            "selected_query",
            "queries",
            "command",
            "commands",
            "dsl",
            "elasticsearch_dsl",
        }

        def visit(value) -> None:
            if isinstance(value, dict):
                self.assertFalse(forbidden_keys.intersection(value))
                for item in value.values():
                    visit(item)
            elif isinstance(value, list):
                for item in value:
                    visit(item)

        visit(dict(outcome.output))
        self.assertFalse(
            outcome.output["promql_generation_performed"]
        )

    def test_agent_reports_no_external_calls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.write_fixture(Path(tmp), "success.json")
            outcome = self.run_agent(Path(tmp))
        self.assertEqual(outcome.external_calls, ())
        self.assertFalse(outcome.output["prometheus_mcp_called"])
        self.assertTrue(outcome.output["reuse_existing_evidence"])
        self.assertFalse(outcome.output["query_logic_changed"])

    def test_network_socket_is_not_used(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_fixture(root, "success.json")
            adapter = PrometheusEvidenceAdapter(
                root,
                utcnow=lambda: NOW,
            )
            agent = MetricsEvidenceAgent(
                adapter=adapter,
                utcnow=lambda: NOW,
            )
            loop = asyncio.new_event_loop()
            try:
                asyncio.set_event_loop(loop)
                with mock.patch.object(
                    socket,
                    "socket",
                    side_effect=AssertionError("network forbidden"),
                ):
                    outcome = loop.run_until_complete(
                        agent.run(
                            invocation(plan=evidence_plan())
                        )
                    )
            finally:
                asyncio.set_event_loop(None)
                loop.close()
        self.assertEqual(outcome.status, AgentStatus.SUCCESS)

    def test_request_mismatch_artifact_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.write_fixture(Path(tmp), "request_mismatch.json")
            outcome = self.run_agent(Path(tmp))
        self.assertEqual(outcome.status, AgentStatus.FAILED)
        self.assertEqual(
            outcome.output["metrics_evidence"]["status"],
            "failed",
        )

    def test_malformed_json_artifact_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = (
                root
                / f"alertmanager_{REQUEST_ID}.prometheus_evidence.json"
            )
            path.write_text("{not-json", encoding="utf-8")
            outcome = self.run_agent(root)
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_oversized_artifact_fails_before_parse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = (
                root
                / f"alertmanager_{REQUEST_ID}.prometheus_evidence.json"
            )
            with path.open("wb") as handle:
                handle.truncate(4 * 1024 * 1024 + 1)
            outcome = self.run_agent(root)
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_symlink_artifact_is_ignored(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symlink unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.json"
            target.write_text(
                json.dumps(fixture("success.json")),
                encoding="utf-8",
            )
            link = (
                root
                / f"alertmanager_{REQUEST_ID}.prometheus_evidence.json"
            )
            os.symlink(target, link)
            outcome = self.run_agent(root)
        self.assertEqual(outcome.status, AgentStatus.NOT_AVAILABLE)

    def test_newest_matching_artifact_is_selected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_path = self.write_fixture(
                root,
                "no_data.json",
                filename_prefix="old",
            )
            new_path = self.write_fixture(
                root,
                "success.json",
                filename_prefix="new",
            )
            os.utime(old_path, (1, 1))
            os.utime(new_path, (2, 2))
            outcome = self.run_agent(root)
        self.assertEqual(outcome.status, AgentStatus.SUCCESS)

    def test_wrong_agent_name_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            adapter = PrometheusEvidenceAdapter(
                tmp,
                utcnow=lambda: NOW,
            )
            agent = MetricsEvidenceAgent(
                adapter=adapter,
                utcnow=lambda: NOW,
            )
            outcome = asyncio.run(
                agent.run(
                    invocation(
                        agent_name=AgentName.DEVICE_EVIDENCE,
                        plan=evidence_plan(),
                    )
                )
            )
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_missing_static_planner_output_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            adapter = PrometheusEvidenceAdapter(
                tmp,
                utcnow=lambda: NOW,
            )
            agent = MetricsEvidenceAgent(
                adapter=adapter,
                utcnow=lambda: NOW,
            )
            outcome = asyncio.run(
                agent.run(invocation(plan=None))
            )
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_invalid_plan_contract_fails(self) -> None:
        bad = evidence_plan()
        bad["unknown"] = True
        with tempfile.TemporaryDirectory() as tmp:
            outcome = self.run_agent(Path(tmp), plan=bad)
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_plan_request_id_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            outcome = self.run_agent(
                Path(tmp),
                plan=evidence_plan(request_id="req-other-001"),
            )
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_reuse_policy_must_be_true(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            outcome = self.run_agent(
                Path(tmp),
                plan=evidence_plan(reuse=False),
            )
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_promql_generation_policy_must_be_false(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            outcome = self.run_agent(
                Path(tmp),
                plan=evidence_plan(promql_allowed=True),
            )
        self.assertEqual(outcome.status, AgentStatus.FAILED)

    def test_evidence_plan_fixture_is_contract_valid(self) -> None:
        plan = EvidencePlan.model_validate(evidence_plan())
        self.assertEqual(plan.request_id, REQUEST_ID)

    def test_all_metrics_fixtures_are_json_objects(self) -> None:
        paths = sorted(FIXTURE_ROOT.glob("*.json"))
        self.assertEqual(len(paths), 8)
        for path in paths:
            self.assertIsInstance(
                json.loads(path.read_text(encoding="utf-8")),
                dict,
            )

    def test_production_modules_do_not_import_network_clients(self) -> None:
        paths = [
            PROJECT_ROOT
            / "netaiops/v12/adapters/prometheus_evidence_adapter.py",
            PROJECT_ROOT
            / "netaiops/v12/agents/metrics_evidence_agent.py",
        ]
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in paths
        )
        forbidden = (
            "PrometheusBridge",
            "collect_prometheus_evidence",
            "requests",
            "httpx",
            "urllib.request",
            "socket.socket",
            "execute_range_query",
        )
        for token in forbidden:
            self.assertNotIn(token, text)

    def test_source_contract_freezes_reuse_and_no_generation(self) -> None:
        text = (
            PROJECT_ROOT
            / "netaiops/v12/agents/metrics_evidence_agent.py"
        ).read_text(encoding="utf-8")
        self.assertIn("reuse_existing_evidence", text)
        self.assertIn("prometheus_mcp_called", text)
        self.assertIn("promql_generation_performed", text)
        self.assertIn("query_logic_changed", text)


if __name__ == "__main__":
    unittest.main()
