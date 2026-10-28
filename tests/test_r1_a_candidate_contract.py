from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import yaml

from netaiops.v12.agents.static_planner_agent import StaticPlannerAgent
from netaiops.v12.execution_context import AgentOutcome
from netaiops.v12.p2_real_canary import (
    P2RealCanaryError,
    _compact_rca_prompt,
    _validate_r1_logs_boundary,
)
from netaiops.v12.primary_release import _audit_payload
from netaiops.v12.status import AgentStatus, EvidenceSource
from netaiops.v14.runtime_config import LogsRuntimeSettings


def _settings(**updates):
    base = {
        "activation_id": "r1-test",
        "enabled": True,
        "store_evidence_enabled": True,
        "real_query_enabled": True,
        "include_in_analysis": False,
        "include_in_review": False,
        "include_in_rca": False,
        "include_in_card": False,
        "window_before_minutes": 1,
        "window_after_minutes": 1,
        "ingestion_grace_seconds": 600,
        "max_raw_samples": 10,
        "retry_delay_seconds": 60,
        "max_attempts_per_phase": 2,
        "late_check_enabled": False,
        "late_check_delay_seconds": 300,
        "startup_recovery_max_jobs": 16,
    }
    base.update(updates)
    return LogsRuntimeSettings.model_validate(base)


def _write_runtime(root: Path, settings: LogsRuntimeSettings) -> None:
    target = root / "config" / "v14_logs_w1.yaml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        yaml.safe_dump(settings.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )


def _fake_playbook():
    return SimpleNamespace(
        prometheus_evidence_enabled=False,
        command_template_count=0,
        prometheus_profile=None,
        prometheus_query_names=(),
        max_commands=0,
    )


def _groups():
    return {
        EvidenceSource.METRICS: [],
        EvidenceSource.DEVICE: [],
        EvidenceSource.LOGS: [],
        EvidenceSource.KNOWLEDGE: [],
    }


def _logs_outcome(
    *,
    status=AgentStatus.SUCCESS,
    placeholder=False,
    include_in_rca=False,
    external_calls=(),
):
    return AgentOutcome(
        status=status,
        output={
            "placeholder": placeholder,
            "logs_evidence": {
                "status": (
                    "success" if status == AgentStatus.SUCCESS else "not_available"
                ),
                "facts": {
                    "include_in_rca": include_in_rca,
                    "window_complete": True,
                    "collection_state": "complete",
                },
            },
        },
        external_calls=external_calls,
    )


def _knowledge_outcome():
    return AgentOutcome(status=AgentStatus.NOT_AVAILABLE)


def _prompt_inputs(include_in_rca: bool):
    metrics_ref = "evidence://r1-test/metrics/m1"
    logs_ref = "evidence://r1-test/logs/R1_LOGS_REF_SENTINEL"
    bundle = {
        "evidence": {
            "metrics": {
                "status": "success",
                "summary": "metrics-ok",
                "facts": {"metric": 1},
                "scope": {},
                "reason": None,
                "evidence_refs": [metrics_ref],
            },
            "device": {
                "status": "not_available",
                "summary": "device-na",
                "facts": {},
                "scope": {},
                "reason": "na",
                "evidence_refs": [],
            },
            "logs": {
                "status": "success",
                "summary": "R1_LOGS_SUMMARY_SENTINEL",
                "facts": {
                    "include_in_rca": include_in_rca,
                    "matched_total": 987654321,
                    "window_complete": True,
                },
                "scope": {"sentinel": "R1_LOGS_SCOPE_SENTINEL"},
                "reason": None,
                "evidence_refs": [logs_ref],
            },
        }
    }
    judge_refs = [metrics_ref] + ([logs_ref] if include_in_rca else [])
    judge = {
        "evidence_refs": judge_refs,
        "missing_required_sources": [],
        "missing_optional_sources": ["knowledge"],
        "confidence_cap": 0.85,
    }
    event = {
        "alert_name": "r1-test",
        "family": "interface_status_or_flap",
        "device": {"ip": "192.0.2.1"},
        "alert_object": {"kind": "interface", "name": "Ethernet1/1"},
        "labels": {},
        "annotations": {},
    }
    return event, bundle, judge, logs_ref


class R1ACandidateContractTests(unittest.TestCase):
    def test_r1_stage_matrix(self):
        self.assertEqual(_settings().r1_stage, "store_only")
        self.assertEqual(
            _settings(include_in_analysis=True, include_in_review=True).r1_stage,
            "review",
        )
        self.assertEqual(
            _settings(
                include_in_analysis=True,
                include_in_review=True,
                include_in_rca=True,
            ).r1_stage,
            "rca_build_only",
        )
        self.assertEqual(
            _settings(
                include_in_analysis=True,
                include_in_review=True,
                include_in_rca=True,
                include_in_card=True,
            ).r1_stage,
            "card_store_only",
        )

    def test_static_planner_preserves_store_only_contract(self):
        with tempfile.TemporaryDirectory(prefix="r1-a-store-only-") as td:
            root = Path(td)
            settings = _settings()
            _write_runtime(root, settings)
            planner = StaticPlannerAgent(project_root=root)
            sources = planner._build_sources(
                groups=_groups(),
                playbook=_fake_playbook(),
                safety={},
            )
        logs = next(item for item in sources if item.source == EvidenceSource.LOGS)
        self.assertEqual(logs.max_items, 0)
        self.assertEqual(
            logs.constraints,
            {
                "enabled": False,
                "reason": "logs_evidence_not_approved",
                "dsl_generation_allowed": False,
            },
        )

    def test_static_planner_review_contract_is_persisted_only(self):
        with tempfile.TemporaryDirectory(prefix="r1-a-review-") as td:
            root = Path(td)
            settings = _settings(include_in_analysis=True, include_in_review=True)
            _write_runtime(root, settings)
            planner = StaticPlannerAgent(project_root=root)
            sources = planner._build_sources(
                groups=_groups(),
                playbook=_fake_playbook(),
                safety={},
            )
        logs = next(item for item in sources if item.source == EvidenceSource.LOGS)
        self.assertEqual(logs.max_items, 1)
        self.assertIs(logs.constraints["enabled"], True)
        self.assertIs(logs.constraints["persisted_evidence_only"], True)
        self.assertIs(logs.constraints["direct_mcp_allowed"], False)
        self.assertIs(logs.constraints["dsl_generation_allowed"], False)
        self.assertEqual(logs.constraints["r1_stage"], "review")

    def test_p2_store_only_boundary_stays_frozen(self):
        stage = _validate_r1_logs_boundary(
            logs=_logs_outcome(
                status=AgentStatus.NOT_AVAILABLE,
                placeholder=True,
            ),
            knowledge=_knowledge_outcome(),
            logs_runtime=_settings(),
        )
        self.assertEqual(stage, "store_only")

    def test_p2_review_boundary_accepts_persisted_logs_without_external_call(self):
        stage = _validate_r1_logs_boundary(
            logs=_logs_outcome(placeholder=False, include_in_rca=False),
            knowledge=_knowledge_outcome(),
            logs_runtime=_settings(include_in_analysis=True, include_in_review=True),
        )
        self.assertEqual(stage, "review")

    def test_p2_review_boundary_rejects_legacy_placeholder(self):
        with self.assertRaises(P2RealCanaryError):
            _validate_r1_logs_boundary(
                logs=_logs_outcome(placeholder=True, include_in_rca=False),
                knowledge=_knowledge_outcome(),
                logs_runtime=_settings(
                    include_in_analysis=True,
                    include_in_review=True,
                ),
            )

    def test_p2_review_boundary_rejects_direct_external_call(self):
        with self.assertRaises(P2RealCanaryError):
            _validate_r1_logs_boundary(
                logs=_logs_outcome(
                    placeholder=False,
                    include_in_rca=False,
                    external_calls=(object(),),
                ),
                knowledge=_knowledge_outcome(),
                logs_runtime=_settings(
                    include_in_analysis=True,
                    include_in_review=True,
                ),
            )

    def test_rca_prompt_excludes_all_logs_content_during_review(self):
        event, bundle, judge, logs_ref = _prompt_inputs(False)
        prompt = _compact_rca_prompt(event=event, bundle=bundle, judge=judge)
        self.assertNotIn(logs_ref, prompt)
        self.assertNotIn("R1_LOGS_SUMMARY_SENTINEL", prompt)
        self.assertNotIn("R1_LOGS_SCOPE_SENTINEL", prompt)
        self.assertNotIn("987654321", prompt)

    def test_rca_prompt_includes_logs_only_after_rca_gate(self):
        event, bundle, judge, logs_ref = _prompt_inputs(True)
        prompt = _compact_rca_prompt(event=event, bundle=bundle, judge=judge)
        self.assertIn(logs_ref, prompt)
        self.assertIn("R1_LOGS_SUMMARY_SENTINEL", prompt)
        self.assertIn("987654321", prompt)

    def test_primary_audit_reports_actual_logs_stage(self):
        payload = _audit_payload(
            request_id="r1-test",
            settings=None,
            status="completed",
            reason="test",
            started_at=datetime.now(timezone.utc),
            notify_result=None,
            result={
                "status": "completed",
                "logs_status": "success",
                "logs_r1_stage": "review",
            },
        )
        self.assertEqual(payload["logs_status"], "success")
        self.assertIs(payload["notification_sent"], False)
        self.assertIs(payload["second_card_sent"], False)
        self.assertIs(payload["production_card_replaced"], False)


if __name__ == "__main__":
    unittest.main()
