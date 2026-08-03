from __future__ import annotations

import ast
import inspect
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from unittest.mock import patch
from pathlib import Path

from netaiops.v12.contracts import (
    ContextEnvelope,
    EvidenceBundle,
    EvidenceCollection,
    EvidenceEnvelope,
    EvidenceJudgeResult,
    EvidencePlan,
    EvidenceSourcePlan,
)
import netaiops.v12.p2_device_continue as p2_device_continue_module
import netaiops.v12.p2_rca_continue as p2_rca_continue_module

from netaiops.v12.execution_context import AgentOutcome
from netaiops.v12.judge_rules import evaluate_evidence
from netaiops.v12.p2_rca_continue import (
    P2RCAContinueError,
    GLMSingleCallError,
    MAX_OUTPUT_TOKENS,
    MAX_PROMPT_CHARS,
    _coerce_content,
    _confidence,
    _exact_nonnegative_int,
    _redact,
    _validate_replay_anchor,
    align_planner_outcome_for_historical_replay,
    evaluate_checkpoint_evidence_at,
    historical_replay_planner_scope,
    _minimal_rca_prompt,
    _single_glm_call,
    _string_list,
    normalize_rca_payload,
    prepare_v8_state,
    preflight_report,
)
from netaiops.v12.schema_validator import (
    build_contract_ref,
    build_evidence_ref,
)
from netaiops.v12.status import (
    AgentStatus,
    EvidenceBundleStatus,
    EvidenceSource,
    EvidenceStatus,
    JudgeStatus,
)


REQUEST_ID = "p2-continue-20260730T091239Z-e6689cba0f"
METRICS_REF = build_evidence_ref(
    REQUEST_ID,
    "metrics",
    "fixture-metrics",
)
DEVICE_REF = build_evidence_ref(
    REQUEST_ID,
    "device",
    "fixture-device",
)


def envelope(
    source: EvidenceSource,
    status: EvidenceStatus,
    refs: list[str],
) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        schema_version="v12.1",
        request_id=REQUEST_ID,
        source=source,
        evidence_kind="evidence",
        status=status,
        summary=f"{source.value} fixture",
        facts={},
        scope={},
        evidence_refs=refs,
        collected_at=datetime.now(timezone.utc),
        reason=None,
    )


def bundle() -> EvidenceBundle:
    return EvidenceBundle(
        schema_version="v12.1",
        request_id=REQUEST_ID,
        event_ref=build_contract_ref(
            "event",
            REQUEST_ID,
            "unified_event",
            "fixture",
        ),
        plan_ref=build_contract_ref(
            "plan",
            REQUEST_ID,
            "evidence_plan",
            "fixture",
        ),
        evidence=EvidenceCollection(
            metrics=envelope(
                EvidenceSource.METRICS,
                EvidenceStatus.SUCCESS,
                [METRICS_REF],
            ),
            device=envelope(
                EvidenceSource.DEVICE,
                EvidenceStatus.SUCCESS,
                [DEVICE_REF],
            ),
            logs=EvidenceEnvelope(
                schema_version="v12.1",
                request_id=REQUEST_ID,
                source=EvidenceSource.LOGS,
                evidence_kind="evidence",
                status=EvidenceStatus.NOT_AVAILABLE,
                summary="logs disabled",
                facts={},
                scope={},
                evidence_refs=[],
                collected_at=datetime.now(timezone.utc),
                reason="not approved in Batch P2",
            ),
            knowledge=ContextEnvelope(
                schema_version="v12.1",
                request_id=REQUEST_ID,
                source="knowledge",
                evidence_kind="context",
                status=EvidenceStatus.NOT_AVAILABLE,
                reason="not approved in Batch P2",
                context_facts=[],
                source_refs=[],
                as_of=None,
                collected_at=datetime.now(timezone.utc),
            ),
        ),
        bundle_status=EvidenceBundleStatus.PARTIAL,
        built_at=datetime.now(timezone.utc),
    )


def judge() -> EvidenceJudgeResult:
    return EvidenceJudgeResult(
        schema_version="v12.1",
        request_id=REQUEST_ID,
        status=JudgeStatus.PARTIAL,
        required_sources=[
            EvidenceSource.METRICS,
            EvidenceSource.DEVICE,
        ],
        missing_required_sources=[],
        missing_optional_sources=[
            EvidenceSource.LOGS,
            EvidenceSource.KNOWLEDGE,
        ],
        conflicts=[],
        rca_allowed=True,
        confidence_cap=0.65,
        evidence_refs=[METRICS_REF, DEVICE_REF],
        judged_at=datetime.now(timezone.utc),
    )


EVENT = {
    "device": {"ip": "10.187.251.61"},
    "alert_object": {
        "kind": "interface",
        "name": "Ethernet1/1",
    },
}


class PrimitiveNormalizationTests(unittest.TestCase):
    def test_string_list_deduplicates(self):
        self.assertEqual(
            _string_list(["a", "a", " b "]),
            ["a", "b"],
        )

    def test_confidence_is_capped(self):
        self.assertEqual(_confidence(0.9, 0.65), 0.65)

    def test_confidence_label_is_supported(self):
        self.assertEqual(_confidence("low", 0.65), 0.35)

    def test_content_list_is_coerced(self):
        self.assertEqual(
            _coerce_content(
                [{"text": "one"}, {"text": "two"}]
            ),
            "one\ntwo",
        )

    def test_secret_text_is_redacted(self):
        value = _redact("token=abc password=hello")
        self.assertNotIn("abc", value)
        self.assertNotIn("hello", value)


class ExactIntegerGateTests(unittest.TestCase):
    def test_integer_zero_is_valid(self):
        self.assertEqual(
            _exact_nonnegative_int(
                {"real_call_count": 0},
                "real_call_count",
                expected=0,
                context="fixture",
            ),
            0,
        )

    def test_string_zero_is_valid(self):
        self.assertEqual(
            _exact_nonnegative_int(
                {"real_call_count": "0"},
                "real_call_count",
                expected=0,
                context="fixture",
            ),
            0,
        )

    def test_missing_value_is_rejected(self):
        with self.assertRaises(P2RCAContinueError):
            _exact_nonnegative_int(
                {},
                "real_call_count",
                expected=0,
                context="fixture",
            )

    def test_none_value_is_rejected(self):
        with self.assertRaises(P2RCAContinueError):
            _exact_nonnegative_int(
                {"real_call_count": None},
                "real_call_count",
                expected=0,
                context="fixture",
            )

    def test_boolean_value_is_rejected(self):
        with self.assertRaises(P2RCAContinueError):
            _exact_nonnegative_int(
                {"real_call_count": False},
                "real_call_count",
                expected=0,
                context="fixture",
            )

    def test_float_value_is_rejected(self):
        with self.assertRaises(P2RCAContinueError):
            _exact_nonnegative_int(
                {"real_call_count": 0.0},
                "real_call_count",
                expected=0,
                context="fixture",
            )


class _FakeResponse:
    status_code = 200
    headers = {}
    payload = {
        "model": "glm-5.2",
        "choices": [
            {
                "finish_reason": "stop",
                "message": {
                    "content": json.dumps(
                        {
                            "candidates": [
                                {
                                    "statement": "fixture",
                                    "confidence": 0.5,
                                    "supporting_evidence_refs": [
                                        DEVICE_REF
                                    ],
                                    "contradicting_evidence_refs": [],
                                    "missing_evidence": [
                                        "logs",
                                        "knowledge",
                                    ],
                                    "uncertainties": ["fixture"],
                                    "scope": EVENT,
                                }
                            ],
                            "missing_evidence": [
                                "logs",
                                "knowledge",
                            ],
                            "uncertainties": ["fixture"],
                        },
                        ensure_ascii=False,
                    )
                },
            }
        ],
    }

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class _FakeClient:
    calls = []
    instances = []

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs
        self.__class__.instances.append(kwargs)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def post(self, url, *, headers, json):
        self.__class__.calls.append(
            {
                "url": url,
                "headers": headers,
                "json": json,
            }
        )
        return _FakeResponse()


class SingleGLMCallTests(unittest.TestCase):
    def setUp(self):
        _FakeClient.calls = []
        _FakeClient.instances = []

    def config(self):
        return {
            "llm": {
                "enabled": True,
                "provider": "openai_compatible",
                "model": "glm-5.2",
                "base_url": "http://127.0.0.1:18000/v1",
                "api_key_env": "P2_FINAL_TEST_KEY",
                "timeout": 30,
                "retry": 0,
                "max_tokens": 1200,
            }
        }

    def test_single_call_uses_one_post_8192_tokens_and_300s_read(self):
        with patch.dict(
            os.environ,
            {"P2_FINAL_TEST_KEY": "fixture-value"},
            clear=False,
        ), patch(
            (
                "netaiops.v12.p2_rca_continue."
                "_systemd_service_environment"
            ),
            return_value={},
        ), patch(
            "netaiops.v12.p2_rca_continue.httpx.Client",
            _FakeClient,
        ):
            analysis, metadata = _single_glm_call(
                prompt="fixture",
                production_config=self.config(),
            )
        self.assertEqual(len(_FakeClient.calls), 1)
        self.assertEqual(len(_FakeClient.instances), 1)
        self.assertEqual(
            _FakeClient.calls[0]["json"]["max_tokens"],
            8192,
        )
        timeout = _FakeClient.instances[0]["timeout"]
        self.assertEqual(float(timeout.connect), 10.0)
        self.assertEqual(float(timeout.read), 300.0)
        self.assertEqual(float(timeout.write), 30.0)
        self.assertEqual(float(timeout.pool), 10.0)
        self.assertEqual(
            metadata["timeout_contract"],
            {
                "request_timeout_seconds": 300,
                "connect_timeout_seconds": 10.0,
                "read_timeout_seconds": 300.0,
                "write_timeout_seconds": 30.0,
                "pool_timeout_seconds": 10.0,
            },
        )
        self.assertEqual(metadata["attempt_count"], 1)
        self.assertEqual(metadata["parse_status"], "ok")
        self.assertIn("candidates", analysis)

    def test_empty_content_preserves_failure_metadata(self):
        original = _FakeResponse.payload
        _FakeResponse.payload = {
            "model": "glm-5.2",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"content": ""},
                }
            ],
        }
        try:
            with patch.dict(
                os.environ,
                {"P2_FINAL_TEST_KEY": "fixture-value"},
                clear=False,
            ), patch(
                (
                    "netaiops.v12.p2_rca_continue."
                    "_systemd_service_environment"
                ),
                return_value={},
            ), patch(
                "netaiops.v12.p2_rca_continue.httpx.Client",
                _FakeClient,
            ):
                with self.assertRaises(GLMSingleCallError) as raised:
                    _single_glm_call(
                        prompt="fixture",
                        production_config=self.config(),
                    )
            self.assertEqual(
                raised.exception.metadata["attempt_count"],
                1,
            )
            self.assertEqual(
                raised.exception.metadata["parse_status"],
                "empty_content",
            )
        finally:
            _FakeResponse.payload = original


    def test_length_empty_content_is_output_budget_exhausted(self):
        original = _FakeResponse.payload
        _FakeResponse.payload = {
            "model": "glm-5.2",
            "choices": [
                {
                    "finish_reason": "length",
                    "message": {
                        "content": "",
                        "reasoning_content": "reasoning",
                    },
                }
            ],
        }
        try:
            with patch.dict(
                os.environ,
                {"P2_FINAL_TEST_KEY": "fixture-value"},
                clear=False,
            ), patch(
                (
                    "netaiops.v12.p2_rca_continue."
                    "_systemd_service_environment"
                ),
                return_value={},
            ), patch(
                "netaiops.v12.p2_rca_continue.httpx.Client",
                _FakeClient,
            ):
                with self.assertRaises(GLMSingleCallError) as raised:
                    _single_glm_call(
                        prompt="fixture",
                        production_config=self.config(),
                    )
            self.assertEqual(
                raised.exception.metadata["parse_status"],
                "output_budget_exhausted",
            )
            self.assertEqual(
                raised.exception.metadata["finish_reason"],
                "length",
            )
        finally:
            _FakeResponse.payload = original

    def test_length_with_complete_json_is_accepted(self):
        original = _FakeResponse.payload
        payload = dict(_FakeResponse.payload)
        payload["choices"] = [
            {
                "finish_reason": "length",
                "message": {
                    "content": original["choices"][0]["message"]["content"]
                },
            }
        ]
        _FakeResponse.payload = payload
        try:
            with patch.dict(
                os.environ,
                {"P2_FINAL_TEST_KEY": "fixture-value"},
                clear=False,
            ), patch(
                (
                    "netaiops.v12.p2_rca_continue."
                    "_systemd_service_environment"
                ),
                return_value={},
            ), patch(
                "netaiops.v12.p2_rca_continue.httpx.Client",
                _FakeClient,
            ):
                analysis, metadata = _single_glm_call(
                    prompt="fixture",
                    production_config=self.config(),
                )
            self.assertEqual(metadata["parse_status"], "ok")
            self.assertEqual(metadata["finish_reason"], "length")
            self.assertIn("candidates", analysis)
        finally:
            _FakeResponse.payload = original

    def test_single_call_metadata_records_prompt_budget(self):
        with patch.dict(
            os.environ,
            {"P2_FINAL_TEST_KEY": "fixture-value"},
            clear=False,
        ), patch(
            (
                "netaiops.v12.p2_rca_continue."
                "_systemd_service_environment"
            ),
            return_value={},
        ), patch(
            "netaiops.v12.p2_rca_continue.httpx.Client",
            _FakeClient,
        ):
            _, metadata = _single_glm_call(
                prompt="fixture",
                production_config=self.config(),
            )
        self.assertEqual(
            metadata["requested_max_tokens"],
            MAX_OUTPUT_TOKENS,
        )
        self.assertEqual(metadata["prompt_chars"], len("fixture"))

    def test_minimal_prompt_is_bounded_and_contract_complete(self):
        value = _minimal_rca_prompt(
            event=EVENT,
            bundle=bundle(),
            judge=judge(),
        )
        self.assertGreater(len(value), 0)
        self.assertLessEqual(len(value), MAX_PROMPT_CHARS)
        self.assertLessEqual(len(value), 5000)
        self.assertIn("output_skeleton", value)
        self.assertIn("possible_causes", value)
        self.assertIn("allowed_evidence_refs", value)
        self.assertNotIn("command_output", value)


class RCANormalizationTests(unittest.TestCase):
    def test_current_shape_is_preserved(self):
        raw = {
            "candidates": [
                {
                    "statement": "interface evidence is abnormal",
                    "confidence": 0.5,
                    "supporting_evidence_refs": [
                        DEVICE_REF
                    ],
                    "contradicting_evidence_refs": [],
                    "missing_evidence": ["logs"],
                    "uncertainties": ["logs unavailable"],
                    "scope": EVENT,
                }
            ],
            "missing_evidence": ["logs", "knowledge"],
            "uncertainties": ["limited evidence"],
        }
        normalized, _ = normalize_rca_payload(
            raw,
            bundle=bundle(),
            judge=judge(),
            event=EVENT,
        )
        self.assertEqual(
            normalized["candidates"][0]["statement"],
            "interface evidence is abnormal",
        )

    def test_invalid_ref_is_replaced_by_allowed_ref(self):
        raw = {
            "candidates": [
                {
                    "statement": "candidate",
                    "supporting_evidence_refs": [
                        "evidence://foreign/device/x"
                    ],
                }
            ],
            "missing_evidence": [],
            "uncertainties": [],
        }
        normalized, actions = normalize_rca_payload(
            raw,
            bundle=bundle(),
            judge=judge(),
            event=EVENT,
        )
        self.assertIn(
            normalized["candidates"][0][
                "supporting_evidence_refs"
            ][0],
            {METRICS_REF, DEVICE_REF},
        )
        self.assertIn(
            "supporting_ref_completed",
            actions,
        )

    def test_missing_evidence_is_inherited(self):
        normalized, _ = normalize_rca_payload(
            {
                "candidates": [
                    {"statement": "candidate"}
                ],
                "missing_evidence": [],
                "uncertainties": [],
            },
            bundle=bundle(),
            judge=judge(),
            event=EVENT,
        )
        self.assertEqual(
            set(normalized["missing_evidence"]),
            {"logs", "knowledge"},
        )

    def test_candidate_uncertainty_is_completed(self):
        normalized, actions = normalize_rca_payload(
            {
                "candidates": [
                    {"statement": "candidate"}
                ],
                "missing_evidence": [],
                "uncertainties": [],
            },
            bundle=bundle(),
            judge=judge(),
            event=EVENT,
        )
        self.assertTrue(
            normalized["candidates"][0]["uncertainties"]
        )
        self.assertIn(
            "candidate_uncertainty_completed",
            actions,
        )

    def test_candidate_scope_is_completed(self):
        normalized, actions = normalize_rca_payload(
            {
                "candidates": [
                    {"statement": "candidate"}
                ],
                "missing_evidence": [],
                "uncertainties": [],
            },
            bundle=bundle(),
            judge=judge(),
            event=EVENT,
        )
        self.assertEqual(
            normalized["candidates"][0]["scope"],
            EVENT,
        )
        self.assertIn("candidate_scope_completed", actions)

    def test_legacy_possible_causes_are_converted(self):
        normalized, actions = normalize_rca_payload(
            {
                "possible_causes": ["cause one"],
                "summary": "summary",
            },
            bundle=bundle(),
            judge=judge(),
            event=EVENT,
        )
        self.assertEqual(
            normalized["candidates"][0]["statement"],
            "cause one",
        )
        self.assertIn(
            "legacy_possible_causes_converted",
            actions,
        )

    def test_legacy_summary_is_converted(self):
        normalized, actions = normalize_rca_payload(
            {"summary": "summary only"},
            bundle=bundle(),
            judge=judge(),
            event=EVENT,
        )
        self.assertEqual(
            normalized["candidates"][0]["statement"],
            "summary only",
        )
        self.assertIn(
            "legacy_summary_converted",
            actions,
        )

    def test_empty_response_is_rejected(self):
        with self.assertRaises(P2RCAContinueError):
            normalize_rca_payload(
                {},
                bundle=bundle(),
                judge=judge(),
                event=EVENT,
            )

    def test_duplicate_statements_are_removed(self):
        normalized, _ = normalize_rca_payload(
            {
                "candidates": [
                    {"statement": "same"},
                    {"statement": "same"},
                ],
                "missing_evidence": [],
                "uncertainties": [],
            },
            bundle=bundle(),
            judge=judge(),
            event=EVENT,
        )
        self.assertEqual(
            len(normalized["candidates"]),
            1,
        )


REPLAY_AT = datetime(2026, 7, 30, 9, 12, 44, tzinfo=timezone.utc)


def historical_envelopes(
    *,
    conflict: bool = False,
) -> tuple[EvidenceEnvelope, EvidenceEnvelope]:
    metrics_scope = {
        "device_ip": "10.187.251.62" if conflict else "10.187.251.61",
        "if_name": "Ethernet1/1",
    }
    metrics = EvidenceEnvelope(
        schema_version="v12.1",
        request_id=REQUEST_ID,
        source=EvidenceSource.METRICS,
        evidence_kind="evidence",
        status=EvidenceStatus.SUCCESS,
        summary="historical metrics",
        facts={},
        scope=metrics_scope,
        evidence_refs=[METRICS_REF],
        collected_at=REPLAY_AT - timedelta(days=3),
    )
    device = EvidenceEnvelope(
        schema_version="v12.1",
        request_id=REQUEST_ID,
        source=EvidenceSource.DEVICE,
        evidence_kind="evidence",
        status=EvidenceStatus.SUCCESS,
        summary="historical device",
        facts={},
        scope={
            "device_ip": "10.187.251.61",
            "interface": "Ethernet1/1",
        },
        evidence_refs=[DEVICE_REF],
        collected_at=REPLAY_AT,
    )
    return metrics, device


def planner_outcome() -> AgentOutcome:
    plan_ref = build_contract_ref(
        "plan",
        REQUEST_ID,
        "evidence_plan",
        "fixture-plan",
    )
    plan = EvidencePlan(
        schema_version="v12.1",
        request_id=REQUEST_ID,
        plan_ref=plan_ref,
        planner_mode="deterministic",
        family="interface_status_or_flap",
        selected_playbook=None,
        sources=[
            EvidenceSourcePlan(
                source=EvidenceSource.METRICS,
                required=False,
                constraints={},
                max_items=1,
            ),
            EvidenceSourcePlan(
                source=EvidenceSource.DEVICE,
                required=True,
                constraints={},
                max_items=1,
            ),
            EvidenceSourcePlan(
                source=EvidenceSource.LOGS,
                required=False,
                constraints={"enabled": False},
                max_items=0,
            ),
            EvidenceSourcePlan(
                source=EvidenceSource.KNOWLEDGE,
                required=False,
                constraints={"enabled": False},
                max_items=0,
            ),
        ],
        readonly_only=True,
        created_at=REPLAY_AT + timedelta(hours=20),
    )
    return AgentOutcome(
        status=AgentStatus.SUCCESS,
        output_refs=(plan_ref,),
        output={"evidence_plan": plan.model_dump(mode="json")},
    )


class HistoricalReplayTests(unittest.TestCase):
    def test_timezone_aware_anchor_is_normalized(self):
        value = _validate_replay_anchor(REPLAY_AT)
        self.assertEqual(value, REPLAY_AT)

    def test_naive_anchor_is_rejected(self):
        with self.assertRaises(P2RCAContinueError):
            _validate_replay_anchor(
                datetime(2026, 7, 30, 9, 12, 44)
            )

    def test_future_anchor_is_rejected(self):
        with self.assertRaises(P2RCAContinueError):
            _validate_replay_anchor(
                datetime.now(timezone.utc) + timedelta(days=1)
            )

    def test_aligned_plan_uses_device_checkpoint_time(self):
        aligned = align_planner_outcome_for_historical_replay(
            planner_outcome(),
            REPLAY_AT,
        )
        plan = EvidencePlan.model_validate(
            aligned.output["evidence_plan"]
        )
        self.assertEqual(plan.created_at, REPLAY_AT)

    def test_aligned_plan_has_explicit_replay_marker(self):
        aligned = align_planner_outcome_for_historical_replay(
            planner_outcome(),
            REPLAY_AT,
        )
        plan = EvidencePlan.model_validate(
            aligned.output["evidence_plan"]
        )
        source_map = {item.source: item for item in plan.sources}
        self.assertTrue(
            source_map[EvidenceSource.DEVICE]
            .constraints["historical_controlled_replay"]
        )
        self.assertFalse(
            source_map[EvidenceSource.DEVICE]
            .constraints["production_freshness_rule_changed"]
        )

    def test_planner_patch_restores_original_class(self):
        original = p2_device_continue_module.StaticPlannerAgent
        with historical_replay_planner_scope(REPLAY_AT):
            self.assertIsNot(
                p2_device_continue_module.StaticPlannerAgent,
                original,
            )
        self.assertIs(
            p2_device_continue_module.StaticPlannerAgent,
            original,
        )

    def test_realtime_plan_rejects_stale_required_device(self):
        metrics, device = historical_envelopes()
        _, _, result = evaluate_checkpoint_evidence_at(
            metrics,
            device,
            plan_created_at=REPLAY_AT + timedelta(hours=10),
        )
        self.assertEqual(result.status, JudgeStatus.INSUFFICIENT)
        self.assertFalse(result.rca_allowed)
        self.assertIn(
            EvidenceSource.DEVICE,
            result.missing_required_sources,
        )

    def test_historical_replay_allows_rca(self):
        metrics, device = historical_envelopes()
        _, _, result = evaluate_checkpoint_evidence_at(
            metrics,
            device,
            plan_created_at=REPLAY_AT,
        )
        self.assertTrue(result.rca_allowed)
        self.assertEqual(result.status, JudgeStatus.PARTIAL)

    def test_historical_replay_has_no_missing_required(self):
        metrics, device = historical_envelopes()
        _, _, result = evaluate_checkpoint_evidence_at(
            metrics,
            device,
            plan_created_at=REPLAY_AT,
        )
        self.assertEqual(result.missing_required_sources, [])

    def test_historical_replay_optional_missing_is_exact(self):
        metrics, device = historical_envelopes()
        _, _, result = evaluate_checkpoint_evidence_at(
            metrics,
            device,
            plan_created_at=REPLAY_AT,
        )
        self.assertEqual(
            result.missing_optional_sources,
            [
                EvidenceSource.METRICS,
                EvidenceSource.LOGS,
                EvidenceSource.KNOWLEDGE,
            ],
        )

    def test_historical_replay_confidence_cap_is_point_seven(self):
        metrics, device = historical_envelopes()
        _, _, result = evaluate_checkpoint_evidence_at(
            metrics,
            device,
            plan_created_at=REPLAY_AT,
        )
        self.assertAlmostEqual(result.confidence_cap, 0.70)

    def test_historical_replay_does_not_bypass_conflicts(self):
        metrics, device = historical_envelopes(conflict=True)
        _, _, result = evaluate_checkpoint_evidence_at(
            metrics,
            device,
            plan_created_at=REPLAY_AT,
        )
        self.assertEqual(result.status, JudgeStatus.BLOCKED)
        self.assertFalse(result.rca_allowed)
        self.assertTrue(result.conflicts)


class FinalStateIdempotenceTests(unittest.TestCase):
    def _seed_roots(self, base: Path) -> tuple[Path, Path, Path]:
        v3 = base / "v3"
        v8 = base / "v8"
        final = base / "final"
        (v3 / "checkpoints").mkdir(parents=True)
        v8.mkdir(parents=True)
        (v3 / "checkpoints" / "metrics.json").write_text(
            '{"kind":"metrics"}\n', encoding="utf-8"
        )
        (v3 / "checkpoints" / "device.json").write_text(
            '{"kind":"device"}\n', encoding="utf-8"
        )
        (v8 / "historical_replay_planner_dry_run.json").write_text(
            '{"source":"v8-planner"}\n', encoding="utf-8"
        )
        (v8 / "historical_replay_judge_dry_run.json").write_text(
            '{"source":"v8-judge"}\n', encoding="utf-8"
        )
        return v3, v8, final

    def _validation_patches(self):
        return (
            patch.object(
                p2_rca_continue_module,
                "validate_v3_source_checkpoints",
                return_value={"status": "pass"},
            ),
            patch.object(
                p2_rca_continue_module,
                "validate_v4_no_call_state",
                return_value={"status": "pass"},
            ),
            patch.object(
                p2_rca_continue_module,
                "validate_v5_no_call_state",
                return_value={"status": "pass"},
            ),
            patch.object(
                p2_rca_continue_module,
                "validate_v6_timeout_state",
                return_value={"status": "pass"},
            ),
            patch.object(
                p2_rca_continue_module,
                "validate_v7_output_budget_state",
                return_value={"status": "pass"},
            ),
            patch.object(
                p2_rca_continue_module,
                "validate_v8_timeout_state",
                return_value={"status": "pass"},
            ),
        )

    def test_source_proofs_do_not_collide_with_current_dry_runs(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            v3, v8, final = self._seed_roots(base)
            patches = self._validation_patches()
            with patch.object(p2_rca_continue_module, "V3_STATE_ROOT", v3), \
                 patch.object(p2_rca_continue_module, "V8_STATE_ROOT", v8), \
                 patches[0], patches[1], patches[2], patches[3], \
                 patches[4], patches[5]:
                first = prepare_v8_state(final)
                planner_source = (
                    final
                    / p2_rca_continue_module.V8_SOURCE_PLANNER_PROOF_NAME
                )
                judge_source = (
                    final
                    / p2_rca_continue_module.V8_SOURCE_JUDGE_PROOF_NAME
                )
                planner_sha = p2_rca_continue_module._sha256_file(
                    planner_source
                )
                judge_sha = p2_rca_continue_module._sha256_file(
                    judge_source
                )
                (final / "historical_replay_planner_dry_run.json").write_text(
                    '{"current":"planner"}\n', encoding="utf-8"
                )
                (final / "historical_replay_judge_dry_run.json").write_text(
                    '{"current":"judge"}\n', encoding="utf-8"
                )
                second = prepare_v8_state(final)

            self.assertEqual(first["status"], "pass")
            self.assertEqual(second["status"], "pass")
            self.assertEqual(
                p2_rca_continue_module._sha256_file(planner_source),
                planner_sha,
            )
            self.assertEqual(
                p2_rca_continue_module._sha256_file(judge_source),
                judge_sha,
            )
            self.assertIn(
                p2_rca_continue_module.V8_SOURCE_PLANNER_PROOF_NAME,
                second["copied_replay_proofs"],
            )
            self.assertEqual(
                json.loads(
                    (final / "historical_replay_planner_dry_run.json")
                    .read_text(encoding="utf-8")
                )["current"],
                "planner",
            )

    def test_preflight_is_idempotent_after_current_dry_runs_exist(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            v3, v8, final = self._seed_roots(base)
            patches = self._validation_patches()
            runtime = {
                "config": {"llm": {"max_tokens": 8192}},
                "endpoint_summary": {
                    "scheme": "https",
                    "hostname": "example.invalid",
                    "port": None,
                    "path_present": False,
                },
                "api_key_configured": True,
                "key_source": "environment",
                "environment_names": ["FIXTURE_KEY"],
                "timeout_contract": {
                    "request_timeout_seconds": 300,
                    "connect_timeout_seconds": 10.0,
                    "read_timeout_seconds": 300.0,
                    "write_timeout_seconds": 30.0,
                    "pool_timeout_seconds": 10.0,
                },
            }
            with patch.object(p2_rca_continue_module, "V3_STATE_ROOT", v3), \
                 patch.object(p2_rca_continue_module, "V8_STATE_ROOT", v8), \
                 patch.object(
                     p2_rca_continue_module,
                     "load_production_config",
                     return_value={},
                 ), \
                 patch.object(
                     p2_rca_continue_module,
                     "_runtime_llm_summary",
                     return_value=runtime,
                 ), \
                 patches[0], patches[1], patches[2], patches[3], \
                 patches[4], patches[5]:
                prepare_v8_state(final)
                (final / "historical_replay_planner_dry_run.json").write_text(
                    '{"status":"pass","run":1}\n', encoding="utf-8"
                )
                (final / "historical_replay_judge_dry_run.json").write_text(
                    '{"status":"pass","run":1}\n', encoding="utf-8"
                )
                first = preflight_report(final)
                second = preflight_report(final)

            self.assertEqual(first["status"], "pass")
            self.assertEqual(second["status"], "pass")
            self.assertEqual(first["external_calls"], second["external_calls"])



class GateVariableIsolationRegressionTests(unittest.TestCase):
    def test_evaluate_v8_gate_does_not_shadow_source_checkpoints(self):
        function_source = inspect.getsource(
            p2_rca_continue_module.evaluate_v8_gate
        )
        tree = ast.parse(function_source)
        stored_names = {
            node.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Store)
        }
        self.assertIn("source_checkpoints", stored_names)
        self.assertIn("evidence_source", stored_names)
        self.assertNotIn("source", stored_names)
        self.assertIn(
            'source_checkpoints.get("copied_checkpoints")',
            function_source,
        )

    def test_gate_source_names_have_distinct_semantics(self):
        function_source = inspect.getsource(
            p2_rca_continue_module.evaluate_v8_gate
        )
        self.assertIn(
            'root / "source_checkpoints.json"',
            function_source,
        )
        self.assertIn(
            "for evidence_source in (",
            function_source,
        )
        self.assertNotIn(
            "for source in (\n                EvidenceSource.METRICS,",
            function_source,
        )


class CLIEntryRegressionTests(unittest.TestCase):
    def test_direct_cli_status_works_without_pythonpath(self):
        project_root = Path(__file__).resolve().parents[1]
        runner = project_root / "scripts" / "run_v12_p2_rca_continue.py"
        self.assertTrue(runner.is_file())

        with tempfile.TemporaryDirectory() as raw:
            env = os.environ.copy()
            env.pop("PYTHONPATH", None)
            env.pop("PYTHONHOME", None)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(runner),
                    "status",
                    "--state-dir",
                    raw,
                ],
                cwd=raw,
                env=env,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )

        self.assertEqual(
            proc.returncode,
            0,
            msg=(proc.stdout or "") + (proc.stderr or ""),
        )
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "available")
        self.assertEqual(payload["state_dir"], raw)


if __name__ == "__main__":
    unittest.main()
