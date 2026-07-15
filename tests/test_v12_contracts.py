from __future__ import annotations

import json
import unittest
from pathlib import Path

from pydantic import ValidationError

from netaiops.v12.contracts import (
    AgentRunRecord,
    ContextEnvelope,
    EvidenceBundle,
    EvidenceEnvelope,
    EvidenceJudgeResult,
    EvidencePlan,
    RCAResult,
    ReportArtifact,
    UnifiedAlertEvent,
)
from netaiops.v12.errors import ContractValidationError, EvidenceReferenceError
from netaiops.v12.schema_validator import (
    REDACTED_VALUE,
    build_evidence_ref,
    parse_contract_ref,
    sanitize_sensitive_data,
    stable_json_dumps,
    validate_contract,
    validate_contract_json,
)
from netaiops.v12.status import AgentStatus, EvidenceStatus, JudgeStatus


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = PROJECT_ROOT / "tests/fixtures/v12/contracts"
REQUEST_ID = "req-20260715-0001"


MODEL_FIXTURES = {
    "valid_unified_alert_event.json": UnifiedAlertEvent,
    "valid_agent_run_record.json": AgentRunRecord,
    "valid_evidence_plan.json": EvidencePlan,
    "valid_evidence_envelope.json": EvidenceEnvelope,
    "valid_context_envelope.json": ContextEnvelope,
    "valid_evidence_bundle.json": EvidenceBundle,
    "valid_evidence_judge_result.json": EvidenceJudgeResult,
    "valid_rca_result.json": RCAResult,
    "valid_report_artifact.json": ReportArtifact,
}


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))


class V12ContractFixtureTests(unittest.TestCase):
    def test_all_expected_fixture_files_exist(self) -> None:
        expected = {
            *MODEL_FIXTURES,
            "invalid_missing_request_id.json",
            "invalid_agent_status.json",
            "invalid_evidence_ref.json",
            "invalid_naive_time.json",
        }
        actual = {path.name for path in FIXTURE_ROOT.glob("*.json")}
        self.assertEqual(actual, expected)

    def test_all_valid_fixtures_parse(self) -> None:
        for name, model_type in MODEL_FIXTURES.items():
            with self.subTest(name=name):
                model = validate_contract(model_type, load_fixture(name))
                self.assertEqual(model.schema_version, "v12.1")
                self.assertEqual(model.request_id, REQUEST_ID)

    def test_valid_fixtures_round_trip_stably(self) -> None:
        for name, model_type in MODEL_FIXTURES.items():
            with self.subTest(name=name):
                payload = load_fixture(name)
                first = validate_contract(model_type, payload)
                serialized = stable_json_dumps(first)
                second = validate_contract_json(model_type, serialized)
                self.assertEqual(serialized, stable_json_dumps(second))

    def test_missing_request_id_fixture_fails(self) -> None:
        with self.assertRaises(ContractValidationError):
            validate_contract(
                UnifiedAlertEvent,
                load_fixture("invalid_missing_request_id.json"),
            )

    def test_invalid_agent_status_fixture_fails(self) -> None:
        with self.assertRaises(ContractValidationError):
            validate_contract(
                AgentRunRecord,
                load_fixture("invalid_agent_status.json"),
            )

    def test_invalid_evidence_ref_fixture_fails(self) -> None:
        with self.assertRaises(ContractValidationError):
            validate_contract(
                EvidenceEnvelope,
                load_fixture("invalid_evidence_ref.json"),
            )

    def test_naive_time_fixture_fails(self) -> None:
        with self.assertRaises(ContractValidationError):
            validate_contract(
                AgentRunRecord,
                load_fixture("invalid_naive_time.json"),
            )


class V12SchemaRulesTests(unittest.TestCase):
    def test_schema_version_is_required(self) -> None:
        payload = load_fixture("valid_unified_alert_event.json")
        payload.pop("schema_version")
        with self.assertRaises(ValidationError):
            UnifiedAlertEvent.model_validate(payload)

    def test_schema_version_is_frozen(self) -> None:
        payload = load_fixture("valid_unified_alert_event.json")
        payload["schema_version"] = "v12.2"
        with self.assertRaises(ValidationError):
            UnifiedAlertEvent.model_validate(payload)

    def test_unknown_fields_are_forbidden(self) -> None:
        payload = load_fixture("valid_agent_run_record.json")
        payload["unexpected"] = True
        with self.assertRaises(ValidationError):
            AgentRunRecord.model_validate(payload)

    def test_request_id_uses_safe_format(self) -> None:
        payload = load_fixture("valid_agent_run_record.json")
        payload["request_id"] = "../bad"
        with self.assertRaises(ValidationError):
            AgentRunRecord.model_validate(payload)

    def test_finished_time_cannot_precede_started_time(self) -> None:
        payload = load_fixture("valid_agent_run_record.json")
        payload["finished_at"] = "2026-07-15T00:59:59+00:00"
        with self.assertRaises(ValidationError):
            AgentRunRecord.model_validate(payload)

    def test_error_structure_is_not_free_text(self) -> None:
        payload = load_fixture("valid_agent_run_record.json")
        payload["errors"] = ["plain text error"]
        with self.assertRaises(ValidationError):
            AgentRunRecord.model_validate(payload)

    def test_not_available_evidence_requires_reason(self) -> None:
        payload = load_fixture("valid_evidence_envelope.json")
        payload["status"] = EvidenceStatus.NOT_AVAILABLE.value
        payload["reason"] = None
        with self.assertRaises(ValidationError):
            EvidenceEnvelope.model_validate(payload)

    def test_knowledge_cannot_use_evidence_envelope(self) -> None:
        payload = load_fixture("valid_evidence_envelope.json")
        payload["source"] = "knowledge"
        with self.assertRaises(ValidationError):
            EvidenceEnvelope.model_validate(payload)

    def test_successful_context_requires_as_of_and_source_refs(self) -> None:
        payload = load_fixture("valid_context_envelope.json")
        payload["status"] = EvidenceStatus.SUCCESS.value
        payload["reason"] = None
        with self.assertRaises(ValidationError):
            ContextEnvelope.model_validate(payload)

    def test_plan_sources_must_be_unique(self) -> None:
        payload = load_fixture("valid_evidence_plan.json")
        payload["sources"][1]["source"] = "metrics"
        with self.assertRaises(ValidationError):
            EvidencePlan.model_validate(payload)

    def test_plan_is_readonly_only(self) -> None:
        payload = load_fixture("valid_evidence_plan.json")
        payload["readonly_only"] = False
        with self.assertRaises(ValidationError):
            EvidencePlan.model_validate(payload)

    def test_bundle_envelope_request_ids_must_match(self) -> None:
        payload = load_fixture("valid_evidence_bundle.json")
        payload["evidence"]["device"]["request_id"] = "other-request"
        with self.assertRaises(ValidationError):
            EvidenceBundle.model_validate(payload)

    def test_blocked_judge_cannot_allow_rca(self) -> None:
        payload = load_fixture("valid_evidence_judge_result.json")
        payload["status"] = JudgeStatus.BLOCKED.value
        payload["rca_allowed"] = True
        with self.assertRaises(ValidationError):
            EvidenceJudgeResult.model_validate(payload)

    def test_successful_rca_requires_candidates(self) -> None:
        payload = load_fixture("valid_rca_result.json")
        payload["candidates"] = []
        with self.assertRaises(ValidationError):
            RCAResult.model_validate(payload)

    def test_failed_rca_cannot_have_candidates(self) -> None:
        payload = load_fixture("valid_rca_result.json")
        payload["status"] = AgentStatus.FAILED.value
        with self.assertRaises(ValidationError):
            RCAResult.model_validate(payload)

    def test_rca_candidate_requires_supporting_evidence(self) -> None:
        payload = load_fixture("valid_rca_result.json")
        payload["candidates"][0]["supporting_evidence_refs"] = []
        with self.assertRaises(ValidationError):
            RCAResult.model_validate(payload)


class V12ReferenceTests(unittest.TestCase):
    def test_build_and_parse_evidence_ref(self) -> None:
        value = build_evidence_ref(REQUEST_ID, "metrics", "sample-1")
        self.assertEqual(
            value,
            "evidence://req-20260715-0001/metrics/sample-1",
        )
        parsed = parse_contract_ref(value)
        self.assertEqual(parsed["request_id"], REQUEST_ID)
        self.assertEqual(parsed["scheme"], "evidence")
        self.assertEqual(parsed["kind"], "metrics")

    def test_wrong_reference_request_id_fails(self) -> None:
        payload = load_fixture("valid_evidence_envelope.json")
        payload["evidence_refs"] = [
            "evidence://other-request/metrics/sample-1"
        ]
        with self.assertRaises(ValidationError):
            EvidenceEnvelope.model_validate(payload)

    def test_non_evidence_scheme_fails_in_evidence_refs(self) -> None:
        payload = load_fixture("valid_report_artifact.json")
        payload["evidence_refs"] = [
            f"artifact://{REQUEST_ID}/metrics/sample-1"
        ]
        with self.assertRaises(ValidationError):
            ReportArtifact.model_validate(payload)

    def test_malformed_reference_raises_normalized_error(self) -> None:
        with self.assertRaises(EvidenceReferenceError):
            parse_contract_ref("not-a-reference")


class V12SanitizationTests(unittest.TestCase):
    def test_sensitive_mapping_values_are_redacted_recursively(self) -> None:
        payload = {
            "safe": 1,
            "nested": {
                "api_key": "should-not-survive",
                "notification_mode": "card",
                "password": "should-not-survive",
            },
        }
        sanitized = sanitize_sensitive_data(payload)
        self.assertEqual(sanitized["nested"]["api_key"], REDACTED_VALUE)
        self.assertEqual(sanitized["nested"]["password"], REDACTED_VALUE)
        self.assertEqual(sanitized["nested"]["notification_mode"], "card")

    def test_contract_sanitizes_sensitive_facts_before_storage(self) -> None:
        payload = load_fixture("valid_evidence_envelope.json")
        payload["facts"]["api_token"] = "should-not-survive"
        model = EvidenceEnvelope.model_validate(payload)
        self.assertEqual(model.facts["api_token"], REDACTED_VALUE)
        self.assertNotIn("should-not-survive", stable_json_dumps(model))

    def test_stable_json_sorts_mapping_keys(self) -> None:
        self.assertEqual(
            stable_json_dumps({"b": 2, "a": 1}),
            '{"a":1,"b":2}',
        )

    def test_invalid_json_is_normalized(self) -> None:
        with self.assertRaises(ContractValidationError) as ctx:
            validate_contract_json(UnifiedAlertEvent, "{")
        self.assertTrue(ctx.exception.issues)

    def test_contract_json_root_must_be_object(self) -> None:
        with self.assertRaises(ContractValidationError):
            validate_contract_json(UnifiedAlertEvent, "[]")


class V12OfflineBoundaryTests(unittest.TestCase):
    def test_contract_modules_do_not_import_network_clients(self) -> None:
        paths = [
            PROJECT_ROOT / "netaiops/v12/contracts.py",
            PROJECT_ROOT / "netaiops/v12/status.py",
            PROJECT_ROOT / "netaiops/v12/schema_validator.py",
            PROJECT_ROOT / "netaiops/v12/errors.py",
        ]
        forbidden = (
            "import httpx",
            "import requests",
            "import socket",
            "urllib.request",
            "subprocess.",
            "include_router",
        )
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for token in forbidden:
                self.assertNotIn(token, text, f"{path}: {token}")

    def test_contract_import_has_no_filesystem_side_effect(self) -> None:
        before = {
            path.relative_to(PROJECT_ROOT)
            for path in PROJECT_ROOT.rglob("*")
            if path.is_file()
        }
        __import__("netaiops.v12.contracts")
        after = {
            path.relative_to(PROJECT_ROOT)
            for path in PROJECT_ROOT.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
