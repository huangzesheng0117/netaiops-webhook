from __future__ import annotations

import asyncio
import copy
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from netaiops.v12.historical_replay import (
    FIXTURE_SCHEMA_VERSION,
    HistoricalReplayError,
    discover_fixtures,
    load_fixture,
    replay_case,
    replay_fixture,
    run_replay_suite,
    run_replay_suite_sync,
)
from netaiops.v12.quality_gates import (
    HIGH_CONFIDENCE_THRESHOLD,
    MINIMUM_SCENARIO_COUNT,
    REQUIRED_CATEGORIES,
    evaluate_quality_gates,
)
from netaiops.v12.report_renderer import CURRENT_CARD_KEYS
from netaiops.v12.schema_validator import parse_contract_ref
from netaiops.v12.status import AgentStatus, JudgeStatus
from scripts.run_v12_historical_replay import main as cli_main


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = PROJECT_ROOT / "tests/fixtures/v12/replay"
EXPECTED_FIXTURES = (
    "01_interface_status.json",
    "02_interface_utilization.json",
    "03_traffic_spike.json",
    "04_traffic_drop.json",
    "05_dci.json",
    "06_hardware.json",
    "07_bgp.json",
    "08_ospf.json",
    "09_bfd.json",
    "10_f5.json",
    "11_fortigate.json",
    "12_partial_evidence.json",
    "13_no_data.json",
    "14_not_available.json",
    "15_required_failure.json",
    "16_evidence_conflict.json",
)


def fixture(name: str) -> dict:
    return load_fixture(FIXTURE_ROOT / name)


def replay(name: str) -> dict:
    return asyncio.run(replay_fixture(FIXTURE_ROOT / name))


class HistoricalReplayFixtureTests(unittest.TestCase):
    def test_fixture_set_is_exact(self) -> None:
        self.assertEqual(
            tuple(path.name for path in discover_fixtures(FIXTURE_ROOT)),
            EXPECTED_FIXTURES,
        )

    def test_fixture_count_exceeds_minimum(self) -> None:
        self.assertGreaterEqual(
            len(EXPECTED_FIXTURES),
            MINIMUM_SCENARIO_COUNT,
        )

    def test_fixture_schema_is_frozen(self) -> None:
        for name in EXPECTED_FIXTURES:
            with self.subTest(name=name):
                self.assertEqual(
                    fixture(name)["schema_version"],
                    FIXTURE_SCHEMA_VERSION,
                )

    def test_fixtures_are_sanitized(self) -> None:
        for name in EXPECTED_FIXTURES:
            with self.subTest(name=name):
                self.assertEqual(
                    fixture(name)["source_kind"],
                    "sanitized_historical_request_fixture",
                )

    def test_scenario_ids_are_unique(self) -> None:
        values = [fixture(name)["scenario_id"] for name in EXPECTED_FIXTURES]
        self.assertEqual(len(values), len(set(values)))

    def test_request_ids_are_unique(self) -> None:
        values = [fixture(name)["request_id"] for name in EXPECTED_FIXTURES]
        self.assertEqual(len(values), len(set(values)))

    def test_required_categories_are_covered(self) -> None:
        categories = {fixture(name)["category"] for name in EXPECTED_FIXTURES}
        self.assertTrue(REQUIRED_CATEGORIES.issubset(categories))

    def test_fixture_evidence_sources_are_exact(self) -> None:
        expected = {"metrics", "device", "logs", "knowledge"}
        for name in EXPECTED_FIXTURES:
            with self.subTest(name=name):
                self.assertEqual(set(fixture(name)["evidence"]), expected)

    def test_logs_placeholder_reason_is_frozen(self) -> None:
        for name in EXPECTED_FIXTURES:
            raw = fixture(name)["evidence"]["logs"]
            if raw["status"] == "not_available":
                self.assertEqual(raw["reason"], "logs_evidence_not_approved")

    def test_knowledge_placeholder_reason_is_frozen(self) -> None:
        for name in EXPECTED_FIXTURES:
            raw = fixture(name)["evidence"]["knowledge"]
            if raw["status"] == "not_available":
                self.assertEqual(
                    raw["reason"], "local_knowledge_base_not_built"
                )

    def test_fixture_files_do_not_contain_secret_markers(self) -> None:
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in discover_fixtures(FIXTURE_ROOT)
        ).lower()
        for token in (
            "authorization:",
            "api_key",
            "password",
            "passwd",
            "private_key",
            "bearer ",
        ):
            self.assertNotIn(token, text)

    def test_missing_fixture_directory_fails(self) -> None:
        with self.assertRaises(HistoricalReplayError):
            discover_fixtures(FIXTURE_ROOT / "missing")

    def test_invalid_json_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.json"
            path.write_text("{bad", encoding="utf-8")
            with self.assertRaises(HistoricalReplayError):
                load_fixture(path)

    def test_array_root_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(HistoricalReplayError):
                load_fixture(path)


class HistoricalReplayCaseTests(unittest.TestCase):
    def test_interface_status_replay(self) -> None:
        result = replay("01_interface_status.json")
        self.assertEqual(result["category"], "interface_status")
        self.assertEqual(result["legacy"]["comparison_status"], "matched")

    def test_interface_utilization_replay(self) -> None:
        result = replay("02_interface_utilization.json")
        self.assertEqual(result["category"], "interface_utilization")
        self.assertEqual(result["judge"]["status"], "partial")

    def test_traffic_spike_replay(self) -> None:
        self.assertEqual(
            replay("03_traffic_spike.json")["legacy"]["comparison_status"],
            "matched",
        )

    def test_traffic_drop_replay(self) -> None:
        self.assertEqual(
            replay("04_traffic_drop.json")["legacy"]["comparison_status"],
            "matched",
        )

    def test_dci_replay(self) -> None:
        self.assertEqual(replay("05_dci.json")["category"], "dci")

    def test_hardware_replay(self) -> None:
        self.assertEqual(replay("06_hardware.json")["category"], "hardware")

    def test_bgp_replay(self) -> None:
        self.assertEqual(replay("07_bgp.json")["category"], "bgp")

    def test_ospf_replay(self) -> None:
        self.assertEqual(replay("08_ospf.json")["category"], "ospf")

    def test_bfd_replay(self) -> None:
        self.assertEqual(replay("09_bfd.json")["category"], "bfd")

    def test_f5_replay(self) -> None:
        self.assertEqual(replay("10_f5.json")["category"], "f5")

    def test_fortigate_replay(self) -> None:
        self.assertEqual(replay("11_fortigate.json")["category"], "fortigate")

    def test_partial_required_evidence_caps_confidence(self) -> None:
        result = replay("12_partial_evidence.json")
        self.assertEqual(result["judge"]["status"], "partial")
        maximum = max(
            candidate["confidence"] for candidate in result["rca"]["candidates"]
        )
        self.assertLess(maximum, HIGH_CONFIDENCE_THRESHOLD)

    def test_no_data_is_declared_missing(self) -> None:
        result = replay("13_no_data.json")
        self.assertIn("metrics", result["rca"]["missing_evidence"])
        self.assertEqual(result["source_statuses"]["metrics"], "no_data")

    def test_required_not_available_is_insufficient(self) -> None:
        result = replay("14_not_available.json")
        self.assertEqual(
            result["judge"]["status"], JudgeStatus.INSUFFICIENT.value
        )
        self.assertEqual(result["rca"]["status"], AgentStatus.SKIPPED.value)

    def test_required_failure_is_insufficient(self) -> None:
        result = replay("15_required_failure.json")
        self.assertEqual(result["judge"]["status"], "insufficient")
        self.assertEqual(result["rca"]["candidates"], [])

    def test_explicit_conflict_is_blocked(self) -> None:
        result = replay("16_evidence_conflict.json")
        self.assertEqual(result["judge"]["status"], JudgeStatus.BLOCKED.value)
        self.assertGreaterEqual(len(result["judge"]["conflicts"]), 1)

    def test_all_references_parse(self) -> None:
        for name in EXPECTED_FIXTURES:
            result = replay(name)
            for reference in result["all_refs"]:
                parsed = parse_contract_ref(reference)
                self.assertEqual(parsed["request_id"], result["request_id"])

    def test_replay_is_deterministic(self) -> None:
        first = replay("01_interface_status.json")
        second = replay("01_interface_status.json")
        self.assertEqual(first["fingerprint"], second["fingerprint"])

    def test_report_card_keys_are_compatible(self) -> None:
        result = replay("01_interface_status.json")
        actual = result["report"]["compatibility_card_keys"]
        expected = list(CURRENT_CARD_KEYS)
        self.assertEqual(len(actual), len(expected))
        self.assertEqual(set(actual), set(expected))

    def test_report_never_sends_notification(self) -> None:
        result = replay("01_interface_status.json")
        plan = result["report"]["notification_plan"]
        self.assertFalse(plan["send_notification"])
        self.assertEqual(plan["notification_count"], 0)
        self.assertFalse(result["report"]["notification_sent"])

    def test_no_second_card(self) -> None:
        plan = replay("01_interface_status.json")["report"]["notification_plan"]
        self.assertFalse(plan["second_card_sent"])

    def test_no_production_card_replacement(self) -> None:
        plan = replay("01_interface_status.json")["report"]["notification_plan"]
        self.assertFalse(plan["production_card_replaced"])

    def test_mock_glm_only_for_allowed_rca(self) -> None:
        result = replay("01_interface_status.json")
        self.assertTrue(result["external_calls"]["mock_glm"])
        self.assertFalse(result["external_calls"]["production_glm"])

    def test_mock_glm_not_called_when_judge_blocks(self) -> None:
        result = replay("16_evidence_conflict.json")
        self.assertFalse(result["external_calls"]["mock_glm"])
        self.assertEqual(result["mock_glm_call_count"], 0)

    def test_no_mcp_calls(self) -> None:
        result = replay("01_interface_status.json")
        for key in (
            "prometheus_mcp",
            "netmiko_mcp",
            "evidence_mcp",
            "ops_es_api",
            "analytics_mcp",
        ):
            self.assertFalse(result["external_calls"][key])

    def test_no_tool_calls(self) -> None:
        self.assertFalse(
            replay("01_interface_status.json")["external_calls"]["tool"]
        )

    def test_no_network_when_socket_is_blocked(self) -> None:
        with mock.patch.object(
            socket,
            "create_connection",
            side_effect=AssertionError("network forbidden"),
        ):
            result = replay("01_interface_status.json")
        self.assertEqual(result["legacy"]["comparison_status"], "matched")

    def test_invalid_fixture_schema_fails(self) -> None:
        raw = fixture("01_interface_status.json")
        raw["schema_version"] = "bad"
        with self.assertRaises(HistoricalReplayError):
            asyncio.run(replay_case(raw))

    def test_unsanitized_source_kind_fails(self) -> None:
        raw = fixture("01_interface_status.json")
        raw["source_kind"] = "production_raw_payload"
        with self.assertRaises(HistoricalReplayError):
            asyncio.run(replay_case(raw))

    def test_missing_evidence_source_fails(self) -> None:
        raw = fixture("01_interface_status.json")
        raw["evidence"].pop("logs")
        with self.assertRaises(HistoricalReplayError):
            asyncio.run(replay_case(raw))


class HistoricalReplaySuiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = run_replay_suite_sync(FIXTURE_ROOT)

    def test_suite_passes(self) -> None:
        self.assertEqual(self.report["status"], "passed")

    def test_suite_case_count(self) -> None:
        self.assertEqual(self.report["case_count"], len(EXPECTED_FIXTURES))

    def test_all_cases_are_deterministic(self) -> None:
        self.assertEqual(
            self.report["deterministic_case_count"], len(EXPECTED_FIXTURES)
        )

    def test_quality_gate_has_no_violations(self) -> None:
        self.assertEqual(self.report["quality_gates"]["violation_count"], 0)

    def test_quality_gate_categories_complete(self) -> None:
        observed = set(self.report["quality_gates"]["observed_categories"])
        self.assertTrue(REQUIRED_CATEGORIES.issubset(observed))

    def test_suite_has_no_external_calls(self) -> None:
        self.assertTrue(
            all(value is False for value in self.report["external_calls"].values())
        )

    def test_suite_async_entrypoint(self) -> None:
        report = asyncio.run(run_replay_suite(FIXTURE_ROOT))
        self.assertEqual(report["status"], "passed")

    def test_cli_returns_zero(self) -> None:
        self.assertEqual(cli_main(["--fixtures", str(FIXTURE_ROOT)]), 0)

    def test_cli_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            rc = cli_main(
                ["--fixtures", str(FIXTURE_ROOT), "--output", str(output)]
            )
            self.assertEqual(rc, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "passed")


class QualityGateNegativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = run_replay_suite_sync(FIXTURE_ROOT)["cases"]

    def evaluate(self, mutate):
        cases = copy.deepcopy(self.cases)
        mutate(cases)
        return evaluate_quality_gates(cases)

    @staticmethod
    def codes(report):
        return {item["code"] for item in report["violations"]}

    def test_missing_category_fails(self) -> None:
        def mutate(cases):
            cases[:] = [case for case in cases if case["category"] != "f5"]
        self.assertIn("required_categories_missing", self.codes(self.evaluate(mutate)))

    def test_duplicate_scenario_id_fails(self) -> None:
        def mutate(cases):
            cases[1]["scenario_id"] = cases[0]["scenario_id"]
        self.assertIn("duplicate_scenario_id", self.codes(self.evaluate(mutate)))

    def test_invalid_ref_fails(self) -> None:
        def mutate(cases):
            cases[0]["all_refs"].append("invalid-ref")
        self.assertIn("reference_not_parseable", self.codes(self.evaluate(mutate)))

    def test_foreign_ref_fails(self) -> None:
        def mutate(cases):
            cases[0]["all_refs"].append(
                "evidence://other-request/metrics/metric-1"
            )
        self.assertIn(
            "reference_request_id_mismatch", self.codes(self.evaluate(mutate))
        )

    def test_required_missing_high_confidence_fails(self) -> None:
        def mutate(cases):
            target = next(case for case in cases if case["category"] == "no_data")
            target["rca"]["candidates"][0]["confidence"] = 0.95
        self.assertIn(
            "required_missing_high_confidence", self.codes(self.evaluate(mutate))
        )

    def test_missing_inheritance_fails(self) -> None:
        def mutate(cases):
            cases[0]["rca"]["missing_evidence"] = []
        self.assertIn(
            "rca_missing_evidence_not_inherited", self.codes(self.evaluate(mutate))
        )

    def test_candidate_missing_inheritance_fails(self) -> None:
        def mutate(cases):
            cases[0]["rca"]["candidates"][0]["missing_evidence"] = []
        self.assertIn(
            "candidate_missing_evidence_not_inherited",
            self.codes(self.evaluate(mutate)),
        )

    def test_empty_uncertainties_fails(self) -> None:
        def mutate(cases):
            cases[0]["rca"]["candidates"][0]["uncertainties"] = []
        self.assertIn(
            "candidate_uncertainties_empty", self.codes(self.evaluate(mutate))
        )

    def test_unavailable_claimed_normal_fails(self) -> None:
        def mutate(cases):
            cases[0]["rca"]["candidates"][0]["statement"] = "Logs are normal."
        self.assertIn(
            "unavailable_source_claimed_normal", self.codes(self.evaluate(mutate))
        )

    def test_legacy_mismatch_fails(self) -> None:
        def mutate(cases):
            cases[0]["legacy"]["comparison_status"] = "mismatch"
        self.assertIn("legacy_comparison_failed", self.codes(self.evaluate(mutate)))

    def test_card_key_drift_fails(self) -> None:
        def mutate(cases):
            cases[0]["report"]["compatibility_card_keys"].append("new_field")
        self.assertIn(
            "compatibility_card_key_drift", self.codes(self.evaluate(mutate))
        )

    def test_notification_send_fails(self) -> None:
        def mutate(cases):
            cases[0]["report"]["notification_plan"]["send_notification"] = True
        self.assertIn(
            "notification_side_effect_detected", self.codes(self.evaluate(mutate))
        )

    def test_notification_count_fails(self) -> None:
        def mutate(cases):
            cases[0]["report"]["notification_plan"]["notification_count"] = 1
        self.assertIn(
            "notification_side_effect_detected", self.codes(self.evaluate(mutate))
        )

    def test_second_card_fails(self) -> None:
        def mutate(cases):
            cases[0]["report"]["notification_plan"]["second_card_sent"] = True
        self.assertIn(
            "notification_side_effect_detected", self.codes(self.evaluate(mutate))
        )

    def test_card_replacement_fails(self) -> None:
        def mutate(cases):
            cases[0]["report"]["notification_plan"][
                "production_card_replaced"
            ] = True
        self.assertIn(
            "notification_side_effect_detected", self.codes(self.evaluate(mutate))
        )

    def test_production_glm_fails(self) -> None:
        def mutate(cases):
            cases[0]["external_calls"]["production_glm"] = True
        self.assertIn("external_call_detected", self.codes(self.evaluate(mutate)))

    def test_mcp_call_fails(self) -> None:
        def mutate(cases):
            cases[0]["external_calls"]["prometheus_mcp"] = True
        self.assertIn("external_call_detected", self.codes(self.evaluate(mutate)))

    def test_nondeterministic_case_fails(self) -> None:
        def mutate(cases):
            cases[0]["deterministic"] = False
        self.assertIn("replay_not_deterministic", self.codes(self.evaluate(mutate)))

    def test_judge_status_mismatch_fails(self) -> None:
        def mutate(cases):
            cases[0]["expected"]["judge_status"] = "ready"
        self.assertIn("judge_status_mismatch", self.codes(self.evaluate(mutate)))

    def test_rca_status_mismatch_fails(self) -> None:
        def mutate(cases):
            cases[0]["expected"]["rca_status"] = "success"
        self.assertIn("rca_status_mismatch", self.codes(self.evaluate(mutate)))

    def test_execution_error_fails(self) -> None:
        def mutate(cases):
            cases[0]["execution_error"] = "synthetic failure"
        self.assertIn("replay_execution_error", self.codes(self.evaluate(mutate)))


class BatchOBoundaryTests(unittest.TestCase):
    def test_production_modules_have_no_network_clients(self) -> None:
        text = "\n".join(
            (PROJECT_ROOT / path).read_text(encoding="utf-8").lower()
            for path in (
                "netaiops/v12/historical_replay.py",
                "netaiops/v12/quality_gates.py",
                "scripts/run_v12_historical_replay.py",
            )
        )
        for token in (
            "import requests",
            "import httpx",
            "import socket",
            "urllib.request",
            "subprocess.",
            "send_notification(",
            "send_dongdong(",
            "fastmcp(",
            "openai(",
        ):
            self.assertNotIn(token, text)

    def test_replay_does_not_read_production_data_root(self) -> None:
        text = (PROJECT_ROOT / "netaiops/v12/historical_replay.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("/opt/netaiops-webhook/data", text)

    def test_cli_default_is_test_fixture_root(self) -> None:
        text = (PROJECT_ROOT / "scripts/run_v12_historical_replay.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("tests/fixtures/v12/replay", text)

    def test_version_is_promoted_by_batch_q_release(self) -> None:
        self.assertEqual(
            (PROJECT_ROOT / "VERSION").read_text(encoding="utf-8").strip(),
            "12.0.0-v12-controlled-multi-agent",
        )


if __name__ == "__main__":
    unittest.main()
