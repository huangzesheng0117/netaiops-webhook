from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import yaml

from netaiops.v12.p2_real_canary import P2CanarySample
from netaiops.v12.primary_release import (
    APPROVED_FAMILIES,
    PRIMARY_SCHEMA_VERSION,
    PrimaryReleaseError,
    load_primary_settings,
    run_v12_primary_after_legacy_safe,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def write_runtime(path: Path, **updates) -> None:
    payload = {
        "schema_version": PRIMARY_SCHEMA_VERSION,
        "activation_id": "q-test",
        "enabled": True,
        "mode": "primary",
        "fail_open_to_legacy": True,
        "notifications_use_v12": False,
        "logs_enabled": False,
        "knowledge_enabled": False,
        "metrics_real_calls_enabled": True,
        "device_real_calls_enabled": True,
        "rca_real_calls_enabled": True,
        "reuse_existing_evidence_before_real_call": True,
        "allowed_families": list(APPROVED_FAMILIES),
        "max_metrics_calls_per_request": 1,
        "max_device_calls_per_request": 1,
        "max_rca_calls_per_request": 1,
        "max_total_external_calls_per_request": 3,
    }
    payload.update(updates)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def sample(request_id: str, family: str = APPROVED_FAMILIES[0]) -> P2CanarySample:
    return P2CanarySample(
        original_request_id=request_id,
        source="alertmanager",
        family=family,
        raw_payload={"alerts": [{"status": "firing"}]},
        normalized_event={"status": "firing", "family": family},
        legacy_plan={"request_id": request_id},
        target_scope={"device_ip": "10.0.0.1", "interface": "Ethernet1/1"},
        command_candidate={"command": "show interface Ethernet1/1"},
        metrics_profile="interface_utilization",
        metrics_query_name="interface_input_utilization_percent",
        metrics_target={"instance": "10.0.0.1", "ifName": "Ethernet1/1"},
        raw_path=f"raw_{request_id}.json",
        normalized_path=f"normalized_{request_id}.json",
        plan_path=f"plan_{request_id}.json",
        discovery_mode="pinned_request_id",
    )


class FakeRunner:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = 0

    async def run(self, request_id: str):
        self.calls += 1
        if self.error:
            raise self.error
        return self.result


class PrimarySettingsTests(unittest.TestCase):
    def test_example_is_safe_and_primary(self):
        raw = yaml.safe_load(
            (PROJECT_ROOT / "config" / "v12_primary.example.yaml").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(raw["enabled"])
        self.assertEqual(raw["mode"], "primary")
        self.assertTrue(raw["fail_open_to_legacy"])
        self.assertFalse(raw["notifications_use_v12"])
        self.assertFalse(raw["logs_enabled"])
        self.assertFalse(raw["knowledge_enabled"])

    def test_valid_runtime_loads(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "primary.yaml"
            write_runtime(path)
            settings = load_primary_settings(path)
            self.assertTrue(settings.enabled)
            self.assertEqual(settings.mode, "primary")

    def test_shadow_mode_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "primary.yaml"
            write_runtime(path, mode="shadow")
            with self.assertRaises(PrimaryReleaseError):
                load_primary_settings(path)

    def test_unapproved_family_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "primary.yaml"
            write_runtime(path, allowed_families=["bgp_neighbor_down"])
            with self.assertRaises(PrimaryReleaseError):
                load_primary_settings(path)

    def test_runtime_config_is_gitignored(self):
        text = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("config/v12_primary.yaml", text)


class PrimaryEntryTests(unittest.TestCase):
    def _roots(self, root: Path):
        return {
            "project_root": root,
            "trace_root": root / "data" / "evidence_hub" / "requests",
            "governance_root": root / "data" / "governance" / "agent_traces",
            "runtime_root": root / "data" / "v12_primary_runtime",
        }

    def test_missing_runtime_is_disabled_without_external_calls(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = run_v12_primary_after_legacy_safe(
                request_id="q-request-1",
                runtime_config=root / "missing.yaml",
                notify_result={"ok": True},
                **self._roots(root),
            )
            self.assertEqual(result["status"], "disabled")
            self.assertEqual(result["prometheus_mcp_calls"], 0)
            self.assertEqual(result["netmiko_mcp_calls"], 0)
            self.assertEqual(result["glm_rca_calls"], 0)
            self.assertFalse(result["notification_sent"])

    def test_unapproved_family_falls_back_to_legacy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "primary.yaml"
            write_runtime(config)
            result = run_v12_primary_after_legacy_safe(
                request_id="q-request-2",
                runtime_config=config,
                family_loader=lambda *_args, **_kwargs: "bgp_neighbor_down",
                sample_loader=lambda *_args, **_kwargs: sample(
                    "q-request-2", "bgp_neighbor_down"
                ),
                production_config_loader=lambda *_args, **_kwargs: {},
                notify_result={"ok": True},
                **self._roots(root),
            )
            self.assertEqual(result["status"], "fallback_legacy")
            self.assertEqual(result["reason"], "family_not_approved_for_v12_primary")
            self.assertTrue(result["legacy_preserved"])

    def test_approved_family_completes_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "primary.yaml"
            write_runtime(config)
            fake = FakeRunner(
                {
                    "status": "completed",
                    "governance_ok": True,
                    "call_ledger": {
                        "call_counts": {
                            "prometheus_mcp": 1,
                            "netmiko_mcp": 1,
                            "glm_rca": 1,
                        }
                    },
                }
            )
            result = run_v12_primary_after_legacy_safe(
                request_id="q-request-3",
                runtime_config=config,
                family_loader=lambda *_args, **_kwargs: APPROVED_FAMILIES[0],
                sample_loader=lambda *_args, **_kwargs: sample("q-request-3"),
                production_config_loader=lambda *_args, **_kwargs: {},
                runner_factory=lambda **_kwargs: fake,
                notify_result={"ok": True, "sent_count": 1},
                **self._roots(root),
            )
            self.assertEqual(result["status"], "completed")
            self.assertEqual(fake.calls, 1)
            self.assertEqual(result["legacy_notification_count"], 1)
            self.assertEqual(result["v12_notification_count"], 0)
            self.assertFalse(result["second_card_sent"])
            again = run_v12_primary_after_legacy_safe(
                request_id="q-request-3",
                runtime_config=config,
                family_loader=lambda *_args, **_kwargs: APPROVED_FAMILIES[0],
                sample_loader=lambda *_args, **_kwargs: sample("q-request-3"),
                production_config_loader=lambda *_args, **_kwargs: {},
                runner_factory=lambda **_kwargs: fake,
                notify_result={"ok": True},
                **self._roots(root),
            )
            self.assertEqual(again["status"], "completed")
            self.assertEqual(fake.calls, 1)

    def test_runner_failure_is_fail_open_and_not_retried(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "primary.yaml"
            write_runtime(config)
            fake = FakeRunner(error=RuntimeError("synthetic failure"))
            result = run_v12_primary_after_legacy_safe(
                request_id="q-request-4",
                runtime_config=config,
                family_loader=lambda *_args, **_kwargs: APPROVED_FAMILIES[0],
                sample_loader=lambda *_args, **_kwargs: sample("q-request-4"),
                production_config_loader=lambda *_args, **_kwargs: {},
                runner_factory=lambda **_kwargs: fake,
                notify_result={"ok": True},
                **self._roots(root),
            )
            self.assertEqual(result["status"], "failed_open")
            self.assertTrue(result["legacy_preserved"])
            self.assertFalse(result["notification_sent"])
            self.assertEqual(fake.calls, 1)

    def test_primary_source_has_no_notification_sender(self):
        text = (
            PROJECT_ROOT / "netaiops" / "v12" / "primary_release.py"
        ).read_text(encoding="utf-8").lower()
        for token in (
            "send_notification(",
            "send_dongdong(",
            "send_universal_card(",
            "collect_log_evidence",
            "search_logs(",
        ):
            self.assertNotIn(token, text)

    def test_app_schedules_primary_after_legacy_notification(self):
        text = (PROJECT_ROOT / "app.py").read_text(encoding="utf-8")
        notify = text.find("notify_result = send_notification(request_id)")
        primary = text.find(
            "background_tasks.add_task(\n"
            "        run_v12_primary_after_legacy_safe,"
        )
        self.assertGreater(notify, 0)
        self.assertGreater(primary, notify)
        self.assertNotIn("run_p1_after_legacy_safe,", text)


if __name__ == "__main__":
    unittest.main()
