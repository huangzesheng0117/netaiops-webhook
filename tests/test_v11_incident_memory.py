from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import timezone
from pathlib import Path

from netaiops.governance.artifact_reader import (
    MAX_JSON_READ_BYTES,
    ArtifactReaderError,
    read_request_artifacts,
)
from netaiops.governance.contracts import EvidenceSourceStatus
from netaiops.governance.memory_builder import (
    build_incident_memory,
    memory_safety_summary,
)
from netaiops.governance.store import GovernanceStore


REQUEST_ID = "20260703_145814_955415_6fe18e1f"


class IncidentMemoryFixture:
    def __init__(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "project"
        self.root.mkdir(parents=True)
        self._write_fixture()

    def close(self) -> None:
        self.tempdir.cleanup()

    def write(self, rel: str, payload: object) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def _write_fixture(self) -> None:
        rid = REQUEST_ID
        self.write(
            f"data/raw/alertmanager_{rid}.json",
            {
                "status": "firing",
                "alerts": [
                    {
                        "labels": {"secret": "must-not-be-copied"},
                        "annotations": {"description": "raw confidential payload"},
                    }
                ],
            },
        )
        self.write(
            f"data/normalized/alertmanager_{rid}.json",
            {
                "request_id": rid,
                "source": "alertmanager",
                "created_at": "2026-07-03T06:58:14+00:00",
                "events": [
                    {
                        "timestamp": "2026-07-03T14:57:00+08:00",
                        "hostname": "switch-01",
                        "device_ip": "10.0.0.1",
                        "vendor": "CISCO",
                        "object_type": "interface",
                        "object_name": "Te1/0/1",
                        "interface": "Te1/0/1",
                        "direction": "outbound",
                        "family": "interface_or_link_utilization_high",
                        "description": "Interface utilization exceeded 80%",
                        "raw_text": "raw alert text that should not be needed",
                    }
                ],
            },
        )
        self.write(
            f"data/analysis/alertmanager_{rid}.analysis.json",
            {
                "request_id": rid,
                "source": "alertmanager",
                "analysis_status": "success",
                "model": "glm-5.2",
                "created_at": "2026-07-03T06:58:15+00:00",
                "result": {
                    "summary": "Traffic is high and requires evidence review.",
                    "suggested_commands": ["show interface"],
                },
            },
        )
        self.write(
            f"data/analysis/alertmanager_{rid}.pipeline.json",
            {"request_id": rid, "pipeline_result": {"status": "ok"}},
        )
        self.write(
            f"data/plans/alertmanager_{rid}.plan.json",
            {
                "request_id": rid,
                "source": "alertmanager",
                "plan_status": "confirmed",
                "summary": "Read-only evidence plan",
                "target_scope": {
                    "hostname": "switch-01",
                    "device_ip": "10.0.0.1",
                    "vendor": "CISCO",
                    "platform": "iosxe",
                    "interface": "Te1/0/1",
                    "direction": "out",
                },
                "classification": {
                    "family": "interface_or_link_utilization_high",
                    "match_reason": "matched_catalog_alertname",
                },
                "playbook": {"matched": True, "playbook_id": "fixture"},
                "policy_result": {"status": "allowed"},
            },
        )
        self.write(
            f"data/prometheus_evidence/alertmanager_{rid}.prometheus_evidence.json",
            {
                "request_id": rid,
                "status": "success",
                "ok": True,
                "profile": "interface_utilization_high",
                "evidences": [{"samples": [1, 2, 3], "query": "secret query"}],
                "summary_text": "metrics summary",
            },
        )
        self.write(
            f"data/execution/alertmanager_{rid}.execution.json",
            {
                "request_id": rid,
                "execution_status": "completed",
                "readonly_only": True,
                "execution_source": "playbook",
                "stats": {
                    "total_commands": 2,
                    "completed_commands": 2,
                    "failed_commands": 0,
                    "partial_commands": 0,
                    "hard_error_count": 0,
                },
                "command_results": [
                    {
                        "command": "show interface",
                        "output": "very long raw device output",
                    }
                ],
            },
        )
        self.write(
            f"data/reviews/alertmanager_{rid}.review.json",
            {
                "request_id": rid,
                "review_status": "completed",
                "execution_status": "completed",
                "family": "interface_or_link_utilization_high",
                "conclusion": "Evidence indicates a transient utilization peak.",
                "key_findings": ["one", "two"],
                "recommendations": ["observe"],
            },
        )
        hub = f"data/evidence_hub/requests/{rid}"
        self.write(
            f"{hub}/meta.json",
            {"status": "generated", "data": {"request_id": rid}},
        )
        self.write(
            f"{hub}/summary.json",
            {
                "request_id": rid,
                "missing_sections": [],
                "read_error_sections": [],
                "summary": {
                    "family": "interface_or_link_utilization_high",
                    "object": "Te1/0/1",
                    "device": {"hostname": "switch-01", "device_ip": "10.0.0.1"},
                    "evidence_status": {
                        "metrics": "found",
                        "device": "found",
                        "review": "found",
                    },
                },
            },
        )
        self.write(
            f"{hub}/notification_summary.json",
            {"status": "derived", "data": {"title": "fixture"}},
        )
        self.write(
            f"{hub}/notification_summary_slim.json",
            {
                "request_id": rid,
                "alert_content": "Interface utilization exceeded 80%",
                "detail_available": True,
                "detail_url": f"http://127.0.0.1/evidence-ui/{rid}",
            },
        )
        self.write(
            f"{hub}/ai_analysis_card_send_result.json",
            {
                "ok": True,
                "sent": True,
                "transport": "universal_card",
                "http_code": 200,
                "business_code": "200",
                "payload_preview": {"forbidden": "must not be copied"},
            },
        )
        self.write(
            f"{hub}/ai_analysis_card.json",
            {"request_id": rid, "card_type": "networkAiAnalysisCard"},
        )


class IncidentMemoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = IncidentMemoryFixture()

    def tearDown(self) -> None:
        self.fx.close()

    def bundle(self):
        return read_request_artifacts(self.fx.root, REQUEST_ID)

    def memory(self):
        return build_incident_memory(
            self.bundle(),
            source_git_metadata={
                "available": True,
                "branch": "main",
                "commit": "a" * 40,
                "dirty": False,
            },
        )

    def test_reader_rejects_invalid_request_id(self) -> None:
        with self.assertRaises(ArtifactReaderError):
            read_request_artifacts(self.fx.root, "../escape")

    def test_reader_rejects_missing_project_root(self) -> None:
        with self.assertRaises(ArtifactReaderError):
            read_request_artifacts(self.fx.root / "missing", REQUEST_ID)

    def test_reader_discovers_known_artifacts(self) -> None:
        bundle = self.bundle()
        self.assertGreaterEqual(bundle.artifact_count, 12)
        self.assertIn("normalized_event", bundle.documents)
        self.assertIn("evidence_hub_summary", bundle.documents)
        self.assertEqual(bundle.read_errors, ())

    def test_artifact_refs_have_hash_size_and_relative_path(self) -> None:
        for ref in self.bundle().artifact_refs:
            self.assertEqual(len(ref.sha256), 64)
            self.assertGreater(ref.size_bytes, 0)
            self.assertFalse(ref.path.startswith("/"))
            self.assertNotIn("..", Path(ref.path).parts)

    def test_corrupt_json_is_isolated(self) -> None:
        path = self.fx.root / f"data/reviews/alertmanager_{REQUEST_ID}.review.json"
        path.write_text("{not json", encoding="utf-8")
        bundle = self.bundle()
        self.assertEqual(len(bundle.read_errors), 1)
        self.assertEqual(bundle.read_errors[0]["kind"], "review")
        memory = build_incident_memory(bundle, source_git_metadata={})
        self.assertIn("artifact_read_error", memory.quality_flags)

    def test_oversized_json_is_not_embedded(self) -> None:
        path = self.fx.root / f"data/analysis/alertmanager_{REQUEST_ID}.analysis.json"
        with path.open("wb") as handle:
            handle.truncate(MAX_JSON_READ_BYTES + 1)
        bundle = self.bundle()
        self.assertTrue(any("file_too_large" in item["error"] for item in bundle.read_errors))

    def test_symlink_artifact_is_ignored(self) -> None:
        path = self.fx.root / f"data/reviews/alertmanager_{REQUEST_ID}.review.json"
        path.unlink()
        outside = Path(self.fx.tempdir.name) / "outside.json"
        outside.write_text("{}", encoding="utf-8")
        path.symlink_to(outside)
        bundle = self.bundle()
        self.assertIn("review", bundle.missing_kinds)

    def test_duplicate_artifact_generates_warning(self) -> None:
        self.fx.write(
            f"data/analysis/aaa_{REQUEST_ID}.analysis.json",
            {"request_id": REQUEST_ID, "analysis_status": "success"},
        )
        bundle = self.bundle()
        self.assertTrue(any(item.startswith("multiple_artifacts:analysis") for item in bundle.warnings))

    def test_memory_validates_and_uses_deterministic_id(self) -> None:
        memory = self.memory()
        self.assertEqual(memory.memory_id, f"memory_{REQUEST_ID}")
        self.assertEqual(memory.request_id, REQUEST_ID)
        self.assertEqual(memory.family, "interface_or_link_utilization_high")

    def test_alert_time_is_normalised_to_utc(self) -> None:
        alert_time = self.memory().alert_time
        self.assertIsNotNone(alert_time)
        assert alert_time is not None
        self.assertEqual(alert_time.tzinfo, timezone.utc)
        self.assertEqual(alert_time.hour, 6)

    def test_success_evidence_statuses(self) -> None:
        status = self.memory().evidence_status
        self.assertEqual(status["metrics"], EvidenceSourceStatus.SUCCESS)
        self.assertEqual(status["device"], EvidenceSourceStatus.SUCCESS)
        self.assertEqual(status["review"], EvidenceSourceStatus.SUCCESS)
        self.assertEqual(status["notification"], EvidenceSourceStatus.SUCCESS)
        self.assertEqual(status["logs"], EvidenceSourceStatus.NOT_AVAILABLE)

    def test_command_summary_does_not_copy_commands_or_output(self) -> None:
        summary = self.memory().command_summary
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["completed"], 2)
        self.assertNotIn("command_results", summary)
        self.assertNotIn("output", summary)

    def test_notification_result_excludes_payload_preview(self) -> None:
        result = self.memory().notification_result
        self.assertTrue(result["sent"])
        self.assertNotIn("payload_preview", result)

    def test_memory_does_not_embed_raw_artifact_content(self) -> None:
        payload = self.memory().to_payload()
        refs = payload.pop("artifact_refs")
        text = json.dumps(payload, ensure_ascii=False).lower()
        self.assertNotIn("very long raw device output", text)
        self.assertNotIn("must-not-be-copied", text)
        self.assertNotIn("secret query", text)
        self.assertTrue(refs)

    def test_memory_safety_summary(self) -> None:
        result = memory_safety_summary(self.memory())
        self.assertTrue(result["safe"])
        self.assertEqual(result["forbidden_markers_present"], [])
        self.assertEqual(result["logs_status"], "not_available")

    def test_failed_execution_sets_quality_flags(self) -> None:
        path = self.fx.root / f"data/execution/alertmanager_{REQUEST_ID}.execution.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["execution_status"] = "failed"
        data["stats"].update(
            {
                "completed_commands": 0,
                "failed_commands": 2,
                "hard_error_count": 2,
            }
        )
        self.fx.write(path.relative_to(self.fx.root).as_posix(), data)
        memory = self.memory()
        self.assertIn("command_failed", memory.quality_flags)
        self.assertIn("cli_hard_error", memory.quality_flags)
        self.assertEqual(memory.evidence_status["device"], EvidenceSourceStatus.FAILED)

    def test_missing_prometheus_maps_to_no_data_from_hub(self) -> None:
        path = self.fx.root / (
            f"data/prometheus_evidence/alertmanager_{REQUEST_ID}.prometheus_evidence.json"
        )
        path.unlink()
        summary_path = self.fx.root / f"data/evidence_hub/requests/{REQUEST_ID}/summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["summary"]["evidence_status"]["metrics"] = "missing"
        self.fx.write(summary_path.relative_to(self.fx.root).as_posix(), summary)
        memory = self.memory()
        self.assertEqual(memory.evidence_status["metrics"], EvidenceSourceStatus.NO_DATA)
        self.assertIn("prometheus_no_data", memory.quality_flags)

    def test_no_artifacts_cannot_build_memory(self) -> None:
        empty_root = Path(self.fx.tempdir.name) / "empty"
        empty_root.mkdir()
        bundle = read_request_artifacts(empty_root, REQUEST_ID)
        with self.assertRaises(ValueError):
            build_incident_memory(bundle, source_git_metadata={})

    def test_store_round_trip_in_temporary_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = GovernanceStore(Path(tmp))
            memory = self.memory()
            result = store.write("incident_memory", memory.memory_id, memory)
            loaded = store.read("incident_memory", memory.memory_id)
            self.assertEqual(loaded["request_id"], REQUEST_ID)
            self.assertEqual(len(result.sha256), 64)

    def test_cli_builds_memory_only_under_explicit_output_root(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            script = Path(__file__).resolve().parents[1] / "tools" / "v11_build_incident_memory.py"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(script),
                    "--project-root",
                    str(self.fx.root),
                    "--request-id",
                    REQUEST_ID,
                    "--output-root",
                    output,
                    "--json-only",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                timeout=20,
                check=True,
            )
            report = json.loads(completed.stdout)
            self.assertEqual(report["status"], "ok")
            self.assertFalse(any(report["external_calls"].values()))
            self.assertTrue(Path(report["output_file"]).is_file())
            self.assertTrue(str(report["output_file"]).startswith(output))


if __name__ == "__main__":
    unittest.main()
