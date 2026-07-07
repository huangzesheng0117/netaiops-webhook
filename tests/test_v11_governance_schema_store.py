from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from netaiops.governance.contracts import GOVERNANCE_SCHEMA_VERSION
from netaiops.governance.schemas import (
    ArtifactReference,
    IncidentMemoryRecord,
    LearningSignalRecord,
    ReplayRecord,
    validate_governance_payload,
)
from netaiops.governance.store import (
    CorruptRecordError,
    GovernanceStore,
    GovernanceStoreError,
    RecordExistsError,
    SensitiveContentError,
    UnsafeStorePathError,
    find_sensitive_paths,
)


def artifact(kind: str = "analysis") -> dict:
    return {
        "kind": kind,
        "path": f"data/{kind}/fixture.json",
        "exists": False,
        "sha256": "",
        "size_bytes": 0,
    }


def memory_payload(memory_id: str = "memory-001") -> dict:
    return {
        "schema_version": GOVERNANCE_SCHEMA_VERSION,
        "memory_id": memory_id,
        "request_id": "20260703_145814_955415_6fe18e1f",
        "created_at": "2026-07-07T00:00:00+00:00",
        "source_type": "alertmanager",
        "alert_time": "2026-07-03T07:58:14+00:00",
        "device": {"hostname": "SH16-G03-DCI-BN-SW01", "ip": "10.0.0.1"},
        "object": {"type": "interface", "name": "Ethernet1/1"},
        "family": "interface_status_or_flap",
        "alert_summary": "接口状态异常",
        "analysis_summary": "历史分析摘要",
        "evidence_status": {
            "metrics": "success",
            "device": "success",
            "logs": "not_available",
        },
        "command_summary": {"success": 3, "failed": 0},
        "review_summary": {"status": "completed"},
        "notification_result": {"status": "success"},
        "quality_flags": [],
        "git_metadata": {"branch": "main", "commit": "fixture"},
        "artifact_refs": [artifact()],
    }


def signal_payload(signal_id: str = "signal-001") -> dict:
    return {
        "schema_version": GOVERNANCE_SCHEMA_VERSION,
        "signal_id": signal_id,
        "request_id": "20260703_154613_796157_3750fbea",
        "created_at": "2026-07-07T00:00:00+00:00",
        "signal_type": "command_failed",
        "severity": "error",
        "detected_from": ["execution"],
        "reason": "three read-only commands failed",
        "evidence_refs": [artifact("execution")],
        "dedupe_key": "command_failed:interface_status_or_flap",
        "proposal_eligible": True,
    }


class GovernanceSchemaTests(unittest.TestCase):
    def test_incident_memory_parses_and_serialises_utf8(self) -> None:
        model = IncidentMemoryRecord.model_validate(memory_payload())
        payload = model.to_payload()
        self.assertEqual(payload["alert_summary"], "接口状态异常")
        self.assertEqual(payload["evidence_status"]["logs"], "not_available")
        self.assertTrue(payload["created_at"].endswith("Z"))

    def test_naive_datetime_is_rejected(self) -> None:
        payload = memory_payload()
        payload["created_at"] = "2026-07-07T00:00:00"
        with self.assertRaises(ValidationError):
            IncidentMemoryRecord.model_validate(payload)

    def test_extra_fields_are_rejected(self) -> None:
        payload = memory_payload()
        payload["unexpected"] = True
        with self.assertRaises(ValidationError):
            IncidentMemoryRecord.model_validate(payload)

    def test_artifact_reference_rejects_path_traversal(self) -> None:
        with self.assertRaises(ValidationError):
            ArtifactReference(kind="analysis", path="../config.yaml")

    def test_existing_artifact_requires_digest(self) -> None:
        with self.assertRaises(ValidationError):
            ArtifactReference(kind="analysis", path="data/a.json", exists=True)

    def test_unknown_signal_type_is_rejected(self) -> None:
        payload = signal_payload()
        payload["signal_type"] = "invented_signal"
        with self.assertRaises(ValidationError):
            LearningSignalRecord.model_validate(payload)

    def test_signal_requires_evidence(self) -> None:
        payload = signal_payload()
        payload["evidence_refs"] = []
        with self.assertRaises(ValidationError):
            LearningSignalRecord.model_validate(payload)

    def test_offline_replay_rejects_real_external_calls(self) -> None:
        payload = {
            "schema_version": GOVERNANCE_SCHEMA_VERSION,
            "replay_id": "replay-001",
            "request_id": "20260703_145814_955415_6fe18e1f",
            "created_at": "2026-07-07T00:00:00+00:00",
            "mode": "offline",
            "baseline_refs": [artifact()],
            "candidate_refs": [],
            "before": {},
            "after": {},
            "diff": {},
            "quality_delta": {},
            "safety_delta": {},
            "external_calls": {"glm": True},
            "errors": [],
            "warnings": [],
        }
        with self.assertRaises(ValidationError):
            ReplayRecord.model_validate(payload)

    def test_validate_governance_payload_dispatch(self) -> None:
        model = validate_governance_payload("learning_signal", signal_payload())
        self.assertIsInstance(model, LearningSignalRecord)
        with self.assertRaises(ValueError):
            validate_governance_payload("unknown", {})


class GovernanceStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "governance"
        self.store = GovernanceStore(self.root)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_health_uses_temporary_probe_only(self) -> None:
        result = self.store.health()
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["writable"])
        self.assertEqual(list(self.root.glob(".governance-health-*")), [])

    def test_atomic_write_read_and_no_tmp_residue(self) -> None:
        result = self.store.write("incident_memory", "memory-001", memory_payload())
        self.assertTrue(result.created)
        self.assertEqual(len(result.sha256), 64)
        self.assertEqual(self.store.read("incident_memory", "memory-001")["family"], "interface_status_or_flap")
        directory = self.store.collection_dir("incident_memory")
        self.assertEqual(list(directory.glob("*.tmp")), [])
        text = Path(result.path).read_text(encoding="utf-8")
        self.assertIn("接口状态异常", text)
        self.assertNotIn("\\u63a5", text)

    def test_write_accepts_pydantic_model(self) -> None:
        model = IncidentMemoryRecord.model_validate(memory_payload())
        self.store.write("incident_memory", model.memory_id, model)
        self.assertEqual(self.store.read("incident_memory", model.memory_id)["memory_id"], model.memory_id)

    def test_overwrite_false_protects_existing_record(self) -> None:
        self.store.write("incident_memory", "memory-001", memory_payload())
        with self.assertRaises(RecordExistsError):
            self.store.write(
                "incident_memory",
                "memory-001",
                memory_payload(),
                overwrite=False,
            )

    def test_record_id_must_match_payload(self) -> None:
        with self.assertRaises(GovernanceStoreError):
            self.store.write("incident_memory", "memory-other", memory_payload())

    def test_collection_and_record_path_traversal_are_rejected(self) -> None:
        with self.assertRaises(UnsafeStorePathError):
            self.store.write("../data", "memory-001", memory_payload())
        with self.assertRaises(UnsafeStorePathError):
            self.store.write("incident_memory", "../memory", memory_payload())

    def test_sensitive_key_and_bearer_value_are_rejected(self) -> None:
        payload = memory_payload()
        payload["command_summary"]["api_key"] = "do-not-store"
        with self.assertRaises(SensitiveContentError):
            self.store.write("incident_memory", "memory-001", payload)
        self.assertEqual(find_sensitive_paths({"note": "Bearer abc"}), ("$.note",))

    def test_pagination_is_stable(self) -> None:
        for suffix in ("001", "002", "003"):
            record_id = f"memory-{suffix}"
            self.store.write("incident_memory", record_id, memory_payload(record_id))
        first = self.store.list_records("incident_memory", page=1, page_size=2)
        second = self.store.list_records("incident_memory", page=2, page_size=2)
        self.assertEqual(first.total, 3)
        self.assertEqual([item["memory_id"] for item in first.items], ["memory-003", "memory-002"])
        self.assertEqual([item["memory_id"] for item in second.items], ["memory-001"])

    def test_corrupt_file_is_isolated_from_listing(self) -> None:
        self.store.write("incident_memory", "memory-001", memory_payload())
        directory = self.store.collection_dir("incident_memory")
        (directory / "broken.json").write_text("{not-json", encoding="utf-8")
        page = self.store.list_records("incident_memory")
        self.assertEqual(page.total, 1)
        self.assertEqual(page.corrupt_count, 1)
        self.assertEqual(page.errors[0]["record_id"], "broken")
        with self.assertRaises(CorruptRecordError):
            self.store.read("incident_memory", "broken")

    def test_generic_report_requires_schema_and_matching_id(self) -> None:
        payload = {
            "schema_version": GOVERNANCE_SCHEMA_VERSION,
            "report_id": "report-001",
            "created_at": "2026-07-07T00:00:00+00:00",
            "summary": {},
        }
        self.store.write("reports", "report-001", payload)
        self.assertEqual(self.store.read("reports", "report-001")["report_id"], "report-001")
        bad = dict(payload)
        bad["schema_version"] = "old"
        with self.assertRaises(GovernanceStoreError):
            self.store.write("reports", "report-001", bad)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_collection_symlink_outside_root_is_rejected(self) -> None:
        self.root.mkdir(parents=True)
        outside = Path(self.tempdir.name) / "outside"
        outside.mkdir()
        os.symlink(outside, self.root / "signals")
        with self.assertRaises(UnsafeStorePathError):
            self.store.write("signals", "signal-001", signal_payload())


if __name__ == "__main__":
    unittest.main()
