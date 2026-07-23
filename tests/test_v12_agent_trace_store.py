from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from netaiops.v12.agent_trace_store import (
    AgentTraceStore,
    AgentTraceStoreError,
)
from netaiops.v12.atomic_writer import (
    AtomicJsonWriter,
    AtomicWriteError,
)
from netaiops.v12.evidence_bundle import EvidenceBundleBuilder
from netaiops.v12.redaction import (
    OMITTED_VALUE,
    redact_for_persistence,
)
from tests.test_v12_evidence_bundle import NOW, REQUEST_ID, result_fixture


class AgentTraceStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name) / "requests"
        self.lock_root = Path(self.temp.name) / "locks"

    def store(self) -> AgentTraceStore:
        def factory(root):
            return AtomicJsonWriter(root, lock_root=self.lock_root)
        return AgentTraceStore(self.base, writer_factory=factory)

    def artifacts(self):
        return EvidenceBundleBuilder(
            utcnow=lambda: NOW
        ).build(result_fixture())

    def test_persist_writes_four_core_files(self) -> None:
        stored = self.store().persist(result_fixture(), self.artifacts())
        self.assertEqual(
            set(stored.files),
            {
                "unified_event.json",
                "evidence_plan.json",
                "agent_runs.json",
                "evidence_bundle.json",
            },
        )

    def test_directory_is_request_v12(self) -> None:
        stored = self.store().persist(result_fixture(), self.artifacts())
        self.assertEqual(
            stored.directory,
            self.base / REQUEST_ID / "v12",
        )

    def test_each_file_has_schema_and_request_id(self) -> None:
        stored = self.store().persist(result_fixture(), self.artifacts())
        for path in stored.files.values():
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], "v12.1")
            self.assertEqual(payload["request_id"], REQUEST_ID)

    def test_file_mode_is_0640(self) -> None:
        stored = self.store().persist(result_fixture(), self.artifacts())
        for path in stored.files.values():
            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertEqual(mode, 0o640)

    def test_directory_mode_is_0750(self) -> None:
        stored = self.store().persist(result_fixture(), self.artifacts())
        mode = stat.S_IMODE(stored.directory.stat().st_mode)
        self.assertEqual(mode, 0o750)

    def test_load_core_round_trip(self) -> None:
        store = self.store()
        store.persist(result_fixture(), self.artifacts())
        loaded = store.load_core(REQUEST_ID)
        self.assertEqual(set(loaded), set({
            "unified_event.json",
            "evidence_plan.json",
            "agent_runs.json",
            "evidence_bundle.json",
        }))

    def test_repeated_persist_is_stable(self) -> None:
        store = self.store()
        first = store.persist(result_fixture(), self.artifacts())
        first_bytes = {
            name: path.read_bytes()
            for name, path in first.files.items()
        }
        second = store.persist(result_fixture(), self.artifacts())
        second_bytes = {
            name: path.read_bytes()
            for name, path in second.files.items()
        }
        self.assertEqual(first_bytes, second_bytes)

    def test_no_temporary_files_remain(self) -> None:
        stored = self.store().persist(result_fixture(), self.artifacts())
        names = [path.name for path in stored.directory.iterdir()]
        self.assertFalse(any(".tmp." in name for name in names))

    def test_concurrent_writes_are_complete_json(self) -> None:
        root = self.base / REQUEST_ID / "v12"
        writer = AtomicJsonWriter(root, lock_root=self.lock_root)

        def write(value: int) -> None:
            writer.write_json(
                "concurrent.json",
                {
                    "schema_version": "v12.1",
                    "request_id": REQUEST_ID,
                    "value": value,
                },
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(write, range(32)))

        payload = json.loads(
            (root / "concurrent.json").read_text(encoding="utf-8")
        )
        self.assertIn(payload["value"], range(32))

    def test_replace_failure_preserves_old_file(self) -> None:
        root = self.base / REQUEST_ID / "v12"
        writer = AtomicJsonWriter(root, lock_root=self.lock_root)
        writer.write_json("item.json", {"value": "old"})

        def broken_replace(source, target):
            raise OSError("simulated interruption")

        broken = AtomicJsonWriter(
            root,
            lock_root=self.lock_root,
            replace_func=broken_replace,
        )
        with self.assertRaises(AtomicWriteError):
            broken.write_json("item.json", {"value": "new"})

        self.assertEqual(
            json.loads((root / "item.json").read_text())["value"],
            "old",
        )
        self.assertFalse(
            any(".tmp." in path.name for path in root.iterdir())
        )

    def test_path_traversal_is_rejected(self) -> None:
        writer = AtomicJsonWriter(
            self.base / REQUEST_ID / "v12",
            lock_root=self.lock_root,
        )
        with self.assertRaises(AtomicWriteError):
            writer.write_json("../escape.json", {})

    def test_absolute_path_is_rejected(self) -> None:
        writer = AtomicJsonWriter(
            self.base / REQUEST_ID / "v12",
            lock_root=self.lock_root,
        )
        with self.assertRaises(AtomicWriteError):
            writer.write_json("/tmp/escape.json", {})

    def test_target_symlink_is_rejected(self) -> None:
        root = self.base / REQUEST_ID / "v12"
        root.mkdir(parents=True)
        outside = Path(self.temp.name) / "outside.json"
        outside.write_text("{}", encoding="utf-8")
        (root / "item.json").symlink_to(outside)
        writer = AtomicJsonWriter(root, lock_root=self.lock_root)
        with self.assertRaises(AtomicWriteError):
            writer.write_json("item.json", {"value": 1})

    def test_request_directory_symlink_is_rejected(self) -> None:
        self.base.mkdir(parents=True)
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        (self.base / REQUEST_ID).symlink_to(outside, target_is_directory=True)
        with self.assertRaises(AgentTraceStoreError):
            self.store().persist(result_fixture(), self.artifacts())

    def test_invalid_request_id_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.store().request_v12_dir("../bad")

    def test_old_v10_v11_artifacts_are_preserved(self) -> None:
        request_root = self.base / REQUEST_ID
        request_root.mkdir(parents=True)
        legacy = request_root / "evidence_bundle.json"
        legacy.write_text('{"legacy":true}\n', encoding="utf-8")
        governance = request_root / "governance.json"
        governance.write_text('{"v11":true}\n', encoding="utf-8")

        self.store().persist(result_fixture(), self.artifacts())

        self.assertEqual(
            legacy.read_text(encoding="utf-8"),
            '{"legacy":true}\n',
        )
        self.assertEqual(
            governance.read_text(encoding="utf-8"),
            '{"v11":true}\n',
        )

    def test_sensitive_keys_are_redacted(self) -> None:
        value = redact_for_persistence(
            {
                "token": "secret-value",
                "nested": {"password": "secret-password"},
            }
        )
        self.assertEqual(value["token"], "[REDACTED]")
        self.assertEqual(value["nested"]["password"], "[REDACTED]")

    def test_raw_payload_keys_are_omitted(self) -> None:
        value = redact_for_persistence(
            {
                "raw_payload": {"secret": "x"},
                "full_device_output": "show run output",
                "full_log": ["event"],
            }
        )
        self.assertEqual(value["raw_payload"], OMITTED_VALUE)
        self.assertEqual(value["full_device_output"], OMITTED_VALUE)
        self.assertEqual(value["full_log"], OMITTED_VALUE)

    def test_agent_runs_are_structured(self) -> None:
        stored = self.store().persist(result_fixture(), self.artifacts())
        payload = json.loads(
            stored.files["agent_runs.json"].read_text(encoding="utf-8")
        )
        self.assertEqual(payload["final_state"], "evidence_collection")
        self.assertEqual(len(payload["agent_runs"]), 6)

    def test_governance_summary_has_no_facts(self) -> None:
        stored = self.store().persist(result_fixture(), self.artifacts())
        serialized = json.dumps(
            stored.governance_summary,
            ensure_ascii=False,
            sort_keys=True,
        )
        self.assertNotIn('"facts"', serialized)
        self.assertFalse(stored.governance_summary["full_facts_copied"])

    def test_governance_summary_contains_only_refs_and_counts(self) -> None:
        summary = self.store().persist(
            result_fixture(),
            self.artifacts(),
        ).governance_summary
        self.assertIn("agent_status_counts", summary)
        self.assertIn("evidence_refs", summary)
        self.assertIn("bundle_status", summary)

    def test_bundle_request_mismatch_is_rejected(self) -> None:
        artifacts = self.artifacts()
        broken = artifacts.evidence_bundle.model_copy(
            update={"request_id": "req-other"}
        )
        from netaiops.v12.evidence_bundle import BundleArtifacts
        with self.assertRaises(AgentTraceStoreError):
            self.store().persist(
                result_fixture(),
                BundleArtifacts(
                    artifacts.unified_event,
                    artifacts.evidence_plan,
                    broken,
                ),
            )

    def test_writer_serializes_without_nan(self) -> None:
        writer = AtomicJsonWriter(
            self.base / REQUEST_ID / "v12",
            lock_root=self.lock_root,
        )
        with self.assertRaises((AtomicWriteError, ValueError)):
            writer.write_json("nan.json", {"value": float("nan")})

    def test_no_network_or_subprocess_imports(self) -> None:
        root = Path(__file__).resolve().parents[1]
        text = "\n".join(
            (root / path).read_text(encoding="utf-8")
            for path in (
                "netaiops/v12/atomic_writer.py",
                "netaiops/v12/agent_trace_store.py",
                "netaiops/v12/evidence_bundle.py",
                "netaiops/v12/redaction.py",
            )
        )
        for token in (
            "import requests",
            "import httpx",
            "import socket",
            "import subprocess",
        ):
            self.assertNotIn(token, text)

    def test_atomic_writer_uses_replace_and_fsync(self) -> None:
        root = Path(__file__).resolve().parents[1]
        text = (root / "netaiops/v12/atomic_writer.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("os.replace", text)
        self.assertIn("os.fsync", text)
        self.assertIn("fcntl.flock", text)

    def test_trace_store_writes_only_v12_subdirectory(self) -> None:
        stored = self.store().persist(result_fixture(), self.artifacts())
        self.assertEqual(stored.directory.name, "v12")
        self.assertEqual(stored.directory.parent.name, REQUEST_ID)


if __name__ == "__main__":
    unittest.main()
