from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from netaiops.v13.evidence_owner_contracts import LegacyCallFenceRecord
from netaiops.v13.legacy_call_fence import LegacyCallFence


class LegacyFenceTests(unittest.TestCase):
    def test_default_allows_legacy_until_owner_claims_source(self):
        with tempfile.TemporaryDirectory() as td:
            fence = LegacyCallFence(td)
            self.assertEqual(fence.legacy_action("d3-fence-1", "metrics"), "allow_legacy")
            fence.record(
                LegacyCallFenceRecord(
                    request_id="d3-fence-1",
                    family="interface_status_or_flap",
                    source="metrics",
                    dedup_key="b" * 64,
                    owner="metrics_agent",
                    external_call_already_attempted=True,
                    recorded_at=datetime.now(timezone.utc),
                )
            )
            self.assertEqual(fence.legacy_action("d3-fence-1", "metrics"), "skip_duplicate")
            self.assertEqual(fence.legacy_action("d3-fence-1", "device"), "allow_legacy")

    def test_symlink_request_directory_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "target"
            target.mkdir()
            (root / "req").symlink_to(target, target_is_directory=True)
            fence = LegacyCallFence(root)
            with self.assertRaises(RuntimeError):
                fence.legacy_action("req", "metrics")


if __name__ == "__main__":
    unittest.main()
