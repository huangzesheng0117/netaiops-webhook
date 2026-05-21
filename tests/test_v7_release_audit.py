import os
import tempfile
import unittest
from pathlib import Path

from netaiops.v7_release_audit import REQUIRED_API_ROUTES, REQUIRED_EXECUTABLES, REQUIRED_FILES, audit_v7_release


class TestV7ReleaseAudit(unittest.TestCase):
    def test_release_audit_passes_for_complete_minimal_tree(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)

            for rel in REQUIRED_FILES:
                p = base / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                if rel == "app.py":
                    pass
                p.write_text("placeholder\n", encoding="utf-8")

            app_text = "\n".join([f'route = "{r}"' for r in REQUIRED_API_ROUTES])
            (base / "app.py").write_text(app_text, encoding="utf-8")

            for rel in REQUIRED_EXECUTABLES:
                p = base / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                if not p.exists():
                    p.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
                p.chmod(p.stat().st_mode | 0o111)

            for rel in [
                "data/memory",
                "data/skill_proposals",
                "data/skill_proposal_reviews",
                "data/skill_drafts",
                "data/learning_reports",
            ]:
                (base / rel).mkdir(parents=True, exist_ok=True)

            (base / "data" / "skill_proposals" / "proposals.jsonl").write_text(
                '{"proposal_id":"skillprop_test","auto_merge_enabled":false}\n',
                encoding="utf-8",
            )
            (base / "data" / "learning_reports" / "reports.jsonl").write_text(
                '{"report_id":"learnreport_test","safety":{"writes_formal_skill":false}}\n',
                encoding="utf-8",
            )

            report = audit_v7_release(base_dir=base, write=True)

            self.assertEqual(report["verdict"], "pass")
            self.assertEqual(report["stage"], "v7.7_release_audit")
            self.assertTrue((base / "docs" / "v7_7_release_audit_snapshot.json").exists())
            self.assertFalse(report["violations"])


if __name__ == "__main__":
    unittest.main()
