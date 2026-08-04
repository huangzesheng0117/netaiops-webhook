from __future__ import annotations

import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNNER = PROJECT_ROOT / "tools" / "v12_master_runner.txt"


class V12MasterRunnerTests(unittest.TestCase):
    def test_batch_a_frozen_safety_contract_is_preserved(self):
        text = RUNNER.read_text(encoding="utf-8")
        for expected in (
            'SUPPORTED_BATCHES="A"',
            'PLANNED_BATCHES="A B C D E F G H I J K L M N O P Q"',
            "CONFIRM_COMMIT=YES",
            "CONFIRM_ROLLBACK=YES",
            "RUN_FULL_REPOSITORY=YES",
            "v12: freeze baseline and add controlled multi-agent flags",
            "LC_ALL=C sort -u",
        ):
            self.assertIn(expected, text)

    def test_runner_exposes_additive_batch_q_release_actions(self):
        text = RUNNER.read_text(encoding="utf-8")
        self.assertIn("# BEGIN BATCH Q RELEASE DISPATCH", text)
        self.assertIn("repository-gate", text)
        self.assertIn("post-commit", text)
        self.assertIn("status", text)
        self.assertIn("v12_release_acceptance.py", text)
        self.assertIn('if [[ "$BATCH" == "Q" ]]', text)

    def test_runner_uses_old_git_compatible_origin_read(self):
        text = RUNNER.read_text(encoding="utf-8")
        block = text.split("# BEGIN BATCH Q RELEASE DISPATCH", 1)[1].split(
            "# END BATCH Q RELEASE DISPATCH", 1
        )[0]
        self.assertIn("git config --get remote.origin.url", block)
        self.assertNotIn("git remote get-url", block)
        self.assertNotIn("git -C", block)

    def test_batch_q_block_contains_no_git_write(self):
        text = RUNNER.read_text(encoding="utf-8")
        block = text.split("# BEGIN BATCH Q RELEASE DISPATCH", 1)[1].split(
            "# END BATCH Q RELEASE DISPATCH", 1
        )[0]
        for token in (
            "git add .",
            "git add -A",
            "git reset --hard",
            "git clean -fd",
            "git push --force",
            "git commit -m",
            "git push origin",
        ):
            self.assertNotIn(token, block)


if __name__ == "__main__":
    unittest.main()
