from __future__ import annotations

import os
import shutil
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Dict, Optional


RUNNER_SOURCE = (
    Path(__file__).resolve().parents[1]
    / "tools"
    / "v11_governance_master_runner.txt"
)


class RunnerHarness:
    def __init__(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "project"
        self.state_root = Path(self.tempdir.name) / "state"
        self.fakebin = Path(self.tempdir.name) / "fakebin"
        self.root.mkdir(parents=True)
        self.fakebin.mkdir(parents=True)
        self._build_fake_curl()
        self._build_fake_python()
        self._build_project()

    def close(self) -> None:
        self.tempdir.cleanup()

    def _build_fake_curl(self) -> None:
        curl = self.fakebin / "curl"
        curl.write_text(
            """#!/usr/bin/env bash
set -e
printf '%s\\n' '{"status":"ok","service":"runner-selftest","version":"test"}'
""",
            encoding="utf-8",
        )
        curl.chmod(0o755)

    def _build_fake_python(self) -> None:
        python = self.fakebin / "python"
        python.write_text(
            "#!/usr/bin/env bash\n"
            f'exec "{sys.executable}" -S "$@"\n',
            encoding="utf-8",
        )
        python.chmod(0o755)

    def _run(
        self,
        args: list[str],
        *,
        check: bool = True,
        env: Optional[Dict[str, str]] = None,
    ) -> subprocess.CompletedProcess[str]:
        merged = os.environ.copy()
        merged.update(
            {
                "PATH": f"{self.fakebin}:{merged.get('PATH', '')}",
                "PYTHONNOUSERSITE": "1",
                "PYTHONPATH": "",
            }
        )
        if env:
            merged.update(env)
        return subprocess.run(
            args,
            cwd=self.root,
            env=merged,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=check,
        )

    def git(
        self,
        *args: str,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return self._run(["git", *args], check=check)

    def runner(
        self,
        action: str,
        batch: int = 0,
        *,
        check: bool = False,
        extra_env: Optional[Dict[str, str]] = None,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "PROJECT_ROOT": str(self.root),
            "STATE_ROOT": str(self.state_root),
            "BASE_URL": "http://runner-selftest.invalid",
            "EXPECTED_BRANCH": "main",
        }
        if extra_env:
            env.update(extra_env)
        return self._run(
            [
                "bash",
                str(
                    self.root
                    / "tools"
                    / "v11_governance_master_runner.txt"
                ),
                action,
                str(batch),
            ],
            check=check,
            env=env,
        )

    def _write(self, rel: str, text: str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _build_project(self) -> None:
        self._write(
            "venv/bin/activate",
            'export VIRTUAL_ENV="${PROJECT_ROOT:-$(pwd)}/venv"\n',
        )
        self._write(
            ".gitignore",
            "__pycache__/\n*.pyc\n",
        )
        (self.root / "tools").mkdir(parents=True, exist_ok=True)
        shutil.copy2(
            RUNNER_SOURCE,
            self.root
            / "tools"
            / "v11_governance_master_runner.txt",
        )

        self._write(
            "netaiops/governance/__init__.py",
            '"""fixture governance package."""\n',
        )
        self._write(
            "netaiops/governance/contracts.py",
            "VALUE = 1\n",
        )
        self._write(
            "tools/v11_baseline_inventory.py",
            """\
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--project-root", required=True)
parser.add_argument("--request-id", required=True)
parser.add_argument("--json-out", required=True)
args = parser.parse_args()
path = Path(args.json_out)
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(
    json.dumps(
        {
            "status": "ok",
            "request_id": args.request_id,
            "project_root": args.project_root,
        }
    ) + "\\n",
    encoding="utf-8",
)
""",
        )
        self._write(
            "tests/test_v11_governance_contracts.py",
            """\
import unittest

class ContractFixtureTests(unittest.TestCase):
    def test_fixture(self):
        self.assertTrue(True)

if __name__ == "__main__":
    unittest.main()
""",
        )

        self.git("init")
        self.git("checkout", "-b", "main")
        self.git("config", "user.email", "runner@example.invalid")
        self.git("config", "user.name", "Runner Test")
        self.git("add", ".")
        self.git("commit", "-m", "baseline")

    def modify_all_batch0_files(self) -> None:
        files = [
            "netaiops/governance/__init__.py",
            "netaiops/governance/contracts.py",
            "tools/v11_baseline_inventory.py",
            "tests/test_v11_governance_contracts.py",
        ]
        for rel in files:
            path = self.root / rel
            with path.open("a", encoding="utf-8") as handle:
                handle.write("\n# changed by runner test\n")


class GovernanceMasterRunnerV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = RunnerHarness()

    def tearDown(self) -> None:
        self.h.close()

    def test_prepare_rejects_dirty_worktree(self) -> None:
        (self.h.root / "unrelated.txt").write_text(
            "dirty\n",
            encoding="utf-8",
        )
        result = self.h.runner("prepare")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("worktree must be clean", result.stdout)

    def test_prepare_and_verify_success(self) -> None:
        prepared = self.h.runner("prepare")
        self.assertEqual(prepared.returncode, 0, prepared.stdout)

        self.h.modify_all_batch0_files()
        verified = self.h.runner("verify")
        self.assertEqual(verified.returncode, 0, verified.stdout)
        self.assertIn("verification passed", verified.stdout)

        stamp = (
            self.h.state_root
            / "batch_0"
            / "verified_digest.txt"
        )
        self.assertTrue(stamp.is_file())
        self.assertEqual(len(stamp.read_text().strip()), 64)

    def test_verify_detects_unexpected_staged_file(self) -> None:
        prepared = self.h.runner("prepare")
        self.assertEqual(prepared.returncode, 0, prepared.stdout)

        self.h.modify_all_batch0_files()
        (self.h.root / "unexpected.txt").write_text(
            "unexpected\n",
            encoding="utf-8",
        )
        self.h.git("add", "unexpected.txt")

        verified = self.h.runner("verify")
        self.assertNotEqual(verified.returncode, 0, verified.stdout)
        self.assertIn(
            "worktree scope does not match",
            verified.stdout,
        )
        self.assertIn("unexpected.txt", verified.stdout)

    def test_rollback_refuses_after_head_changes(self) -> None:
        prepared = self.h.runner("prepare")
        self.assertEqual(prepared.returncode, 0, prepared.stdout)

        self.h.modify_all_batch0_files()
        self.h.git("add", ".")
        self.h.git("commit", "-m", "unexpected commit")

        rolled_back = self.h.runner(
            "rollback",
            extra_env={"CONFIRM_ROLLBACK": "YES"},
        )
        self.assertNotEqual(
            rolled_back.returncode,
            0,
            rolled_back.stdout,
        )
        self.assertIn(
            "HEAD changed after prepare",
            rolled_back.stdout,
        )
        self.assertIn("git revert", rolled_back.stdout)

    def test_precommit_rollback_restores_clean_worktree(self) -> None:
        prepared = self.h.runner("prepare")
        self.assertEqual(prepared.returncode, 0, prepared.stdout)

        self.h.modify_all_batch0_files()
        rolled_back = self.h.runner(
            "rollback",
            extra_env={"CONFIRM_ROLLBACK": "YES"},
        )
        self.assertEqual(
            rolled_back.returncode,
            0,
            rolled_back.stdout,
        )
        self.assertEqual(
            self.h.git(
                "status",
                "--short",
                "--untracked-files=all",
            ).stdout.strip(),
            "",
        )

    def test_commit_reuses_valid_verification_stamp(self) -> None:
        prepared = self.h.runner("prepare")
        self.assertEqual(prepared.returncode, 0, prepared.stdout)

        self.h.modify_all_batch0_files()
        verified = self.h.runner("verify")
        self.assertEqual(verified.returncode, 0, verified.stdout)

        committed = self.h.runner(
            "commit",
            extra_env={"CONFIRM_COMMIT": "YES"},
        )
        self.assertEqual(
            committed.returncode,
            0,
            committed.stdout,
        )
        self.assertIn(
            "reusing valid verification stamp",
            committed.stdout,
        )
        self.assertIn(
            "v11: freeze governance contracts and baseline",
            self.h.git("log", "-1", "--pretty=%s").stdout,
        )
        self.assertEqual(
            self.h.git(
                "status",
                "--short",
                "--untracked-files=all",
            ).stdout.strip(),
            "",
        )


class Batch11KnownHistoricalFailureGateTests(unittest.TestCase):
    def test_batch11_uses_repository_gate_instead_of_raw_full_suite(self) -> None:
        text = RUNNER_SOURCE.read_text(encoding="utf-8")
        start = text.index("    batch11)")
        end = text.index("    none)", start)
        block = text[start:end]

        self.assertIn("--mode repository-gate", block)
        self.assertIn(
            '--known-failure-policy "frozen-historical-regressions-v1"',
            block,
        )
        self.assertIn(
            '"${STATE_DIR}/repository_gate/v11_release_audit.json"',
            block,
        )
        self.assertNotIn(
            "python -m unittest discover -s tests -v",
            block,
        )

    def test_batch11_still_runs_all_v11_tests(self) -> None:
        text = RUNNER_SOURCE.read_text(encoding="utf-8")
        start = text.index("    batch11)")
        end = text.index("    none)", start)
        block = text[start:end]
        self.assertIn(
            "python -m unittest discover -s tests -p 'test_v11_*.py' -v",
            block,
        )

    def test_batch11_checks_governance_and_evidence_ui(self) -> None:
        text = RUNNER_SOURCE.read_text(encoding="utf-8")
        start = text.index("    batch11)")
        end = text.index("    none)", start)
        block = text[start:end]
        self.assertIn("/governance/health", block)
        self.assertIn("/governance-ui", block)
        self.assertIn("/evidence-ui", block)


if __name__ == "__main__":
    unittest.main()
