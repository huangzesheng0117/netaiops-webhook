import unittest

from tools.v6_release_precheck import build_release_snapshot


class TestV6ReleasePrecheck(unittest.TestCase):
    def test_release_snapshot_without_health_passes(self):
        snapshot = build_release_snapshot(
            base_dir=".",
            check_health=False,
        )

        self.assertEqual(snapshot["verdict"], "pass")
        self.assertEqual(snapshot["stage"], "v6.6")
        self.assertEqual(snapshot["violations"], [])

    def test_release_snapshot_has_required_boundaries(self):
        snapshot = build_release_snapshot(
            base_dir=".",
            check_health=False,
        )

        boundaries = snapshot["release_boundaries"]

        self.assertFalse(boundaries["adaptive_execution_enabled"])
        self.assertEqual(boundaries["adaptive_mode"], "skill_constrained_dry_run")
        self.assertTrue(boundaries["readonly_only"])
        self.assertFalse(boundaries["llm_free_command_generation"])
        self.assertFalse(boundaries["git_commit_in_this_batch"])

    def test_required_groups_include_v6_scripts_and_docs(self):
        snapshot = build_release_snapshot(
            base_dir=".",
            check_health=False,
        )

        groups = snapshot["required_path_status"]["groups"]

        docs = {item["path"] for item in groups["docs"]}
        scripts = {item["path"] for item in groups["regression_scripts"]}

        self.assertIn("docs/v6_6_release_and_maintenance_runbook.md", docs)
        self.assertIn("tools/regress_v6_all.sh", scripts)
        self.assertIn("tools/regress_v6_5.sh", scripts)


if __name__ == "__main__":
    unittest.main()
