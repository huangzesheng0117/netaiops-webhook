import unittest

from tools.v6_git_audit import (
    check_gitignore,
    classify_changed_path,
    is_forbidden_path,
    parse_git_status_porcelain,
    scan_diff_for_sensitive_keywords,
)


class TestV6GitAudit(unittest.TestCase):
    def test_parse_git_status_porcelain(self):
        text = " M app.py\n?? netaiops/skill_registry.py\nA  docs/v6_release_notes.md\n"
        items = parse_git_status_porcelain(text)

        self.assertEqual(len(items), 3)
        self.assertEqual(items[0]["path"], "app.py")
        self.assertEqual(items[1]["status"], "??")
        self.assertEqual(items[2]["path"], "docs/v6_release_notes.md")

    def test_forbidden_paths(self):
        self.assertTrue(is_forbidden_path("config.yaml"))
        self.assertTrue(is_forbidden_path("data/raw/test.json"))
        self.assertTrue(is_forbidden_path("logs/app.log"))
        self.assertTrue(is_forbidden_path("backup/app.py.bak"))
        self.assertTrue(is_forbidden_path("certs/client.pem"))
        self.assertFalse(is_forbidden_path("netaiops/skill_registry.py"))
        self.assertFalse(is_forbidden_path("docs/v6_release_notes.md"))

    def test_classify_changed_path(self):
        self.assertEqual(classify_changed_path("app.py"), "app.py")
        self.assertEqual(classify_changed_path("netaiops/skill_registry.py"), "netaiops")
        self.assertEqual(classify_changed_path("skills/interface_utilization_high/SKILL.md"), "skills")
        self.assertEqual(classify_changed_path("unknown/file.txt"), "other")

    def test_gitignore_check(self):
        text = "config.yaml\ndata/\nlogs/\nbackup/\nvenv/\n"
        result = check_gitignore(text)

        self.assertTrue(result["ok"])
        self.assertEqual(result["missing"], [])

    def test_scan_diff_for_sensitive_keywords(self):
        diff = """
diff --git a/a.py b/a.py
+API_TOKEN = "abc"
+normal_line = "hello"
+forbidden_patterns:
+  - "secret keyword inside docs"
"""
        hits = scan_diff_for_sensitive_keywords(diff)

        self.assertTrue(any(item["keyword"] == "token" for item in hits))

    def test_project_path_is_not_sensitive_keyword(self):
        diff = """
diff --git a/docs/a.md b/docs/a.md
+cd /opt/netaiops-webhook
+项目名称是 NetAIOps webhook 平台
"""
        hits = scan_diff_for_sensitive_keywords(diff)

        self.assertFalse(any(item["keyword"] == "webhook" for item in hits))


if __name__ == "__main__":
    unittest.main()
