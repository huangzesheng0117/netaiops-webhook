import unittest

from netaiops.investigation_policy import evaluate_investigation_session


class TestInvestigationPolicy(unittest.TestCase):
    def test_valid_v6_1_completed_session_passes(self):
        session = {
            "request_id": "rid",
            "v6_stage": "v6.1",
            "session_status": "completed",
            "adaptive": {
                "enabled": False,
                "max_extra_rounds": 0,
                "max_extra_commands": 0,
            },
            "timeline": [
                {
                    "stage": "planned",
                    "status": "completed",
                    "details": {},
                },
                {
                    "stage": "policy_checked",
                    "status": "allowed",
                    "details": {
                        "checked_items": {
                            "readonly_only": True,
                            "guard_all_readonly": True,
                            "command_count": 5,
                            "max_commands": 5,
                        }
                    },
                },
                {
                    "stage": "executed",
                    "status": "completed",
                    "details": {
                        "total_commands": 5,
                        "completed_commands": 5,
                        "failed_commands": 0,
                        "partial_commands": 0,
                        "hard_error_count": 0,
                    },
                },
                {
                    "stage": "judged",
                    "status": "completed",
                    "details": {
                        "hard_error_count": 0,
                        "failed_commands": 0,
                    },
                },
                {
                    "stage": "reviewed",
                    "status": "completed",
                    "details": {},
                },
                {
                    "stage": "notified",
                    "status": "completed",
                    "details": {
                        "sent": True,
                        "ok": True,
                        "status_code": 200,
                    },
                },
            ],
        }

        result = evaluate_investigation_session(session)
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["violations"], [])

    def test_adaptive_enabled_fails_in_v6_1(self):
        session = {
            "request_id": "rid",
            "v6_stage": "v6.1",
            "session_status": "completed",
            "adaptive": {
                "enabled": True,
                "max_extra_rounds": 1,
                "max_extra_commands": 3,
            },
            "timeline": [
                {
                    "stage": "reviewed",
                    "status": "completed",
                    "details": {},
                }
            ],
        }

        result = evaluate_investigation_session(session)
        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(any("adaptive.enabled" in item for item in result["violations"]))

    def test_non_readonly_policy_fails(self):
        session = {
            "request_id": "rid",
            "v6_stage": "v6.1",
            "session_status": "reviewed",
            "adaptive": {
                "enabled": False,
                "max_extra_rounds": 0,
                "max_extra_commands": 0,
            },
            "timeline": [
                {
                    "stage": "policy_checked",
                    "status": "allowed",
                    "details": {
                        "checked_items": {
                            "readonly_only": False,
                            "guard_all_readonly": False,
                            "command_count": 6,
                            "max_commands": 5,
                        }
                    },
                }
            ],
        }

        result = evaluate_investigation_session(session)
        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(any("readonly_only" in item for item in result["violations"]))
        self.assertTrue(any("guard_all_readonly" in item for item in result["violations"]))
        self.assertTrue(any("command_count exceeds" in item for item in result["violations"]))


if __name__ == "__main__":
    unittest.main()
