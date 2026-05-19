import json
import tempfile
import unittest
from pathlib import Path

from netaiops.investigation_state import append_notified_stage, build_and_persist_investigation_session, build_investigation_session


class TestInvestigationState(unittest.TestCase):
    def test_build_session_from_existing_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            rid = "20260514_010203_123456_test"

            for d in [
                "data/analysis",
                "data/plans",
                "data/dispatch",
                "data/execution",
                "data/reviews",
                "data/callback",
            ]:
                (base / d).mkdir(parents=True, exist_ok=True)

            (base / "data/analysis" / f"alertmanager_{rid}.analysis.json").write_text(
                json.dumps({
                    "status": "success",
                    "summary": "interface utilization high",
                    "confidence": "high",
                }, ensure_ascii=False),
                encoding="utf-8",
            )

            (base / "data/plans" / f"alertmanager_{rid}.plan.json").write_text(
                json.dumps({
                    "status": "confirmed",
                    "readonly_only": True,
                    "execution_source": "capability_registry",
                    "family_result": {"family": "interface_or_link_utilization_high"},
                    "capability_plan": {
                        "selected_capabilities": [
                            {"capability": "show_interface_detail"},
                            {"capability": "show_interface_error_counters"},
                        ]
                    },
                    "policy_result": {
                        "auto_confirm_allowed": True,
                        "policy_summary": "allowed",
                        "checked_items": {
                            "readonly_only": True,
                            "guard_all_readonly": True,
                        },
                    },
                }, ensure_ascii=False),
                encoding="utf-8",
            )

            (base / "data/execution" / f"alertmanager_{rid}.execution.json").write_text(
                json.dumps({
                    "request_id": rid,
                    "execution_status": "completed",
                    "target_scope": {
                        "hostname": "SW01",
                        "device_ip": "10.0.0.1",
                        "alarm_type": "test",
                        "interface": "Te1/0/1",
                    },
                    "classification": {
                        "family": "interface_or_link_utilization_high",
                    },
                    "command_results": [
                        {
                            "command": "show interfaces Te1/0/1",
                            "dispatch_status": "completed",
                            "judge": {"final_status": "completed", "hard_error": False},
                        }
                    ],
                }, ensure_ascii=False),
                encoding="utf-8",
            )

            (base / "data/reviews" / f"alertmanager_{rid}.review.json").write_text(
                json.dumps({
                    "request_id": rid,
                    "review_status": "completed",
                    "family": "interface_or_link_utilization_high",
                    "conclusion": "done",
                    "recommendations": ["check prometheus"],
                    "evidence_bundle": {"confidence": "medium"},
                }, ensure_ascii=False),
                encoding="utf-8",
            )

            (base / "data/callback" / f"{rid}.callback.payload.json").write_text(
                json.dumps({
                    "notify_result": {
                        "sent": True,
                        "ok": True,
                        "status_code": 200,
                        "provider": "dongdong",
                    }
                }, ensure_ascii=False),
                encoding="utf-8",
            )

            session = build_investigation_session(rid, base)
            stages = [item["stage"] for item in session["timeline"]]

            self.assertEqual(session["request_id"], rid)
            self.assertEqual(session["v6_stage"], "v6.1")
            self.assertEqual(session["session_status"], "completed")
            self.assertIn("analyzed", stages)
            self.assertIn("planned", stages)
            self.assertIn("policy_checked", stages)
            self.assertIn("executed", stages)
            self.assertIn("judged", stages)
            self.assertIn("reviewed", stages)
            self.assertIn("notified", stages)
            self.assertFalse(session["adaptive"]["enabled"])

    def test_persist_session(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            rid = "20260514_010203_123456_test"

            (base / "data/analysis").mkdir(parents=True, exist_ok=True)
            (base / "data/analysis" / f"alertmanager_{rid}.analysis.json").write_text(
                json.dumps({"status": "success"}, ensure_ascii=False),
                encoding="utf-8",
            )

            session, out_file = build_and_persist_investigation_session(rid, base)

            self.assertTrue(out_file.exists())
            saved = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(saved["request_id"], rid)
            self.assertEqual(session["request_id"], rid)


    def test_append_notified_stage_marks_session_completed(self):
        session = {
            "request_id": "rid-test",
            "session_status": "reviewed",
            "timeline": [
                {
                    "stage": "reviewed",
                    "label": "证据复盘生成",
                    "status": "completed",
                    "file_key": "review",
                    "file": "",
                    "details": {},
                }
            ],
            "adaptive": {"enabled": False},
        }

        result = append_notified_stage(
            session,
            {
                "sent": True,
                "ok": True,
                "status_code": 200,
                "provider": "dongdong",
                "request_id": "rid-test",
            },
        )

        self.assertEqual(result["session_status"], "completed")
        self.assertEqual(result["timeline"][-1]["stage"], "notified")
        self.assertEqual(result["timeline"][-1]["status"], "completed")
        self.assertTrue(result["timeline"][-1]["details"]["sent"])


    def test_rebuild_preserves_existing_notified_stage(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            rid = "20260514_010203_123456_test"

            (base / "data/reviews").mkdir(parents=True, exist_ok=True)
            (base / "data/investigation").mkdir(parents=True, exist_ok=True)

            (base / "data/reviews" / f"alertmanager_{rid}.review.json").write_text(
                json.dumps({
                    "request_id": rid,
                    "review_status": "completed",
                    "family": "interface_or_link_utilization_high",
                    "conclusion": "done",
                    "recommendations": [],
                    "evidence_bundle": {"confidence": "medium"},
                }, ensure_ascii=False),
                encoding="utf-8",
            )

            existing_session = {
                "request_id": rid,
                "session_status": "completed",
                "timeline": [
                    {
                        "stage": "reviewed",
                        "label": "证据复盘生成",
                        "status": "completed",
                        "file_key": "review",
                        "file": "",
                        "details": {},
                    },
                    {
                        "stage": "notified",
                        "label": "通知发送",
                        "status": "completed",
                        "file_key": "runtime_notify_result",
                        "file": "",
                        "details": {
                            "sent": True,
                            "ok": True,
                            "status_code": 200,
                            "provider": "dongdong",
                        },
                    },
                ],
            }

            session_file = base / "data/investigation" / f"{rid}.investigation.session.json"
            session_file.write_text(json.dumps(existing_session, ensure_ascii=False), encoding="utf-8")

            session, _ = build_and_persist_investigation_session(rid, base)
            stages = [item["stage"] for item in session["timeline"]]

            self.assertEqual(session["session_status"], "completed")
            self.assertIn("reviewed", stages)
            self.assertIn("notified", stages)


if __name__ == "__main__":
    unittest.main()
