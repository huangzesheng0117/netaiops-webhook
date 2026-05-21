import json
import tempfile
import unittest
from pathlib import Path

from netaiops.learning_report import (
    build_learning_report,
    list_learning_reports,
    validate_report_safety,
)


class TestLearningReport(unittest.TestCase):
    def test_build_learning_report_from_v7_sidecar_files(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)

            (base / "data" / "memory").mkdir(parents=True)
            (base / "data" / "skill_proposals").mkdir(parents=True)
            (base / "data" / "skill_proposal_reviews").mkdir(parents=True)
            (base / "data" / "skill_drafts").mkdir(parents=True)

            memory = {
                "request_id": "20260519_150115_014287_1f8f0606",
                "family": "interface_or_link_utilization_high",
                "hostname": "10.191.96.43",
                "direction": "out",
                "device_ip_hash": "hash_device_a",
                "interfaces": ["TenGigabitEthernet1/0/1", "TenGigabitEthernet2/0/1"],
            }
            (base / "data" / "memory" / "incidents.jsonl").write_text(
                json.dumps(memory, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

            graph = {
                "schema_version": "v7.2.incident_relations.v1",
                "stage": "v7.2_relation_engine",
                "record_count": 1,
                "relation_count": 0,
                "cluster_count": 1,
                "clusters": [
                    {
                        "cluster_id": "cluster_test",
                        "size": 3,
                        "family": "interface_or_link_utilization_high",
                        "hostname": "WG404-H0304-C95-INT-ACC",
                        "interfaces": ["TenGigabitEthernet1/0/1"],
                        "circuit_alias": "WG88互联网线路_电信_100M",
                        "direction": "out",
                    }
                ],
            }
            (base / "data" / "memory" / "incident_relations.json").write_text(
                json.dumps(graph, ensure_ascii=False),
                encoding="utf-8",
            )

            proposal = {
                "proposal_id": "skillprop_test",
                "proposal_type": "enhance_existing_skill",
                "proposal_status": "draft_review_required",
                "candidate_skill_name": "interface_utilization_high_enhance_test",
                "family": "interface_or_link_utilization_high",
                "manual_review_required": True,
                "auto_merge_enabled": False,
                "reuse_value": {"total_score": 90, "verdict": "high_reuse_value"},
            }
            (base / "data" / "skill_proposals" / "proposals.jsonl").write_text(
                json.dumps(proposal, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

            review = {
                "review_id": "review_test",
                "proposal_id": "skillprop_test",
                "decision": "approve",
                "reviewer": "tester",
                "created_at": "2026-05-21T00:00:00+00:00",
            }
            (base / "data" / "skill_proposal_reviews" / "reviews.jsonl").write_text(
                json.dumps(review, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

            draft = {
                "draft_id": "skilldraft_test",
                "draft_status": "draft_generated_review_required",
                "proposal_id": "skillprop_test",
                "review_id": "review_test",
                "candidate_skill_name": "interface_utilization_high_enhance_test",
                "family": "interface_or_link_utilization_high",
                "auto_merge_enabled": False,
                "writes_formal_skill": False,
            }
            (base / "data" / "skill_drafts" / "drafts.jsonl").write_text(
                json.dumps(draft, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

            report = build_learning_report(base_dir=base, write=True)

            self.assertEqual(report["stage"], "v7.6_learning_report")
            self.assertEqual(report["lifecycle_counts"]["incident_memory_count"], 1)
            self.assertEqual(report["lifecycle_counts"]["proposal_count"], 1)
            self.assertEqual(report["lifecycle_counts"]["review_count"], 1)
            self.assertEqual(report["lifecycle_counts"]["draft_count"], 1)
            self.assertFalse(report["safety"]["writes_formal_skill"])
            self.assertFalse(report["safety"]["auto_merge_enabled"])
            self.assertFalse(report["safety"]["executes_device_commands"])
            self.assertTrue(validate_report_safety(report)["ok"])

            report_text = json.dumps(report, ensure_ascii=False)
            self.assertNotIn("10.191.96.43", report_text)
            self.assertIn("<ip_hash_", report_text)

            rows = list_learning_reports(base_dir=base)
            self.assertEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main()
