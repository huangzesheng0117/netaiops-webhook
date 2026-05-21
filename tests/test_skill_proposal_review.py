import json
import tempfile
import unittest
from pathlib import Path

from netaiops.skill_proposal_review import (
    create_skill_proposal_review,
    list_pending_proposals,
    proposal_review_status,
    query_skill_proposal_reviews,
    review_summary,
)


class TestSkillProposalReview(unittest.TestCase):
    def test_review_gate_records_manual_decision_without_formal_skill_write(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            prop_dir = base / "data" / "skill_proposals"
            prop_dir.mkdir(parents=True)

            proposal = {
                "schema_version": "v7.3.skill_proposal.v1",
                "proposal_id": "skillprop_test001",
                "proposal_status": "draft_review_required",
                "manual_review_required": True,
                "auto_merge_enabled": False,
                "candidate_skill_name": "interface_utilization_high_enhance_test",
                "proposal_type": "enhance_existing_skill",
                "family": "interface_or_link_utilization_high",
                "reuse_value": {"total_score": 90, "verdict": "high_reuse_value"},
                "source_cluster": {"cluster_id": "cluster_test", "size": 3},
                "safety": {"writes_formal_skill": False},
            }

            detail = prop_dir / "skillprop_test001.proposal.json"
            detail.write_text(json.dumps(proposal, ensure_ascii=False), encoding="utf-8")

            with (prop_dir / "proposals.jsonl").open("w", encoding="utf-8") as f:
                f.write(json.dumps(proposal, ensure_ascii=False) + "\n")

            pending_before = list_pending_proposals(base_dir=base, min_score=60)
            self.assertEqual(len(pending_before), 1)

            review = create_skill_proposal_review(
                proposal_id="skillprop_test001",
                decision="approve",
                reviewer="tester",
                comment="approve for skill draft",
                next_action="create draft skill in next stage",
                base_dir=base,
            )

            self.assertEqual(review["decision"], "approve")
            self.assertFalse(review["auto_merge_enabled"])
            self.assertFalse(review["writes_formal_skill"])

            status = proposal_review_status("skillprop_test001", base_dir=base)
            self.assertEqual(status["review_status"], "approved_for_skill_draft")

            rows = query_skill_proposal_reviews(base_dir=base, proposal_id="skillprop_test001")
            self.assertEqual(len(rows), 1)

            pending_after = list_pending_proposals(base_dir=base, min_score=60)
            self.assertEqual(len(pending_after), 0)

            summary = review_summary(base_dir=base)
            self.assertEqual(summary["review_count"], 1)
            self.assertEqual(summary["decision_counts"]["approve"], 1)
            self.assertFalse((base / "skills").exists())


if __name__ == "__main__":
    unittest.main()
