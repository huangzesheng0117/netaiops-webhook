import json
import tempfile
import unittest
from pathlib import Path

from netaiops.skill_draft_builder import (
    build_skill_drafts,
    query_skill_drafts,
    validate_draft_safety,
)


class TestSkillDraftBuilder(unittest.TestCase):
    def test_build_draft_from_approved_proposal_without_formal_skill_write(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)

            prop_dir = base / "data" / "skill_proposals"
            review_dir = base / "data" / "skill_proposal_reviews"
            prop_dir.mkdir(parents=True)
            review_dir.mkdir(parents=True)

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
                "trigger_template": {
                    "family": "interface_or_link_utilization_high",
                    "direction": "out",
                    "match_strategy": "family + interface",
                },
                "evidence_requirements": [
                    "interface status",
                    "input output rate",
                    "multi interface aggregate utilization",
                ],
                "risks_and_guardrails": [
                    "multi-interface alerts must not be reduced to first interface",
                ],
                "acceptance_criteria": [
                    "readonly only",
                    "manual review required",
                ],
                "proposed_instruction_summary": "Build readonly evidence for interface utilization alerts.",
                "safety": {"writes_formal_skill": False},
            }

            (prop_dir / "skillprop_test001.proposal.json").write_text(
                json.dumps(proposal, ensure_ascii=False),
                encoding="utf-8",
            )
            (prop_dir / "proposals.jsonl").write_text(
                json.dumps(proposal, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

            review = {
                "schema_version": "v7.4.skill_proposal_review.v1",
                "review_id": "review_test001",
                "proposal_id": "skillprop_test001",
                "decision": "approve",
                "reviewer": "tester",
                "comment": "approved for draft generation",
                "created_at": "2026-05-20T00:00:00+00:00",
                "auto_merge_enabled": False,
                "writes_formal_skill": False,
            }

            (review_dir / "reviews.jsonl").write_text(
                json.dumps(review, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

            result = build_skill_drafts(base_dir=base, write=True)

            self.assertTrue(result["ok"])
            self.assertEqual(result["approved_review_count"], 1)
            self.assertEqual(result["draft_count"], 1)

            draft = result["drafts"][0]
            self.assertEqual(draft["draft_status"], "draft_generated_review_required")
            self.assertFalse(draft["auto_merge_enabled"])
            self.assertFalse(draft["writes_formal_skill"])
            self.assertTrue(validate_draft_safety(draft, base_dir=base)["ok"])

            draft_dir = Path(draft["draft_dir"])
            self.assertTrue((draft_dir / "SKILL.md").exists())
            self.assertTrue((draft_dir / "commands.yaml").exists())
            self.assertTrue((draft_dir / "evidence_rules.yaml").exists())
            self.assertTrue((draft_dir / "output_schema.json").exists())
            self.assertTrue((draft_dir / "proposal_snapshot.json").exists())
            self.assertFalse((base / "skills").exists())

            rows = query_skill_drafts(base_dir=base, proposal_id="skillprop_test001")
            self.assertEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main()
