from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from netaiops.governance.contracts import (
    EvidenceSourceStatus,
    LearningSignalSeverity,
    ProposalStatus,
)
from netaiops.governance.proposal_builder import (
    InvalidProposalTransition,
    ProposalBuilder,
    ProposalBuilderError,
    ProposalNotEligibleError,
    can_transition,
    proposal_safety_summary,
    proposal_workflow_summary,
    transition_proposal,
)
from netaiops.governance.schemas import (
    ArtifactReference,
    IncidentMemoryRecord,
    LearningSignalRecord,
)
from netaiops.governance.store import GovernanceStore


FIXED_TIME = datetime(2026, 7, 7, 12, 0, tzinfo=timezone.utc)


def make_ref(kind: str = "plan") -> ArtifactReference:
    return ArtifactReference(
        kind=kind,
        path=f"data/{kind}/fixture.json",
        sha256="a" * 64,
        exists=True,
        size_bytes=100,
    )


def make_signal(**overrides) -> LearningSignalRecord:
    payload = {
        "signal_id": "signal_fixture_1",
        "request_id": "20260703_154613_796157_3750fbea",
        "created_at": FIXED_TIME,
        "signal_type": "playbook_missing",
        "severity": LearningSignalSeverity.WARNING,
        "detected_from": ["incident_memory.quality_flags"],
        "reason": "No governed Playbook matched.",
        "evidence_refs": [make_ref("plan")],
        "dedupe_key": "playbook_missing|interface_status_or_flap|switch|Te1/0/1",
        "proposal_eligible": True,
    }
    payload.update(overrides)
    return LearningSignalRecord.model_validate(payload)


def make_memory(**overrides) -> IncidentMemoryRecord:
    payload = {
        "memory_id": "memory_20260703_154613_796157_3750fbea",
        "request_id": "20260703_154613_796157_3750fbea",
        "created_at": FIXED_TIME,
        "source_type": "alertmanager",
        "alert_time": FIXED_TIME,
        "device": {"hostname": "switch-01", "device_ip": "10.0.0.1"},
        "object": {"name": "Te1/0/1", "interface": "Te1/0/1"},
        "family": "interface_status_or_flap",
        "alert_summary": "Interface state changed",
        "analysis_summary": "Review required",
        "evidence_status": {
            "metrics": EvidenceSourceStatus.NO_DATA,
            "device": EvidenceSourceStatus.FAILED,
            "review": EvidenceSourceStatus.PARTIAL,
            "notification": EvidenceSourceStatus.SUCCESS,
            "logs": EvidenceSourceStatus.NOT_AVAILABLE,
        },
        "command_summary": {"failed": 1, "hard_error_count": 1},
        "review_summary": {"missing_evidence_count": 1, "read_error_count": 0},
        "notification_result": {"status": "success", "sent": True},
        "quality_flags": ["playbook_missing", "logs_not_available"],
        "git_metadata": {"branch": "main", "commit": "a" * 40, "dirty": False},
        "artifact_refs": [make_ref("plan")],
    }
    payload.update(overrides)
    return IncidentMemoryRecord.model_validate(payload)


class ProposalBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = ProposalBuilder()

    def proposal(self):
        return self.builder.build(
            make_signal(),
            affected_family="interface_status_or_flap",
            generated_at=FIXED_TIME,
        )

    def test_build_creates_draft_with_audit_trail(self) -> None:
        proposal = self.proposal()
        self.assertEqual(proposal.status, ProposalStatus.DRAFT)
        self.assertEqual(proposal.reviewer, "")
        self.assertEqual(len(proposal.audit_trail), 1)
        self.assertEqual(proposal.audit_trail[0]["to_status"], "draft")

    def test_build_accepts_detailed_plan_minimal_mapping(self) -> None:
        proposal = self.builder.build(
            {
                "signal_id": "sig-fixture-1",
                "signal_type": "playbook_missing",
                "affected_family": "interface_status_or_flap",
                "evidence_refs": [{"kind": "plan", "path": "fixture/plan.json"}],
            },
            generated_at=FIXED_TIME,
        )
        self.assertEqual(proposal.status, ProposalStatus.DRAFT)
        self.assertTrue(proposal.audit_trail)

    def test_proposal_id_is_deterministic(self) -> None:
        self.assertEqual(self.proposal().proposal_id, self.proposal().proposal_id)

    def test_evidence_refs_are_preserved_as_metadata_only(self) -> None:
        proposal = self.proposal()
        self.assertEqual(proposal.evidence_refs[0].kind, "plan")
        self.assertNotIn("raw_output", str(proposal.to_payload()).lower())

    def test_logs_not_available_is_not_eligible(self) -> None:
        signal = make_signal(
            signal_type="logs_not_available",
            severity=LearningSignalSeverity.INFO,
            proposal_eligible=False,
        )
        with self.assertRaises(ProposalNotEligibleError):
            self.builder.build(signal, affected_family="interface_status_or_flap")

    def test_explicit_non_eligible_signal_is_rejected(self) -> None:
        with self.assertRaises(ProposalNotEligibleError):
            self.builder.build(
                make_signal(proposal_eligible=False),
                affected_family="interface_status_or_flap",
            )

    def test_missing_family_is_rejected(self) -> None:
        with self.assertRaises(ProposalBuilderError):
            self.builder.build(make_signal())

    def test_missing_evidence_is_rejected(self) -> None:
        with self.assertRaises(ProposalBuilderError):
            self.builder.build(
                {
                    "signal_id": "signal_fixture_2",
                    "signal_type": "playbook_missing",
                    "affected_family": "interface_status_or_flap",
                    "evidence_refs": [],
                }
            )

    def test_unknown_signal_type_is_rejected(self) -> None:
        with self.assertRaises(ProposalBuilderError):
            self.builder.build(
                {
                    "signal_id": "signal_fixture_3",
                    "signal_type": "unknown_signal",
                    "affected_family": "interface_status_or_flap",
                    "evidence_refs": [{"kind": "plan", "path": "fixture/plan.json"}],
                }
            )

    def test_generated_proposal_is_non_executable_and_auto_apply_false(self) -> None:
        summary = proposal_safety_summary(self.proposal())
        self.assertTrue(summary["safe"])
        self.assertFalse(summary["auto_apply"])

    def test_replay_scope_is_offline_and_disables_external_calls(self) -> None:
        proposal = self.proposal()
        self.assertEqual(proposal.replay_scope["mode"], "offline")
        self.assertFalse(any(proposal.replay_scope["external_calls"].values()))

    def test_build_for_memory_uses_family_and_checks_request_id(self) -> None:
        proposal = self.builder.build_for_memory(
            make_signal(), make_memory(), generated_at=FIXED_TIME
        )
        self.assertEqual(proposal.affected_family, "interface_status_or_flap")
        with self.assertRaises(ProposalBuilderError):
            self.builder.build_for_memory(
                make_signal(request_id="other-request"), make_memory()
            )

    def test_draft_can_only_move_to_pending_review(self) -> None:
        self.assertTrue(can_transition("draft", "pending_review"))
        self.assertFalse(can_transition("draft", "approved"))
        with self.assertRaises(InvalidProposalTransition):
            transition_proposal(
                self.proposal(), "approved", reviewer="reviewer-1", changed_at=FIXED_TIME
            )

    def test_pending_review_requires_reviewer(self) -> None:
        with self.assertRaises(ProposalBuilderError):
            transition_proposal(
                self.proposal(),
                "pending_review",
                reviewer="",
                changed_at=FIXED_TIME,
            )

    def test_valid_state_machine_path_to_verified(self) -> None:
        proposal = self.proposal()
        pending = transition_proposal(
            proposal,
            "pending_review",
            reviewer="reviewer-1",
            changed_at=FIXED_TIME + timedelta(minutes=1),
        )
        approved = transition_proposal(
            pending,
            "approved",
            reviewer="reviewer-2",
            note="Evidence and replay scope accepted.",
            changed_at=FIXED_TIME + timedelta(minutes=2),
        )
        implemented = transition_proposal(
            approved,
            "implemented",
            reviewer="implementer-1",
            note="Implemented under a separate controlled change.",
            changed_at=FIXED_TIME + timedelta(minutes=3),
        )
        verified = transition_proposal(
            implemented,
            "verified",
            reviewer="reviewer-3",
            note="Offline replay and release checks passed.",
            changed_at=FIXED_TIME + timedelta(minutes=4),
        )
        self.assertEqual(verified.status, ProposalStatus.VERIFIED)
        self.assertEqual(len(verified.audit_trail), 5)

    def test_pending_review_can_be_rejected_and_is_terminal(self) -> None:
        pending = transition_proposal(
            self.proposal(),
            "pending_review",
            reviewer="reviewer-1",
            changed_at=FIXED_TIME + timedelta(minutes=1),
        )
        rejected = transition_proposal(
            pending,
            "rejected",
            reviewer="reviewer-2",
            note="Risk exceeds expected benefit.",
            changed_at=FIXED_TIME + timedelta(minutes=2),
        )
        self.assertEqual(rejected.status, ProposalStatus.REJECTED)
        with self.assertRaises(InvalidProposalTransition):
            transition_proposal(
                rejected,
                "approved",
                reviewer="reviewer-3",
                changed_at=FIXED_TIME + timedelta(minutes=3),
            )

    def test_transition_does_not_mutate_original(self) -> None:
        original = self.proposal()
        pending = transition_proposal(
            original,
            "pending_review",
            reviewer="reviewer-1",
            changed_at=FIXED_TIME + timedelta(minutes=1),
        )
        self.assertEqual(original.status, ProposalStatus.DRAFT)
        self.assertEqual(len(original.audit_trail), 1)
        self.assertEqual(pending.status, ProposalStatus.PENDING_REVIEW)

    def test_transition_rejects_time_regression(self) -> None:
        with self.assertRaises(InvalidProposalTransition):
            transition_proposal(
                self.proposal(),
                "pending_review",
                reviewer="reviewer-1",
                changed_at=FIXED_TIME - timedelta(seconds=1),
            )

    def test_transition_requires_timezone(self) -> None:
        with self.assertRaises(ProposalBuilderError):
            transition_proposal(
                self.proposal(),
                "pending_review",
                reviewer="reviewer-1",
                changed_at=datetime(2026, 7, 7, 12, 1),
            )

    def test_store_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            store = GovernanceStore(Path(tempdir) / "governance")
            proposal = self.proposal()
            result = store.write("proposals", proposal.proposal_id, proposal)
            loaded = store.read("proposals", proposal.proposal_id)
            self.assertTrue(result.created)
            self.assertEqual(loaded["proposal_id"], proposal.proposal_id)
            self.assertEqual(loaded["status"], "draft")

    def test_workflow_summary(self) -> None:
        draft = self.proposal()
        pending = transition_proposal(
            draft,
            "pending_review",
            reviewer="reviewer-1",
            changed_at=FIXED_TIME + timedelta(minutes=1),
        )
        summary = proposal_workflow_summary([draft, pending])
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["by_status"]["draft"], 1)
        self.assertEqual(summary["by_status"]["pending_review"], 1)
        self.assertEqual(summary["auto_apply_enabled"], 0)


if __name__ == "__main__":
    unittest.main()
