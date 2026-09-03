"""Historical, no-external-call D3 owner replay helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from netaiops.v12.contracts import EvidenceEnvelope
from netaiops.v12.schema_validator import build_evidence_ref
from netaiops.v12.status import EvidenceSource, EvidenceStatus

from .capability_broker import EvidenceCapabilityBroker
from .evidence_owner_builders import build_device_material, build_metrics_request, plan_family
from .evidence_owner_contracts import APPROVED_OWNER_FAMILIES
from .evidence_owners import DeviceEvidenceOwner, MetricsEvidenceOwner
from .legacy_call_fence import LegacyCallFence
from .triage_owner import TriageOwner


@dataclass(frozen=True, slots=True)
class ReplaySample:
    request_id: str
    family: str
    source: str
    plan_path: str
    normalized_path: str
    plan: Mapping[str, Any]
    normalized_event: Mapping[str, Any]

    def public_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "family": self.family,
            "source": self.source,
            "plan_file": Path(self.plan_path).name,
            "normalized_file": Path(self.normalized_path).name,
        }


def _read(path: Path) -> Mapping[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("unsafe replay artifact")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("replay artifact root is not an object")
    return value


def _matching_normalized(root: Path, request_id: str) -> Path | None:
    items = [p for p in root.glob(f"*_{request_id}.json") if p.is_file() and not p.is_symlink()]
    if not items:
        return None
    items.sort(key=lambda p: (p.stat().st_mtime_ns, p.name), reverse=True)
    return items[0]


def discover_owner_replay_samples(
    project_root: str | Path,
    *,
    per_family: int = 3,
    scan_limit: int = 1600,
) -> tuple[list[ReplaySample], dict[str, Any]]:
    root = Path(project_root)
    plans = [p for p in (root / "data" / "plans").glob("*.plan.json") if p.is_file() and not p.is_symlink()]
    plans.sort(key=lambda p: (p.stat().st_mtime_ns, p.name), reverse=True)
    plans = plans[:scan_limit]
    normalized_root = root / "data" / "normalized"
    coverage = {family: 0 for family in APPROVED_OWNER_FAMILIES}
    skipped: dict[str, int] = {}
    output: list[ReplaySample] = []

    for plan_path in plans:
        if all(v >= per_family for v in coverage.values()):
            break
        reason = ""
        try:
            plan = _read(plan_path)
            request_id = str(plan.get("request_id") or "").strip()
            source = str(plan.get("source") or "").strip().lower()
            family = plan_family(plan)
            if coverage[family] >= per_family:
                continue
            if source != "alertmanager":
                reason = "source_not_alertmanager"
                raise ValueError(reason)
            normalized_path = _matching_normalized(normalized_root, request_id)
            if normalized_path is None:
                reason = "normalized_missing"
                raise ValueError(reason)
            normalized = _read(normalized_path)
            events = normalized.get("events")
            if not (isinstance(events, list) and len(events) == 1 and isinstance(events[0], Mapping)):
                reason = "single_event_required"
                raise ValueError(reason)
            event = dict(events[0])
            triage = TriageOwner().classify_normalized(
                request_id=request_id,
                source=source,
                normalized_event=event,
                mode="shadow",
            )
            if triage.family != family or triage.routing_action != "controlled_orchestrator":
                reason = "triage_family_mismatch"
                raise ValueError(reason)
            build_metrics_request(request_id=request_id, plan=plan)
            build_device_material(request_id=request_id, plan=plan)
            output.append(
                ReplaySample(
                    request_id=request_id,
                    family=family,
                    source=source,
                    plan_path=str(plan_path),
                    normalized_path=str(normalized_path),
                    plan=plan,
                    normalized_event=event,
                )
            )
            coverage[family] += 1
        except Exception:
            skipped[reason or "not_owner_ready"] = skipped.get(reason or "not_owner_ready", 0) + 1

    return output, {
        "scanned": len(plans),
        "coverage": coverage,
        "skipped": dict(sorted(skipped.items())),
    }


def _success_executor(source: str, counter: dict[str, int]):
    def execute(request, attempt):
        counter[source] = counter.get(source, 0) + 1
        evidence_ref = build_evidence_ref(
            request.request_id,
            source,
            f"d3-replay-{request.template_fingerprint[:24]}",
        )
        return EvidenceEnvelope(
            schema_version="v12.1",
            request_id=request.request_id,
            source=EvidenceSource(source),
            evidence_kind="evidence",
            status=EvidenceStatus.SUCCESS,
            summary=f"D3 deterministic {source} replay evidence.",
            facts={"fixture": True, "attempt": attempt, "external_call": False},
            scope={"family": request.family},
            evidence_refs=[evidence_ref],
            collected_at=datetime.now(timezone.utc),
        )
    return execute


def replay_owner_sample(sample: ReplaySample, work_root: str | Path) -> dict[str, Any]:
    root = Path(work_root)
    broker = EvidenceCapabilityBroker(root / "checkpoints")
    fence = LegacyCallFence(root / "trace")
    metrics_owner = MetricsEvidenceOwner(broker=broker, fence=fence)
    device_owner = DeviceEvidenceOwner(broker=broker, fence=fence)
    metrics_request = build_metrics_request(request_id=sample.request_id, plan=sample.plan)
    device_material = build_device_material(request_id=sample.request_id, plan=sample.plan)
    counts: dict[str, int] = {}
    metrics_1 = metrics_owner.execute(metrics_request, _success_executor("metrics", counts))
    metrics_2 = metrics_owner.execute(metrics_request, _success_executor("metrics", counts))
    device_1 = device_owner.execute(device_material.request, _success_executor("device", counts))
    device_2 = device_owner.execute(device_material.request, _success_executor("device", counts))
    return {
        "sample": sample.public_dict(),
        "metrics": {
            "first_action": metrics_1.owner_record.decision_action,
            "second_action": metrics_2.owner_record.decision_action,
            "executor_calls": counts.get("metrics", 0),
            "legacy_action": fence.legacy_action(sample.request_id, "metrics"),
        },
        "device": {
            "first_action": device_1.owner_record.decision_action,
            "second_action": device_2.owner_record.decision_action,
            "executor_calls": counts.get("device", 0),
            "legacy_action": fence.legacy_action(sample.request_id, "device"),
            "playbook_id": device_material.playbook_id,
            "command_sha256": device_material.command_sha256,
        },
        "external_calls_performed": False,
        "write_command_executed": False,
        "classification_owner": "triage",
        "metrics_owner": "metrics_agent",
        "device_owner": "device_agent",
    }
