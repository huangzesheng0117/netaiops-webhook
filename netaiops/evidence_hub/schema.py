"""Evidence Hub schema primitives for v10.

This module is intentionally side-effect free:
- no device access
- no DingDong sending
- no pipeline integration
- no runtime directory creation unless callers do it explicitly

Batch 1 provides a stable schema foundation for later batches:
Batch 2 will add the writer that loads existing request artifacts.
Batch 3 will integrate the writer into the main pipeline.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, Dict, Mapping, Optional

SCHEMA_VERSION = "v10.evidence_hub.detail.v1"
DEFAULT_BASE_DIR = Path("/opt/netaiops-webhook")
DETAIL_ROOT_REL_PATH = Path("data/evidence_hub/requests")

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")

REQUIRED_SECTION_FILES: Dict[str, str] = {
    "meta": "meta.json",
    "alert_context": "alert_context.json",
    "normalized_event": "normalized_event.json",
    "classification": "classification.json",
    "plan": "plan.json",
    "metrics_evidence": "metrics_evidence.json",
    "device_evidence": "device_evidence.json",
    "review": "review.json",
    "analysis_result": "analysis_result.json",
    "notification_summary": "notification_summary.json",
    "raw_payload": "raw_payload.json",
}

FUTURE_SECTION_FILES: Dict[str, str] = {
    "logs_evidence": "logs_evidence.json",
    "topology_context": "topology_context.json",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_request_id(request_id: str) -> bool:
    if not isinstance(request_id, str):
        return False
    text = request_id.strip()
    if not text:
        return False
    if "/" in text or "\\" in text:
        return False
    if text in {".", ".."}:
        return False
    return bool(_REQUEST_ID_RE.match(text))


def safe_request_id(request_id: str) -> str:
    if not validate_request_id(request_id):
        raise ValueError(f"invalid request_id: {request_id!r}")
    return request_id.strip()


def evidence_hub_root(base_dir: Path = DEFAULT_BASE_DIR) -> Path:
    return Path(base_dir) / DETAIL_ROOT_REL_PATH


def request_detail_dir(request_id: str, base_dir: Path = DEFAULT_BASE_DIR) -> Path:
    return evidence_hub_root(base_dir) / safe_request_id(request_id)


@dataclass(frozen=True)
class ArtifactRef:
    name: str
    filename: str
    rel_path: str = ""
    exists: bool = False
    status: str = "missing"
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DetailMeta:
    request_id: str
    schema_version: str = SCHEMA_VERSION
    created_at: str = field(default_factory=utc_now)
    source: str = ""
    family: str = ""
    hostname: str = ""
    device_ip: str = ""
    object_name: str = ""
    detail_url: str = ""
    status: str = "schema_only"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["request_id"] = safe_request_id(data["request_id"])
        return data


def _empty_sections() -> Dict[str, Dict[str, Any]]:
    sections: Dict[str, Dict[str, Any]] = {}
    for section in REQUIRED_SECTION_FILES:
        sections[section] = {
            "status": "missing",
            "data": {},
            "warnings": [],
        }
    return sections


def _artifact_refs(request_id: str) -> Dict[str, Dict[str, Any]]:
    safe_id = safe_request_id(request_id)
    artifacts: Dict[str, Dict[str, Any]] = {}
    for name, filename in REQUIRED_SECTION_FILES.items():
        artifacts[name] = ArtifactRef(
            name=name,
            filename=filename,
            rel_path=str(DETAIL_ROOT_REL_PATH / safe_id / filename),
        ).to_dict()
    return artifacts


def build_empty_detail(
    request_id: str,
    *,
    source: str = "",
    family: str = "",
    hostname: str = "",
    device_ip: str = "",
    object_name: str = "",
    detail_url: str = "",
    git_info: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    meta = DetailMeta(
        request_id=safe_request_id(request_id),
        source=str(source or ""),
        family=str(family or ""),
        hostname=str(hostname or ""),
        device_ip=str(device_ip or ""),
        object_name=str(object_name or ""),
        detail_url=str(detail_url or ""),
    ).to_dict()

    return {
        "schema_version": SCHEMA_VERSION,
        "request_id": meta["request_id"],
        "meta": meta,
        "summary": {
            "title": "",
            "judgement": "",
            "recommendations": [],
            "evidence_status": {
                "metrics": "missing",
                "device": "missing",
                "review": "missing",
                "notification": "missing",
            },
        },
        "sections": _empty_sections(),
        "artifacts": _artifact_refs(meta["request_id"]),
        "git": dict(git_info or {}),
    }


def expected_detail_files(request_id: str, base_dir: Path = DEFAULT_BASE_DIR) -> Dict[str, Path]:
    root = request_detail_dir(request_id, base_dir=base_dir)
    return {name: root / filename for name, filename in REQUIRED_SECTION_FILES.items()}
