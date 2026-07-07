"""Read existing v10 request artifacts for v11 governance.

The reader is deliberately local and read-only. It discovers only frozen,
known request-artifact paths, validates every path stays under the project
root, limits JSON reads, and returns metadata references instead of embedding
raw artifacts in governance records.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .contracts import ArtifactRef
from .schemas import validate_governance_id

DEFAULT_PROJECT_ROOT = Path("/opt/netaiops-webhook")
MAX_JSON_READ_BYTES = 16 * 1024 * 1024

# One deterministic document is selected for each kind. These patterns mirror
# the current v10 runtime directories and Evidence Hub outputs.
ARTIFACT_PATTERNS: tuple[tuple[str, str], ...] = (
    ("raw_payload", "data/raw/*{request_id}*.json"),
    ("normalized_event", "data/normalized/*{request_id}*.json"),
    ("analysis", "data/analysis/*{request_id}*.analysis.json"),
    ("pipeline", "data/analysis/*{request_id}*.pipeline.json"),
    ("plan", "data/plans/*{request_id}*.plan.json"),
    (
        "prometheus_evidence",
        "data/prometheus_evidence/*{request_id}*.prometheus_evidence.json",
    ),
    ("execution", "data/execution/*{request_id}*.execution.json"),
    ("review", "data/reviews/*{request_id}*.review.json"),
    (
        "notification_summary",
        "data/evidence_hub/requests/{request_id}/notification_summary.json",
    ),
    (
        "notification_summary_slim",
        "data/evidence_hub/requests/{request_id}/notification_summary_slim.json",
    ),
    (
        "notification_send_result",
        "data/evidence_hub/requests/{request_id}/ai_analysis_card_send_result.json",
    ),
    (
        "evidence_hub_meta",
        "data/evidence_hub/requests/{request_id}/meta.json",
    ),
    (
        "evidence_hub_summary",
        "data/evidence_hub/requests/{request_id}/summary.json",
    ),
    (
        "ai_analysis_card",
        "data/evidence_hub/requests/{request_id}/ai_analysis_card.json",
    ),
)


class ArtifactReaderError(RuntimeError):
    """Raised when request artifacts cannot be safely discovered."""


@dataclass(frozen=True)
class ArtifactDocument:
    """One selected JSON artifact and its metadata-only reference."""

    kind: str
    path: Path
    data: Mapping[str, Any] | None
    reference: ArtifactRef
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.data is not None and not self.error


@dataclass(frozen=True)
class RequestArtifactBundle:
    """Read-only bundle used by the Incident Memory builder."""

    request_id: str
    project_root: Path
    documents: Mapping[str, ArtifactDocument]
    artifact_refs: tuple[ArtifactRef, ...]
    missing_kinds: tuple[str, ...]
    read_errors: tuple[Mapping[str, str], ...]
    warnings: tuple[str, ...]

    def get(self, kind: str) -> Mapping[str, Any]:
        document = self.documents.get(kind)
        if document is None or document.data is None:
            return {}
        return document.data

    @property
    def artifact_count(self) -> int:
        return len(self.artifact_refs)


def _safe_request_id(value: str) -> str:
    try:
        return validate_governance_id(value, field_name="request_id")
    except ValueError as exc:
        raise ArtifactReaderError(str(exc)) from exc


def _ensure_within_root(path: Path, project_root: Path) -> Path:
    root = project_root.resolve(strict=True)
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ArtifactReaderError(f"artifact escapes project root: {path}") from exc
    return resolved


def _relative_path(path: Path, project_root: Path) -> str:
    resolved = _ensure_within_root(path, project_root)
    return resolved.relative_to(project_root.resolve(strict=True)).as_posix()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json_object(path: Path, project_root: Path) -> tuple[Mapping[str, Any] | None, str]:
    try:
        resolved = _ensure_within_root(path, project_root)
        if path.is_symlink() or resolved.is_symlink():
            return None, "symlink_not_allowed"
        if not resolved.is_file():
            return None, "not_a_regular_file"
        size = resolved.stat().st_size
    except OSError as exc:
        return None, f"stat_failed:{type(exc).__name__}:{exc}"
    if size > MAX_JSON_READ_BYTES:
        return None, f"file_too_large:{size}"
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, f"json_read_failed:{type(exc).__name__}:{exc}"
    if not isinstance(payload, dict):
        return None, f"json_root_not_object:{type(payload).__name__}"
    return payload, ""


def _discover_one(
    project_root: Path,
    request_id: str,
    kind: str,
    pattern: str,
) -> tuple[ArtifactDocument | None, tuple[str, ...]]:
    formatted = pattern.format(request_id=request_id)
    candidates: list[Path] = []
    for path in sorted(project_root.glob(formatted), key=lambda item: item.as_posix()):
        try:
            resolved = _ensure_within_root(path, project_root)
        except ArtifactReaderError:
            continue
        if path.is_symlink() or resolved.is_symlink() or not resolved.is_file():
            continue
        candidates.append(resolved)

    if not candidates:
        return None, ()

    warnings: list[str] = []
    if len(candidates) > 1:
        warnings.append(
            f"multiple_artifacts:{kind}:{len(candidates)};selected={candidates[0].name}"
        )

    selected = candidates[0]
    data, error = _read_json_object(selected, project_root)
    reference = ArtifactRef(
        kind=kind,
        path=_relative_path(selected, project_root),
        sha256=_sha256_file(selected),
        exists=True,
        size_bytes=selected.stat().st_size,
    )
    return (
        ArtifactDocument(
            kind=kind,
            path=selected,
            data=data,
            reference=reference,
            error=error,
        ),
        tuple(warnings),
    )


def read_request_artifacts(
    project_root: Path | str,
    request_id: str,
) -> RequestArtifactBundle:
    """Discover and safely read the known artifacts for one request."""

    root = Path(project_root).expanduser().resolve(strict=False)
    if not root.is_dir():
        raise ArtifactReaderError(f"project root does not exist: {root}")
    safe_id = _safe_request_id(request_id)

    documents: dict[str, ArtifactDocument] = {}
    references: list[ArtifactRef] = []
    missing: list[str] = []
    errors: list[Mapping[str, str]] = []
    warnings: list[str] = []

    for kind, pattern in ARTIFACT_PATTERNS:
        document, discovery_warnings = _discover_one(
            root,
            safe_id,
            kind,
            pattern,
        )
        warnings.extend(discovery_warnings)
        if document is None:
            missing.append(kind)
            continue
        documents[kind] = document
        references.append(document.reference)
        if document.error:
            errors.append(
                {
                    "kind": kind,
                    "path": document.reference.path,
                    "error": document.error,
                }
            )

    return RequestArtifactBundle(
        request_id=safe_id,
        project_root=root,
        documents=documents,
        artifact_refs=tuple(references),
        missing_kinds=tuple(missing),
        read_errors=tuple(errors),
        warnings=tuple(warnings),
    )


def git_metadata(project_root: Path | str) -> dict[str, Any]:
    """Return bounded Git metadata without reading file contents."""

    root = Path(project_root).expanduser().resolve(strict=False)

    def run(*args: str) -> str:
        try:
            completed = subprocess.run(
                ["git", *args],
                cwd=root,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=True,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        return completed.stdout.strip()

    branch = run("rev-parse", "--abbrev-ref", "HEAD")
    commit = run("rev-parse", "HEAD")
    status = run("status", "--short", "--untracked-files=all")
    return {
        "available": bool(branch and commit),
        "branch": branch,
        "commit": commit,
        "dirty": bool(status),
    }


__all__ = [
    "ARTIFACT_PATTERNS",
    "ArtifactDocument",
    "ArtifactReaderError",
    "DEFAULT_PROJECT_ROOT",
    "MAX_JSON_READ_BYTES",
    "RequestArtifactBundle",
    "git_metadata",
    "read_request_artifacts",
]
