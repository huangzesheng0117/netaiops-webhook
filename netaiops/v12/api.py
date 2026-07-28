"""Read-only API and service for v12 Agent Trace artifacts."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from .schema_validator import parse_contract_ref, validate_request_id


DEFAULT_AGENT_TRACE_ROOT = Path(
    "/opt/netaiops-webhook/data/evidence_hub/requests"
)
MAX_TRACE_FILE_BYTES = 5 * 1024 * 1024
TRACE_FILE_NAMES = (
    "agent_runs.json",
    "evidence_bundle.json",
    "judge_result.json",
    "rca_result.json",
    "report.json",
    "shadow_integration.json",
)


class AgentTraceReadError(RuntimeError):
    """Base exception for read-only Agent Trace access."""


class AgentTraceCorruptError(AgentTraceReadError):
    """Raised when a trace artifact cannot be safely interpreted."""


class AgentTraceReadService:
    """Expose an allowlisted view without copying full evidence facts."""

    def __init__(
        self,
        root: str | Path = DEFAULT_AGENT_TRACE_ROOT,
        *,
        max_file_bytes: int = MAX_TRACE_FILE_BYTES,
    ) -> None:
        self.root = Path(root)
        self.max_file_bytes = int(max_file_bytes)
        if self.max_file_bytes < 1024:
            raise ValueError("max_file_bytes must be at least 1024")

    @staticmethod
    def external_call_policy() -> dict[str, bool]:
        return {
            "glm": False,
            "prometheus_mcp": False,
            "netmiko_mcp": False,
            "evidence_mcp": False,
            "ops_es_api": False,
            "notification": False,
            "production_write": False,
        }

    def health(self) -> dict[str, Any]:
        root_exists = self.root.exists()
        root_is_symlink = self.root.is_symlink()
        readable = True
        error = None
        trace_count = 0
        corrupt_count = 0
        if root_exists and not root_is_symlink:
            try:
                result = self.list_traces(limit=1)
                trace_count = int(result["total"])
                corrupt_count = int(result["corrupt_count"])
            except Exception as exc:
                readable = False
                error = f"{type(exc).__name__}: {exc}"
        status = "ok"
        if root_is_symlink or not readable:
            status = "error"
        elif corrupt_count:
            status = "warning"
        return {
            "status": status,
            "service": "netaiops-v12-agent-trace-api",
            "schema_version": "v12.1",
            "root": str(self.root),
            "root_exists": root_exists,
            "root_is_symlink": root_is_symlink,
            "read_only": True,
            "trace_count": trace_count,
            "corrupt_count": corrupt_count,
            "error": error,
            "external_calls": self.external_call_policy(),
        }

    def list_traces(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        status: str = "",
        q: str = "",
    ) -> dict[str, Any]:
        limit_value = self._bounded_int(
            limit,
            field_name="limit",
            minimum=1,
            maximum=200,
        )
        offset_value = self._bounded_int(
            offset,
            field_name="offset",
            minimum=0,
            maximum=1000000,
        )
        status_filter = str(status or "").strip().lower()
        query = str(q or "").strip().lower()
        if self.root.is_symlink():
            raise AgentTraceReadError(
                "Agent Trace root must not be a symlink"
            )
        if not self.root.is_dir():
            return self._list_response(
                limit_value,
                offset_value,
                [],
                [],
            )

        candidates: list[tuple[float, str]] = []
        for request_dir in self.root.iterdir():
            if not request_dir.is_dir() or request_dir.is_symlink():
                continue
            try:
                request_id = validate_request_id(request_dir.name)
            except ValueError:
                continue
            v12_dir = request_dir / "v12"
            if (
                not v12_dir.is_dir()
                or v12_dir.is_symlink()
                or not (v12_dir / "agent_runs.json").is_file()
            ):
                continue
            try:
                timestamp = v12_dir.stat().st_mtime
            except OSError:
                timestamp = 0.0
            candidates.append((timestamp, request_id))
        candidates.sort(
            key=lambda item: (item[0], item[1]),
            reverse=True,
        )

        items: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        for _, request_id in candidates:
            try:
                summary = self._list_summary(
                    self.get_trace(request_id)
                )
            except Exception as exc:
                errors.append(
                    {
                        "request_id": request_id,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                continue
            statuses = {
                item.lower()
                for item in summary["agent_statuses"]
            }
            if status_filter and (
                summary["final_state"].lower() != status_filter
                and status_filter not in statuses
            ):
                continue
            haystack = " ".join(
                [
                    summary["request_id"],
                    summary["final_state"],
                    summary["judge_status"],
                    summary["rca_status"],
                    *summary["agent_statuses"],
                ]
            ).lower()
            if query and query not in haystack:
                continue
            items.append(summary)
        return self._list_response(
            limit_value,
            offset_value,
            items,
            errors,
        )

    def get_trace(self, request_id: str) -> dict[str, Any]:
        safe_id = validate_request_id(request_id)
        directory = self._safe_v12_directory(safe_id)
        artifacts = {
            name: self._read_json(
                directory,
                name,
                required=(name == "agent_runs.json"),
                request_id=safe_id,
            )
            for name in TRACE_FILE_NAMES
        }
        runs = self._agent_runs_view(
            artifacts["agent_runs.json"],
            safe_id,
        )
        evidence = self._evidence_view(
            artifacts["evidence_bundle.json"],
            safe_id,
        )
        judge = self._judge_view(
            self._unwrap(
                artifacts["judge_result.json"],
                "judge_result",
            ),
            safe_id,
        )
        rca = self._rca_view(
            self._unwrap(
                artifacts["rca_result.json"],
                "rca_result",
            ),
            safe_id,
        )
        report = self._report_view(
            self._unwrap(
                artifacts["report.json"],
                "report_artifact",
            ),
            safe_id,
        )
        shadow = self._shadow_view(
            artifacts["shadow_integration.json"],
            safe_id,
        )
        references = self._artifact_references(
            safe_id,
            runs,
            evidence,
            judge,
            rca,
            report,
            shadow,
        )
        files = []
        for name in TRACE_FILE_NAMES:
            path = directory / name
            if path.is_file() and not path.is_symlink():
                files.append(
                    {
                        "name": name,
                        "size_bytes": path.stat().st_size,
                    }
                )
        return {
            "status": "ok",
            "schema_version": "v12.1",
            "request_id": safe_id,
            "read_only": True,
            "final_state": runs["final_state"],
            "state_history": runs["state_history"],
            "fallback_to_legacy": runs["fallback_to_legacy"],
            "stop_reason": runs["stop_reason"],
            "elapsed_ms": runs["elapsed_ms"],
            "agent_runs": runs["agent_runs"],
            "evidence_sources": evidence,
            "judge": judge,
            "rca": rca,
            "report": report,
            "shadow": shadow,
            "artifact_refs": references,
            "files": files,
            "data_boundaries": {
                "full_logs_exposed": False,
                "full_device_output_exposed": False,
                "full_metrics_exposed": False,
                "raw_payload_exposed": False,
            },
            "external_calls": self.external_call_policy(),
        }

    def _safe_v12_directory(self, request_id: str) -> Path:
        if self.root.is_symlink():
            raise AgentTraceReadError(
                "Agent Trace root must not be a symlink"
            )
        request_dir = self.root / request_id
        directory = request_dir / "v12"
        for path in (request_dir, directory):
            if path.is_symlink():
                raise AgentTraceReadError(
                    "Agent Trace directory must not be a symlink"
                )
        root_resolved = self.root.resolve(strict=False)
        resolved = directory.resolve(strict=False)
        try:
            resolved.relative_to(root_resolved)
        except ValueError as exc:
            raise AgentTraceReadError(
                "Agent Trace directory escapes root"
            ) from exc
        if not directory.is_dir():
            raise FileNotFoundError(
                f"v12 Agent Trace not found: {request_id}"
            )
        return directory

    def _read_json(
        self,
        directory: Path,
        name: str,
        *,
        required: bool,
        request_id: str,
    ) -> Mapping[str, Any] | None:
        if name not in TRACE_FILE_NAMES:
            raise AgentTraceReadError(
                f"unsupported Agent Trace file: {name}"
            )
        path = directory / name
        if path.is_symlink():
            raise AgentTraceCorruptError(
                f"Agent Trace file must not be a symlink: {name}"
            )
        if not path.is_file():
            if required:
                raise FileNotFoundError(path)
            return None
        if path.stat().st_size > self.max_file_bytes:
            raise AgentTraceCorruptError(
                f"Agent Trace file exceeds size budget: {name}"
            )
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AgentTraceCorruptError(
                f"Agent Trace file cannot be decoded: {name}"
            ) from exc
        if not isinstance(payload, Mapping):
            raise AgentTraceCorruptError(
                f"Agent Trace file root must be an object: {name}"
            )
        payload_request_id = payload.get("request_id")
        if (
            payload_request_id is not None
            and str(payload_request_id) != request_id
        ):
            raise AgentTraceCorruptError(
                f"request_id mismatch in {name}"
            )
        return payload

    @staticmethod
    def _unwrap(
        payload: Mapping[str, Any] | None,
        key: str,
    ) -> Mapping[str, Any] | None:
        if not isinstance(payload, Mapping):
            return None
        nested = payload.get(key)
        return nested if isinstance(nested, Mapping) else payload

    @staticmethod
    def _agent_runs_view(
        payload: Mapping[str, Any] | None,
        request_id: str,
    ) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise AgentTraceCorruptError(
                "agent_runs.json is missing"
            )
        raw_runs = payload.get("agent_runs")
        if not isinstance(raw_runs, list):
            raise AgentTraceCorruptError(
                "agent_runs must be a list"
            )
        runs = []
        for index, raw in enumerate(raw_runs):
            if not isinstance(raw, Mapping):
                raise AgentTraceCorruptError(
                    f"agent_runs[{index}] must be an object"
                )
            if str(raw.get("request_id", request_id)) != request_id:
                raise AgentTraceCorruptError(
                    f"agent_runs[{index}] request_id mismatch"
                )
            inputs = AgentTraceReadService._string_list(
                raw.get("inputs_ref")
            )
            outputs = AgentTraceReadService._string_list(
                raw.get("outputs_ref")
            )
            AgentTraceReadService._validate_refs(
                request_id,
                [*inputs, *outputs],
            )
            runs.append(
                {
                    "order": index + 1,
                    "agent_name": str(raw.get("agent_name") or ""),
                    "status": str(raw.get("status") or ""),
                    "started_at": raw.get("started_at"),
                    "finished_at": raw.get("finished_at"),
                    "duration_ms": AgentTraceReadService._safe_int(
                        raw.get("duration_ms")
                    ),
                    "inputs_ref": inputs,
                    "outputs_ref": outputs,
                    "error_categories": (
                        AgentTraceReadService._notice_codes(
                            raw.get("errors")
                        )
                    ),
                    "warning_categories": (
                        AgentTraceReadService._notice_codes(
                            raw.get("warnings")
                        )
                    ),
                    "external_call_count": len(
                        raw.get("external_calls")
                        if isinstance(raw.get("external_calls"), list)
                        else []
                    ),
                }
            )
        return {
            "final_state": str(payload.get("final_state") or ""),
            "state_history": AgentTraceReadService._string_list(
                payload.get("state_history")
            ),
            "fallback_to_legacy": bool(
                payload.get("fallback_to_legacy", False)
            ),
            "stop_reason": payload.get("stop_reason"),
            "elapsed_ms": AgentTraceReadService._safe_int(
                payload.get("elapsed_ms")
            ),
            "agent_runs": runs,
        }

    @staticmethod
    def _evidence_view(
        payload: Mapping[str, Any] | None,
        request_id: str,
    ) -> list[dict[str, Any]]:
        if not isinstance(payload, Mapping):
            return []
        evidence = payload.get("evidence")
        if not isinstance(evidence, Mapping):
            return []
        output = []
        for source in ("metrics", "device", "logs", "knowledge"):
            envelope = evidence.get(source)
            if not isinstance(envelope, Mapping):
                output.append(
                    {
                        "source": source,
                        "status": "missing",
                        "reason": "artifact_missing",
                        "ref_count": 0,
                        "evidence_refs": [],
                    }
                )
                continue
            refs = AgentTraceReadService._string_list(
                envelope.get("source_refs")
                if source == "knowledge"
                else envelope.get("evidence_refs")
            )
            AgentTraceReadService._validate_refs(request_id, refs)
            output.append(
                {
                    "source": source,
                    "status": str(envelope.get("status") or ""),
                    "reason": envelope.get("reason"),
                    "ref_count": len(refs),
                    "evidence_refs": refs,
                }
            )
        return output

    @staticmethod
    def _judge_view(
        payload: Mapping[str, Any] | None,
        request_id: str,
    ) -> dict[str, Any] | None:
        if not isinstance(payload, Mapping):
            return None
        refs = AgentTraceReadService._string_list(
            payload.get("evidence_refs")
        )
        AgentTraceReadService._validate_refs(request_id, refs)
        conflicts = []
        raw_conflicts = payload.get("conflicts")
        if isinstance(raw_conflicts, list):
            for item in raw_conflicts:
                if not isinstance(item, Mapping):
                    continue
                conflict_refs = AgentTraceReadService._string_list(
                    item.get("evidence_refs")
                )
                AgentTraceReadService._validate_refs(
                    request_id,
                    conflict_refs,
                )
                conflicts.append(
                    {
                        "statement": str(item.get("statement") or ""),
                        "severity": str(item.get("severity") or ""),
                        "evidence_refs": conflict_refs,
                    }
                )
        return {
            "status": str(payload.get("status") or ""),
            "rca_allowed": bool(payload.get("rca_allowed", False)),
            "confidence_cap": AgentTraceReadService._safe_float(
                payload.get("confidence_cap")
            ),
            "missing_required_sources": (
                AgentTraceReadService._string_list(
                    payload.get("missing_required_sources")
                )
            ),
            "missing_optional_sources": (
                AgentTraceReadService._string_list(
                    payload.get("missing_optional_sources")
                )
            ),
            "conflicts": conflicts,
            "evidence_refs": refs,
            "judged_at": payload.get("judged_at"),
        }

    @staticmethod
    def _rca_view(
        payload: Mapping[str, Any] | None,
        request_id: str,
    ) -> dict[str, Any] | None:
        if not isinstance(payload, Mapping):
            return None
        candidates = []
        raw_candidates = payload.get("candidates")
        if isinstance(raw_candidates, list):
            for item in raw_candidates:
                if not isinstance(item, Mapping):
                    continue
                supporting = AgentTraceReadService._string_list(
                    item.get("supporting_evidence_refs")
                )
                contradicting = AgentTraceReadService._string_list(
                    item.get("contradicting_evidence_refs")
                )
                AgentTraceReadService._validate_refs(
                    request_id,
                    [*supporting, *contradicting],
                )
                candidates.append(
                    {
                        "statement": str(item.get("statement") or ""),
                        "confidence": AgentTraceReadService._safe_float(
                            item.get("confidence")
                        ),
                        "supporting_evidence_refs": supporting,
                        "contradicting_evidence_refs": contradicting,
                        "missing_evidence": (
                            AgentTraceReadService._string_list(
                                item.get("missing_evidence")
                            )
                        ),
                        "uncertainties": (
                            AgentTraceReadService._string_list(
                                item.get("uncertainties")
                            )
                        ),
                    }
                )
        return {
            "status": str(payload.get("status") or ""),
            "provider": payload.get("provider"),
            "candidates": candidates,
            "missing_evidence": AgentTraceReadService._string_list(
                payload.get("missing_evidence")
            ),
            "uncertainties": AgentTraceReadService._string_list(
                payload.get("uncertainties")
            ),
            "generated_at": payload.get("generated_at"),
        }

    @staticmethod
    def _report_view(
        payload: Mapping[str, Any] | None,
        request_id: str,
    ) -> dict[str, Any] | None:
        if not isinstance(payload, Mapping):
            return None
        evidence_refs = AgentTraceReadService._string_list(
            payload.get("evidence_refs")
        )
        artifact_refs = AgentTraceReadService._string_list(
            payload.get("artifact_refs")
        )
        AgentTraceReadService._validate_refs(
            request_id,
            [*evidence_refs, *artifact_refs],
        )
        return {
            "status": str(payload.get("status") or ""),
            "title": str(payload.get("title") or ""),
            "summary": str(payload.get("summary") or ""),
            "notification_compatible": bool(
                payload.get("notification_compatible", True)
            ),
            "evidence_refs": evidence_refs,
            "artifact_refs": artifact_refs,
            "generated_at": payload.get("generated_at"),
        }

    @staticmethod
    def _shadow_view(
        payload: Mapping[str, Any] | None,
        request_id: str,
    ) -> dict[str, Any] | None:
        if not isinstance(payload, Mapping):
            return None
        refs = AgentTraceReadService._string_list(
            payload.get("artifact_refs")
        )
        AgentTraceReadService._validate_refs(request_id, refs)
        return {
            "status": str(payload.get("status") or ""),
            "reason": str(payload.get("reason") or ""),
            "legacy_preserved": bool(
                payload.get("legacy_preserved", True)
            ),
            "fail_open_to_legacy": bool(
                payload.get("fail_open_to_legacy", True)
            ),
            "legacy_notification_count": (
                AgentTraceReadService._safe_int(
                    payload.get("legacy_notification_count")
                )
            ),
            "shadow_notification_count": (
                AgentTraceReadService._safe_int(
                    payload.get("shadow_notification_count")
                )
            ),
            "notification_count_delta": (
                AgentTraceReadService._safe_int(
                    payload.get("notification_count_delta")
                )
            ),
            "second_card_sent": bool(
                payload.get("second_card_sent", False)
            ),
            "production_card_replaced": bool(
                payload.get("production_card_replaced", False)
            ),
            "artifact_refs": refs,
            "error_code": payload.get("error_code"),
        }

    @staticmethod
    def _artifact_references(
        request_id: str,
        runs: Mapping[str, Any],
        evidence: list[dict[str, Any]],
        judge: Mapping[str, Any] | None,
        rca: Mapping[str, Any] | None,
        report: Mapping[str, Any] | None,
        shadow: Mapping[str, Any] | None,
    ) -> list[str]:
        refs: list[str] = []
        for run in runs.get("agent_runs", []):
            if isinstance(run, Mapping):
                refs.extend(
                    AgentTraceReadService._string_list(
                        run.get("inputs_ref")
                    )
                )
                refs.extend(
                    AgentTraceReadService._string_list(
                        run.get("outputs_ref")
                    )
                )
        for source in evidence:
            refs.extend(
                AgentTraceReadService._string_list(
                    source.get("evidence_refs")
                )
            )
        if isinstance(judge, Mapping):
            refs.extend(
                AgentTraceReadService._string_list(
                    judge.get("evidence_refs")
                )
            )
            for conflict in judge.get("conflicts", []):
                if isinstance(conflict, Mapping):
                    refs.extend(
                        AgentTraceReadService._string_list(
                            conflict.get("evidence_refs")
                        )
                    )
        if isinstance(rca, Mapping):
            for candidate in rca.get("candidates", []):
                if isinstance(candidate, Mapping):
                    refs.extend(
                        AgentTraceReadService._string_list(
                            candidate.get("supporting_evidence_refs")
                        )
                    )
                    refs.extend(
                        AgentTraceReadService._string_list(
                            candidate.get(
                                "contradicting_evidence_refs"
                            )
                        )
                    )
        for item in (report, shadow):
            if isinstance(item, Mapping):
                refs.extend(
                    AgentTraceReadService._string_list(
                        item.get("evidence_refs")
                    )
                )
                refs.extend(
                    AgentTraceReadService._string_list(
                        item.get("artifact_refs")
                    )
                )
        unique = sorted(set(refs))
        AgentTraceReadService._validate_refs(request_id, unique)
        return unique

    @staticmethod
    def _list_summary(detail: Mapping[str, Any]) -> dict[str, Any]:
        judge = detail.get("judge")
        rca = detail.get("rca")
        statuses = [
            str(item.get("status") or "")
            for item in detail.get("agent_runs", [])
            if isinstance(item, Mapping)
        ]
        return {
            "request_id": str(detail.get("request_id") or ""),
            "final_state": str(detail.get("final_state") or ""),
            "fallback_to_legacy": bool(
                detail.get("fallback_to_legacy", False)
            ),
            "elapsed_ms": AgentTraceReadService._safe_int(
                detail.get("elapsed_ms")
            ),
            "agent_count": len(detail.get("agent_runs", [])),
            "agent_statuses": statuses,
            "judge_status": (
                str(judge.get("status") or "")
                if isinstance(judge, Mapping)
                else "not_persisted"
            ),
            "rca_status": (
                str(rca.get("status") or "")
                if isinstance(rca, Mapping)
                else "not_persisted"
            ),
            "artifact_ref_count": len(
                detail.get("artifact_refs", [])
            ),
        }

    def _list_response(
        self,
        limit: int,
        offset: int,
        items: list[dict[str, Any]],
        errors: list[dict[str, str]],
    ) -> dict[str, Any]:
        total = len(items)
        return {
            "status": "ok",
            "schema_version": "v12.1",
            "read_only": True,
            "total": total,
            "limit": limit,
            "offset": offset,
            "corrupt_count": len(errors),
            "items": items[offset : offset + limit],
            "errors": errors,
            "external_calls": self.external_call_policy(),
        }

    @staticmethod
    def _notice_codes(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return sorted(
            {
                str(item.get("code") or "")
                for item in value
                if isinstance(item, Mapping) and item.get("code")
            }
        )

    @staticmethod
    def _string_list(value: Any) -> list[str]:
        if not isinstance(value, (list, tuple)):
            return []
        return [str(item) for item in value if item is not None]

    @staticmethod
    def _safe_int(value: Any) -> int:
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _safe_float(value: Any) -> float:
        try:
            return float(value or 0.0)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _validate_refs(
        request_id: str,
        references: list[str],
    ) -> None:
        for reference in references:
            try:
                parsed = parse_contract_ref(reference)
            except Exception as exc:
                raise AgentTraceCorruptError(
                    f"invalid contract reference: {reference!r}"
                ) from exc
            if parsed["request_id"] != request_id:
                raise AgentTraceCorruptError(
                    "contract reference request_id mismatch"
                )

    @staticmethod
    def _bounded_int(
        value: int,
        *,
        field_name: str,
        minimum: int,
        maximum: int,
    ) -> int:
        if isinstance(value, bool):
            raise ValueError(f"{field_name} must be an integer")
        number = int(value)
        if number < minimum or number > maximum:
            raise ValueError(
                f"{field_name} must be between {minimum} and {maximum}"
            )
        return number


TraceServiceFactory = Callable[[], AgentTraceReadService]


def default_agent_trace_service() -> AgentTraceReadService:
    return AgentTraceReadService(DEFAULT_AGENT_TRACE_ROOT)


def _translate_error(exc: Exception) -> HTTPException:
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, AgentTraceCorruptError):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, AgentTraceReadError):
        return HTTPException(status_code=500, detail=str(exc))
    return HTTPException(
        status_code=500,
        detail=f"{type(exc).__name__}: {exc}",
    )


def create_agent_trace_api_router(
    service_factory: TraceServiceFactory = default_agent_trace_service,
) -> APIRouter:
    router = APIRouter(prefix="/agent", tags=["agent-trace"])

    @router.get("/health")
    async def agent_trace_health() -> dict[str, Any]:
        try:
            return service_factory().health()
        except Exception as exc:
            raise _translate_error(exc) from exc

    @router.get("/traces")
    async def agent_trace_list(
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
        status: str = "",
        q: str = "",
    ) -> dict[str, Any]:
        try:
            return service_factory().list_traces(
                limit=limit,
                offset=offset,
                status=status,
                q=q,
            )
        except Exception as exc:
            raise _translate_error(exc) from exc

    @router.get("/traces/{request_id}")
    async def agent_trace_detail(
        request_id: str,
    ) -> dict[str, Any]:
        try:
            return service_factory().get_trace(request_id)
        except Exception as exc:
            raise _translate_error(exc) from exc

    return router


router = create_agent_trace_api_router()


__all__ = [
    "AgentTraceCorruptError",
    "AgentTraceReadError",
    "AgentTraceReadService",
    "DEFAULT_AGENT_TRACE_ROOT",
    "MAX_TRACE_FILE_BYTES",
    "TRACE_FILE_NAMES",
    "create_agent_trace_api_router",
    "default_agent_trace_service",
    "router",
]
