"""FastAPI routes for the read-only v11 Governance API."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from .service import GovernanceApiServiceError, GovernanceReadService, default_governance_service
from .store import CorruptRecordError, GovernanceStoreError, UnsafeStorePathError

ServiceFactory = Callable[[], GovernanceReadService]


def _translate_error(exc: Exception) -> HTTPException:
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, (GovernanceApiServiceError, UnsafeStorePathError, ValueError)):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, CorruptRecordError):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, GovernanceStoreError):
        return HTTPException(status_code=500, detail=str(exc))
    return HTTPException(status_code=500, detail=f"{type(exc).__name__}: {exc}")


def create_governance_router(
    service_factory: ServiceFactory = default_governance_service,
) -> APIRouter:
    router = APIRouter(prefix="/governance", tags=["governance"])

    def service() -> GovernanceReadService:
        return service_factory()

    def list_collection_response(
        collection: str,
        *,
        page: int,
        page_size: int,
        descending: bool,
    ) -> dict[str, Any]:
        try:
            return service().list_records(
                collection,
                page=page,
                page_size=page_size,
                descending=descending,
            )
        except Exception as exc:
            raise _translate_error(exc) from exc

    def get_record_response(collection: str, record_id: str) -> dict[str, Any]:
        try:
            return service().get_record(collection, record_id)
        except Exception as exc:
            raise _translate_error(exc) from exc

    @router.get("/health")
    async def governance_health() -> dict[str, Any]:
        try:
            return service().health()
        except Exception as exc:
            raise _translate_error(exc) from exc

    @router.get("/summary")
    async def governance_summary() -> dict[str, Any]:
        try:
            return service().summary()
        except Exception as exc:
            raise _translate_error(exc) from exc

    @router.get("/collections")
    async def governance_collections() -> dict[str, Any]:
        try:
            return service().collections()
        except Exception as exc:
            raise _translate_error(exc) from exc

    @router.get("/collections/{collection}")
    async def governance_collection(
        collection: str,
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=500),
        descending: bool = True,
    ) -> dict[str, Any]:
        return list_collection_response(
            collection,
            page=page,
            page_size=page_size,
            descending=descending,
        )

    @router.get("/collections/{collection}/{record_id}")
    async def governance_collection_record(collection: str, record_id: str) -> dict[str, Any]:
        return get_record_response(collection, record_id)

    @router.get("/memories")
    async def governance_memories(
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=500),
        descending: bool = True,
    ) -> dict[str, Any]:
        return list_collection_response("incident_memory", page=page, page_size=page_size, descending=descending)

    @router.get("/memories/{memory_id}")
    async def governance_memory(memory_id: str) -> dict[str, Any]:
        return get_record_response("incident_memory", memory_id)

    @router.get("/signals")
    async def governance_signals(page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500), descending: bool = True) -> dict[str, Any]:
        return list_collection_response("signals", page=page, page_size=page_size, descending=descending)

    @router.get("/signals/{signal_id}")
    async def governance_signal(signal_id: str) -> dict[str, Any]:
        return get_record_response("signals", signal_id)

    @router.get("/proposals")
    async def governance_proposals(page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500), descending: bool = True) -> dict[str, Any]:
        return list_collection_response("proposals", page=page, page_size=page_size, descending=descending)

    @router.get("/proposals/{proposal_id}")
    async def governance_proposal(proposal_id: str) -> dict[str, Any]:
        return get_record_response("proposals", proposal_id)

    @router.get("/replays")
    async def governance_replays(page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500), descending: bool = True) -> dict[str, Any]:
        return list_collection_response("replays", page=page, page_size=page_size, descending=descending)

    @router.get("/replays/{replay_id}")
    async def governance_replay(replay_id: str) -> dict[str, Any]:
        return get_record_response("replays", replay_id)

    @router.get("/reports")
    async def governance_reports(page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500), descending: bool = True) -> dict[str, Any]:
        return list_collection_response("reports", page=page, page_size=page_size, descending=descending)

    @router.get("/reports/{report_id}")
    async def governance_report(report_id: str) -> dict[str, Any]:
        return get_record_response("reports", report_id)

    @router.get("/audits")
    async def governance_audits(page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500), descending: bool = True) -> dict[str, Any]:
        return list_collection_response("audits", page=page, page_size=page_size, descending=descending)

    @router.get("/audits/{audit_id}")
    async def governance_audit(audit_id: str) -> dict[str, Any]:
        return get_record_response("audits", audit_id)

    return router


router = create_governance_router()

__all__ = ["create_governance_router", "router"]
