"""Fail-open Shadow Integration controller for the v12 sidecar."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol

from pydantic import ValidationError

from .redaction import redact_for_persistence
from .schema_validator import stable_json_dumps
from .shadow_audit_store import (
    ShadowAuditStore,
    ShadowAuditStoreError,
)
from .shadow_contracts import (
    LegacyDeliverySnapshot,
    ShadowIntegrationAudit,
    ShadowIntegrationSettings,
    ShadowPipelineRequest,
    ShadowPipelineResult,
    ShadowStatus,
)


class ShadowPipelineRunner(Protocol):
    """Injected deterministic v12 Shadow pipeline."""

    async def run(
        self,
        request: ShadowPipelineRequest,
    ) -> ShadowPipelineResult | Mapping[str, Any]:
        """Run once without changing the legacy delivery result."""


class ShadowIntegrationController:
    """Run v12 after legacy delivery and always preserve legacy output."""

    def __init__(
        self,
        *,
        settings: ShadowIntegrationSettings | None = None,
        runner: ShadowPipelineRunner | None = None,
        audit_store: ShadowAuditStore | None = None,
        utcnow: Any | None = None,
    ) -> None:
        self.settings = settings or ShadowIntegrationSettings()
        self.runner = runner
        self.audit_store = audit_store
        self._utcnow = utcnow or (
            lambda: datetime.now(timezone.utc)
        )

    async def run_after_legacy(
        self,
        snapshot: LegacyDeliverySnapshot,
        *,
        input_refs: list[str] | None = None,
        input_snapshot: Mapping[str, Any] | None = None,
    ) -> ShadowIntegrationAudit:
        started_at = self._aware_now()

        if not self.settings.enabled:
            return self._audit(
                snapshot=snapshot,
                status=ShadowStatus.DISABLED,
                reason="v12_shadow_disabled",
                started_at=started_at,
                finished_at=self._aware_now(),
            )

        if snapshot.route in self.settings.excluded_routes:
            return self._audit(
                snapshot=snapshot,
                status=ShadowStatus.SKIPPED_ROUTE,
                reason="route_explicitly_excluded",
                started_at=started_at,
                finished_at=self._aware_now(),
            )

        if snapshot.route not in self.settings.allowed_routes:
            return self._audit(
                snapshot=snapshot,
                status=ShadowStatus.SKIPPED_ROUTE,
                reason="route_not_allowed",
                started_at=started_at,
                finished_at=self._aware_now(),
            )

        if not snapshot.legacy_completed:
            return self._audit(
                snapshot=snapshot,
                status=ShadowStatus.SKIPPED_LEGACY_INCOMPLETE,
                reason="legacy_delivery_not_completed",
                started_at=started_at,
                finished_at=self._aware_now(),
            )

        if self.runner is None:
            return self._failed_open(
                snapshot=snapshot,
                started_at=started_at,
                error_code="shadow_runner_missing",
            )

        try:
            request = ShadowPipelineRequest(
                request_id=snapshot.request_id,
                route=snapshot.route,
                alert_status=snapshot.alert_status,
                legacy_notification_count=(
                    snapshot.legacy_notification_count
                ),
                legacy_notification_ref=(
                    snapshot.legacy_notification_ref
                ),
                captured_at=snapshot.captured_at,
                input_refs=input_refs or [],
                input_snapshot=redact_for_persistence(
                    input_snapshot or {}
                ),
            )
            raw_result = await asyncio.wait_for(
                self.runner.run(request),
                timeout=self.settings.timeout_ms / 1000.0,
            )
            result = ShadowPipelineResult.model_validate(
                raw_result
            )
            if result.request_id != snapshot.request_id:
                raise ValueError(
                    "Shadow result request_id mismatch"
                )

            audit = self._audit(
                snapshot=snapshot,
                status=ShadowStatus.COMPLETED,
                reason="shadow_completed",
                started_at=started_at,
                finished_at=self._aware_now(),
                report_generated=result.report_generated,
                trace_written=result.trace_written,
                artifact_refs=result.artifact_refs,
            )

            if self.audit_store is not None:
                self.audit_store.persist(audit)
                audit = audit.model_copy(
                    update={"trace_written": True}
                )
            return audit
        except asyncio.TimeoutError:
            return self._failed_open(
                snapshot=snapshot,
                started_at=started_at,
                error_code="shadow_timeout",
            )
        except (
            ValidationError,
            ValueError,
            TypeError,
            ShadowAuditStoreError,
        ):
            return self._failed_open(
                snapshot=snapshot,
                started_at=started_at,
                error_code="shadow_validation_or_store_failed",
            )
        except Exception:
            return self._failed_open(
                snapshot=snapshot,
                started_at=started_at,
                error_code="shadow_runner_failed",
            )

    def _failed_open(
        self,
        *,
        snapshot: LegacyDeliverySnapshot,
        started_at: datetime,
        error_code: str,
    ) -> ShadowIntegrationAudit:
        return self._audit(
            snapshot=snapshot,
            status=ShadowStatus.FAILED_OPEN,
            reason="legacy_result_preserved_after_shadow_failure",
            started_at=started_at,
            finished_at=self._aware_now(),
            error_code=error_code,
        )

    def _audit(
        self,
        *,
        snapshot: LegacyDeliverySnapshot,
        status: ShadowStatus,
        reason: str,
        started_at: datetime,
        finished_at: datetime,
        report_generated: bool = False,
        trace_written: bool = False,
        artifact_refs: list[str] | None = None,
        error_code: str | None = None,
    ) -> ShadowIntegrationAudit:
        duration_ms = max(
            0,
            int(
                (
                    finished_at - started_at
                ).total_seconds()
                * 1000
            ),
        )
        return ShadowIntegrationAudit(
            request_id=snapshot.request_id,
            route=snapshot.route,
            status=status,
            reason=reason,
            legacy_notification_count=(
                snapshot.legacy_notification_count
            ),
            report_generated=report_generated,
            trace_written=trace_written,
            artifact_refs=artifact_refs or [],
            error_code=error_code,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
        )

    def _aware_now(self) -> datetime:
        value = self._utcnow()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(
                "utcnow provider must return a timezone-aware datetime"
            )
        return value


def shadow_audit_fingerprint(
    audit: ShadowIntegrationAudit,
) -> str:
    """Stable fingerprint for trace comparison and replay."""

    payload = audit.model_dump(
        mode="json",
        exclude={"started_at", "finished_at", "duration_ms"},
    )
    return hashlib.sha256(
        stable_json_dumps(payload).encode("utf-8")
    ).hexdigest()
