"""Adapter around the existing Alertmanager and Elastic normalizers."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from netaiops.normalizers import normalize_alertmanager, normalize_elastic


class UnsupportedAlertSourceError(ValueError):
    """Raised when Batch D receives a source outside its approved scope."""


class NormalizedEventSelectionError(ValueError):
    """Raised when normalization produces no selectable event."""


class NormalizerAdapter:
    """Reuse current normalizers without changing their production behavior."""

    _NORMALIZERS = {
        "alertmanager": normalize_alertmanager,
        "elastic": normalize_elastic,
    }

    def normalize(
        self,
        source: str,
        payload: Mapping[str, Any],
    ) -> tuple[dict[str, Any], ...]:
        normalized_source = str(source or "").strip().lower()
        normalizer = self._NORMALIZERS.get(normalized_source)
        if normalizer is None:
            raise UnsupportedAlertSourceError(
                f"unsupported triage source: {normalized_source or '<empty>'}"
            )
        if not isinstance(payload, Mapping):
            raise NormalizedEventSelectionError("payload must be a mapping")

        payload_copy = deepcopy(dict(payload))
        result = normalizer(payload_copy)
        if not isinstance(result, list):
            raise NormalizedEventSelectionError(
                "normalizer result must be a list"
            )

        events: list[dict[str, Any]] = []
        for index, item in enumerate(result):
            if not isinstance(item, Mapping):
                raise NormalizedEventSelectionError(
                    f"normalized event {index} must be a mapping"
                )
            event = deepcopy(dict(item))
            event["_v12_source"] = normalized_source
            event["_v12_index"] = index
            self._attach_source_metadata(
                normalized_source,
                payload_copy,
                index,
                event,
            )
            events.append(event)
        return tuple(events)

    def select_event(
        self,
        source: str,
        payload: Mapping[str, Any],
        *,
        event_index: int = 0,
    ) -> dict[str, Any]:
        events = self.normalize(source, payload)
        if not events:
            raise NormalizedEventSelectionError(
                "normalizer produced no events"
            )
        if event_index < 0 or event_index >= len(events):
            raise NormalizedEventSelectionError(
                f"event_index out of range: {event_index}"
            )
        return deepcopy(events[event_index])

    def _attach_source_metadata(
        self,
        source: str,
        payload: Mapping[str, Any],
        index: int,
        event: dict[str, Any],
    ) -> None:
        if source == "alertmanager":
            alerts = payload.get("alerts")
            if isinstance(alerts, list) and index < len(alerts):
                raw_alert = alerts[index]
                if isinstance(raw_alert, Mapping):
                    event["_v12_ends_at"] = raw_alert.get("endsAt")
                    event["_v12_fingerprint"] = raw_alert.get("fingerprint")
            return

        hits = (
            ((payload.get("hits") or {}).get("hits") or [])
            if isinstance(payload.get("hits"), Mapping)
            else []
        )
        if not hits and isinstance(payload.get("_source"), Mapping):
            hits = [payload]
        if isinstance(hits, list) and index < len(hits):
            raw_hit = hits[index]
            if isinstance(raw_hit, Mapping):
                event["_v12_document_id"] = raw_hit.get("_id")
