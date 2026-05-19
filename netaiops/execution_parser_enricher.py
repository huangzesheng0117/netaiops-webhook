from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from netaiops.parser_registry import enrich_command_results_with_parsed


def _safe_read_json(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def _safe_write_json(path: str | Path, data: dict[str, Any]) -> None:
    p = Path(path)
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _count_parse_statuses(execution_data: dict[str, Any]) -> dict[str, int]:
    counters: dict[str, int] = {}

    for item in execution_data.get("command_results", []) or []:
        if not isinstance(item, dict):
            continue

        parsed = item.get("parsed") if isinstance(item.get("parsed"), dict) else {}
        status = str(parsed.get("status") or "missing")
        counters[status] = counters.get(status, 0) + 1

    return counters


def enrich_execution_data(execution_data: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    enriched = enrich_command_results_with_parsed(execution_data or {})
    status_counts = _count_parse_statuses(enriched)

    result = {
        "ok": True,
        "stage": "v6.2",
        "mode": "parser_registry_enrich",
        "command_count": len(enriched.get("command_results") or []),
        "parse_status_counts": status_counts,
    }

    return enriched, result


def enrich_execution_file(execution_file: str | Path) -> dict[str, Any]:
    p = Path(execution_file)
    data = _safe_read_json(p)

    if not data:
        return {
            "ok": False,
            "stage": "v6.2",
            "error": f"execution file not found or empty: {p}",
            "execution_file": str(p),
        }

    if isinstance(data.get("execution_data"), dict):
        enriched, result = enrich_execution_data(data.get("execution_data") or {})
        data["execution_data"] = enriched
    else:
        enriched, result = enrich_execution_data(data)
        data = enriched

    _safe_write_json(p, data)

    result["execution_file"] = str(p)
    return result


def enrich_callback_execution_result(callback_result: dict[str, Any]) -> dict[str, Any]:
    callback_result = callback_result or {}

    execution_file = callback_result.get("execution_file")
    execution_data = callback_result.get("execution_data")

    if not execution_file and not isinstance(execution_data, dict):
        return {
            "ok": False,
            "stage": "v6.2",
            "mode": "parser_registry_enrich",
            "error": "callback_result has no execution_file or execution_data",
        }

    if execution_file:
        result = enrich_execution_file(execution_file)

        try:
            data = _safe_read_json(execution_file)
            if isinstance(data.get("execution_data"), dict):
                callback_result["execution_data"] = data.get("execution_data")
            else:
                callback_result["execution_data"] = data
        except Exception:
            pass

        return result

    enriched, result = enrich_execution_data(execution_data or {})
    callback_result["execution_data"] = enriched
    return result
