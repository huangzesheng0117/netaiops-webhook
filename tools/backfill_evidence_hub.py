#!/usr/bin/env python3
"""Backfill Evidence Hub request details for historical request_id records.

v10 Batch 11 boundaries:
- read historical request artifacts from data/* only
- write generated details under data/evidence_hub/requests/<request_id>/ only
- do not modify source artifacts
- do not touch network devices
- do not send DingDong notifications
- do not integrate into the production pipeline
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - PyYAML is expected in the venv, but optional here.
    yaml = None  # type: ignore

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from netaiops.evidence_hub.detail_url import build_detail_url  # noqa: E402
from netaiops.evidence_hub.schema import safe_request_id  # noqa: E402
from netaiops.evidence_hub.writer import build_evidence_detail  # noqa: E402

JsonDict = Dict[str, Any]

REQUEST_ID_RE = re.compile(
    r"(?P<rid>\d{8}_\d{6}_[0-9A-Za-z]{4,}_[0-9A-Za-z]{4,})"
)

DEFAULT_SCAN_DIRS = (
    "data/raw",
    "data/normalized",
    "data/analysis",
    "data/plans",
    "data/prometheus_evidence",
    "data/execution",
    "data/reviews",
    "data/callback",
)


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _print(message: str, *, quiet: bool = False) -> None:
    if not quiet:
        print(message)


def extract_request_ids_from_text(text: str) -> List[str]:
    """Extract unique request_id values from a filename or arbitrary text."""
    seen: set[str] = set()
    result: List[str] = []
    for match in REQUEST_ID_RE.finditer(text or ""):
        rid = match.group("rid")
        if rid not in seen:
            seen.add(rid)
            result.append(rid)
    return result


def extract_request_ids_from_path(path: Path) -> List[str]:
    """Extract request_id values from a path string."""
    return extract_request_ids_from_text(str(path))


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _relative_path(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except Exception:
        return str(path)


def discover_request_ids(
    *,
    base_dir: Path,
    scan_dirs: Sequence[str] = DEFAULT_SCAN_DIRS,
) -> List[Tuple[str, float, str]]:
    """Discover request_id values from historical data filenames.

    Returns tuples of (request_id, latest_mtime, sample_path), sorted by latest_mtime
    descending.
    """
    discovered: Dict[str, Tuple[float, str]] = {}
    base = Path(base_dir)
    for rel_dir in scan_dirs:
        root = base / rel_dir
        if not root.exists() or not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            ids = extract_request_ids_from_path(path)
            if not ids:
                continue
            mt = _mtime(path)
            rel_path = _relative_path(path, base)
            for rid in ids:
                old = discovered.get(rid)
                if old is None or mt > old[0]:
                    discovered[rid] = (mt, rel_path)
    return sorted(
        ((rid, mt, sample) for rid, (mt, sample) in discovered.items()),
        key=lambda item: (item[1], item[0]),
        reverse=True,
    )


def _load_yaml_config(path: Path) -> JsonDict:
    if not path.exists() or not path.is_file():
        return {}
    if yaml is None:
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _unique_request_ids(values: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for value in values:
        text = _as_text(value)
        if not text:
            continue
        rid = safe_request_id(text)
        if rid not in seen:
            seen.add(rid)
            result.append(rid)
    return result


def resolve_target_request_ids(
    *,
    explicit_ids: Sequence[str],
    latest: int,
    base_dir: Path,
) -> List[str]:
    ids = _unique_request_ids(explicit_ids)
    if latest > 0:
        discovered = discover_request_ids(base_dir=base_dir)
        for rid, _mtime_value, _sample in discovered[:latest]:
            if rid not in ids:
                ids.append(rid)
    return ids


def _result_status(result: Mapping[str, Any]) -> str:
    status = _as_text(result.get("status"))
    if status:
        return status
    return "ok" if result else "unknown"


def backfill_request_ids(
    request_ids: Sequence[str],
    *,
    base_dir: Path,
    config: Optional[Mapping[str, Any]] = None,
    dry_run: bool = False,
    overwrite: bool = True,
) -> JsonDict:
    """Backfill Evidence Hub details for a list of request IDs."""
    results: List[JsonDict] = []
    ok_count = 0
    error_count = 0
    dry_run_count = 0

    for rid_raw in request_ids:
        rid = safe_request_id(rid_raw)
        detail_url = build_detail_url(rid, config=config)
        if dry_run:
            results.append({
                "request_id": rid,
                "status": "dry_run",
                "detail_url": detail_url,
                "would_write": f"data/evidence_hub/requests/{rid}",
            })
            dry_run_count += 1
            continue

        try:
            result = build_evidence_detail(
                rid,
                base_dir=Path(base_dir),
                detail_url=detail_url,
                overwrite=overwrite,
            )
            item = dict(result or {})
            item.setdefault("request_id", rid)
            item.setdefault("detail_url", detail_url)
            item.setdefault("status", _result_status(item))
            results.append(item)
            if item.get("status") == "ok":
                ok_count += 1
            else:
                error_count += 1
        except Exception as exc:
            results.append({
                "request_id": rid,
                "status": "error",
                "detail_url": detail_url,
                "error": f"{type(exc).__name__}: {exc}",
            })
            error_count += 1

    return {
        "status": "ok" if error_count == 0 else "partial_error",
        "requested": len(request_ids),
        "ok": ok_count,
        "dry_run": dry_run_count,
        "errors": error_count,
        "results": results,
    }


def _print_human_report(report: Mapping[str, Any], *, quiet: bool = False) -> None:
    _print(
        "[SUMMARY] requested={requested} ok={ok} dry_run={dry_run} errors={errors} status={status}".format(
            requested=report.get("requested"),
            ok=report.get("ok"),
            dry_run=report.get("dry_run"),
            errors=report.get("errors"),
            status=report.get("status"),
        ),
        quiet=quiet,
    )
    for item in report.get("results", []):
        if not isinstance(item, Mapping):
            continue
        rid = item.get("request_id")
        status = item.get("status")
        detail_dir = item.get("detail_dir_rel") or item.get("detail_dir") or item.get("would_write") or ""
        missing = item.get("missing_sections")
        read_errors = item.get("read_error_sections")
        detail_url = item.get("detail_url") or ""
        error = item.get("error") or ""
        line = f"- {rid}: status={status} detail={detail_dir}"
        if detail_url:
            line += f" url={detail_url}"
        if missing:
            line += f" missing={missing}"
        if read_errors:
            line += f" read_errors={read_errors}"
        if error:
            line += f" error={error}"
        _print(line, quiet=quiet)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Backfill Evidence Hub details for historical request_id values.",
    )
    parser.add_argument(
        "--request-id",
        action="append",
        default=[],
        help="Specific request_id to backfill. Can be used multiple times.",
    )
    parser.add_argument(
        "--latest",
        type=int,
        default=0,
        help="Backfill the latest N discovered request_id values from data directories.",
    )
    parser.add_argument(
        "--base-dir",
        default=".",
        help="Project base directory. Defaults to current directory.",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Config YAML path used only for non-secret Evidence Hub base URL settings.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be backfilled without writing detail files.",
    )
    parser.add_argument(
        "--no-overwrite",
        action="store_true",
        help="Do not overwrite existing detail files.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON report.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress human-readable progress output. JSON output is still printed with --json.",
    )
    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        help="Return non-zero when any request_id fails.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.latest < 0:
        parser.error("--latest must be >= 0")

    base_dir = Path(args.base_dir).resolve()
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = base_dir / config_path
    config = _load_yaml_config(config_path)

    try:
        request_ids = resolve_target_request_ids(
            explicit_ids=args.request_id,
            latest=args.latest,
            base_dir=base_dir,
        )
    except Exception as exc:
        print(f"[FAIL] request_id discovery failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    if not request_ids:
        print(
            "[FAIL] no request_id selected; use --request-id <rid> or --latest <N>",
            file=sys.stderr,
        )
        return 2

    _print(f"[INFO] selected request_id count={len(request_ids)}", quiet=args.quiet or args.json)
    report = backfill_request_ids(
        request_ids,
        base_dir=base_dir,
        config=config,
        dry_run=args.dry_run,
        overwrite=not args.no_overwrite,
    )

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        _print_human_report(report, quiet=args.quiet)

    if args.fail_on_error and int(report.get("errors") or 0) > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
