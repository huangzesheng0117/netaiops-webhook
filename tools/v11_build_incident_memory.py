#!/usr/bin/env python3
"""Build one v11 Incident Memory record from historical request artifacts.

This tool is local and read-only with respect to existing request artifacts. It
writes only to the explicitly supplied Governance output root. It never calls
GLM, Prometheus MCP, Netmiko MCP, DingTalk, or the production webhook.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_IMPORT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_IMPORT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_IMPORT_ROOT))

from netaiops.governance.artifact_reader import read_request_artifacts  # noqa: E402
from netaiops.governance.memory_builder import (  # noqa: E402
    build_incident_memory,
    memory_safety_summary,
)
from netaiops.governance.store import GovernanceStore  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a governed Incident Memory record from one request_id."
    )
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument(
        "--output-root",
        required=True,
        help="Governance store root; use a /tmp path for Batch 2 verification.",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Print only the final machine-readable report.",
    )
    parser.add_argument(
        "--no-overwrite",
        action="store_true",
        help="Fail if the deterministic memory_id already exists.",
    )
    parser.add_argument(
        "--allow-production-output",
        action="store_true",
        help="Explicitly allow output under <project-root>/data/governance.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    project_root = Path(args.project_root).expanduser().resolve(strict=False)
    output_root = Path(args.output_root).expanduser().resolve(strict=False)

    production_root = (project_root / "data" / "governance").resolve(strict=False)
    try:
        writes_production = output_root == production_root or output_root.is_relative_to(
            production_root
        )
    except AttributeError:  # pragma: no cover - Python 3.10+ has is_relative_to
        writes_production = output_root == production_root
    if writes_production and not args.allow_production_output:
        raise SystemExit(
            "refusing production Governance output without "
            "--allow-production-output"
        )

    bundle = read_request_artifacts(project_root, args.request_id)
    memory = build_incident_memory(bundle)
    safety = memory_safety_summary(memory)
    if not safety["safe"]:
        raise SystemExit(f"memory safety check failed: {safety!r}")

    store = GovernanceStore(output_root)
    result = store.write(
        "incident_memory",
        memory.memory_id,
        memory,
        overwrite=not args.no_overwrite,
    )
    persisted = store.read("incident_memory", memory.memory_id)

    report = {
        "status": "ok",
        "request_id": memory.request_id,
        "memory_id": memory.memory_id,
        "output_root": str(output_root),
        "output_file": result.path,
        "sha256": result.sha256,
        "size_bytes": result.size_bytes,
        "created": result.created,
        "artifact_count": bundle.artifact_count,
        "missing_kinds": list(bundle.missing_kinds),
        "read_errors": [dict(item) for item in bundle.read_errors],
        "warnings": list(bundle.warnings),
        "quality_flags": list(memory.quality_flags),
        "evidence_status": persisted.get("evidence_status", {}),
        "safety": safety,
        "external_calls": {
            "glm": False,
            "prometheus": False,
            "device": False,
            "notification": False,
        },
        "production_data_written": writes_production,
    }

    if not args.json_only:
        print(
            f"Incident Memory built: {memory.memory_id} -> {result.path}",
            file=sys.stderr,
        )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
