"""CLI for the single Batch P2 controlled real-Agent Canary."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from netaiops.v12.p2_real_canary import (
    P2RealCanaryError,
    discovery_report,
    evaluate_real_canary_gate,
    run_real_canary,
)


def _print(value: dict) -> None:
    print(
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the v12 Batch P2 controlled real Canary"
    )
    parser.add_argument(
        "action",
        choices=("discover", "run", "gate", "status"),
    )
    parser.add_argument(
        "--state-dir",
        required=True,
    )
    args = parser.parse_args()
    state = Path(args.state_dir)

    try:
        if args.action == "discover":
            _print(discovery_report(state_dir=state))
            return 0
        if args.action == "run":
            _print(run_real_canary(state_dir=state))
            return 0
        if args.action == "gate":
            gate = evaluate_real_canary_gate(
                state_dir=state
            )
            _print(gate)
            return 0 if gate["status"] == "passed" else 1

        result_path = state / "real_canary_result.json"
        gate_path = state / "gate.json"
        _print(
            {
                "status": "available"
                if result_path.is_file()
                else "not_run",
                "state_dir": str(state),
                "discovery_exists": (
                    state / "discovery.json"
                ).is_file(),
                "result_exists": result_path.is_file(),
                "gate_exists": gate_path.is_file(),
                "failure_exists": (
                    state / "P2_FAILURE_REPORT.json"
                ).is_file(),
            }
        )
        return 0
    except (
        P2RealCanaryError,
        OSError,
        ValueError,
        RuntimeError,
    ) as exc:
        _print(
            {
                "status": "failed",
                "action": args.action,
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
