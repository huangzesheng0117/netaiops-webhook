"""CLI for the Batch P2 Device/RCA continuation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from netaiops.v12.p2_device_continue import (
    P2ContinueError,
    evaluate_gate,
    preflight_report,
    run_continuation,
)
from netaiops.v12.p2_real_canary import P2RealCanaryError


def show(value: dict) -> None:
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
        description="Resume Batch P2 from Device/RCA only"
    )
    parser.add_argument(
        "action",
        choices=("preflight", "continue", "gate", "status"),
    )
    parser.add_argument("--state-dir", required=True)
    args = parser.parse_args()
    state = Path(args.state_dir)

    try:
        if args.action == "preflight":
            show(preflight_report(state_root=state))
            return 0
        if args.action == "continue":
            show(run_continuation(state_root=state))
            return 0
        if args.action == "gate":
            gate = evaluate_gate(state_root=state)
            show(gate)
            return 0 if gate["status"] == "passed" else 1

        show(
            {
                "status": "available",
                "state_dir": str(state),
                "preflight_exists": (
                    state / "preflight.json"
                ).is_file(),
                "metrics_checkpoint_exists": (
                    state / "checkpoints" / "metrics.json"
                ).is_file(),
                "device_checkpoint_exists": (
                    state / "checkpoints" / "device.json"
                ).is_file(),
                "rca_checkpoint_exists": (
                    state / "checkpoints" / "rca.json"
                ).is_file(),
                "result_exists": (
                    state / "continue_result.json"
                ).is_file(),
                "gate_exists": (
                    state / "gate.json"
                ).is_file(),
                "failure_exists": (
                    state / "CONTINUE_FAILURE_REPORT.json"
                ).is_file(),
            }
        )
        return 0
    except (
        P2ContinueError,
        P2RealCanaryError,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        show(
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
