"""CLI for the Batch P2 final RCA-only continuation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Direct execution sets sys.path[0] to the scripts directory. Add the
# repository root before importing the project package so this CLI works
# without relying on an inherited PYTHONPATH.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
project_root_text = str(PROJECT_ROOT)
if project_root_text not in sys.path:
    sys.path.insert(0, project_root_text)

from netaiops.v12.p2_device_continue import P2ContinueError
from netaiops.v12.p2_real_canary import P2RealCanaryError
from netaiops.v12.p2_rca_continue import (
    P2RCAContinueError,
    evaluate_v8_gate,
    preflight_report,
    run_rca_continuation,
)


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
        description="Resume Batch P2 from RCA only"
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
            show(preflight_report(state))
            return 0
        if args.action == "continue":
            show(run_rca_continuation(state))
            return 0
        if args.action == "gate":
            gate = evaluate_v8_gate(state)
            show(gate)
            return 0 if gate["status"] == "passed" else 1

        show(
            {
                "status": "available",
                "state_dir": str(state),
                "preflight_exists": (
                    state / "preflight.json"
                ).is_file(),
                "historical_replay_planner_dry_run_exists": (
                    state / "historical_replay_planner_dry_run.json"
                ).is_file(),
                "historical_replay_dry_run_exists": (
                    state / "historical_replay_judge_dry_run.json"
                ).is_file(),
                "glm_attempt_exists": (
                    state / "glm_attempt.json"
                ).is_file(),
                "rca_validation_exists": (
                    state / "rca_validation.json"
                ).is_file(),
                "rca_checkpoint_exists": (
                    state / "checkpoints" / "rca.json"
                ).is_file(),
                "result_exists": (
                    state / "continue_result.json"
                ).is_file(),
                "gate_exists": (
                    state / "final_gate.json"
                ).is_file(),
                "failure_exists": (
                    state
                    / "RCA_CONTINUE_FAILURE_REPORT.json"
                ).is_file(),
            }
        )
        return 0
    except (
        P2RCAContinueError,
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
