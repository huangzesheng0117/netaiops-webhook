#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import yaml

from netaiops.llm_client import check_llm_health


def load_config(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Check NetAIOps local LLM gateway connectivity.")
    parser.add_argument("--config", default="/opt/netaiops-webhook/config.yaml")
    parser.add_argument("--models", action="store_true", help="Call /v1/models on configured endpoint(s).")
    parser.add_argument("--chat-smoke", action="store_true", help="Run a tiny chat completion JSON smoke test.")
    args = parser.parse_args()

    config = load_config(Path(args.config))
    result = check_llm_health(config, include_models=args.models, chat_smoke=args.chat_smoke)
    print(json.dumps(result, ensure_ascii=False, indent=2))

    return 0 if result.get("overall_status") in {"ok", "disabled"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
