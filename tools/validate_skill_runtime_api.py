#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import urllib.parse
import urllib.request


def get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate NetAIOps v6.4 skill runtime HTTP APIs.")
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    parser.add_argument("--family", default="interface_or_link_utilization_high")
    parser.add_argument("--skill", default="interface_utilization_high")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")

    results = {}

    results["index"] = get_json(f"{base}/v6/skills/runtime")
    results["validate"] = get_json(f"{base}/v6/skills/runtime/validate")

    family_q = urllib.parse.quote(args.family)
    skill_q = urllib.parse.quote(args.skill)

    results["family_metadata"] = get_json(
        f"{base}/v6/skills/runtime/family/{family_q}?levels=metadata"
    )

    results["family_commands"] = get_json(
        f"{base}/v6/skills/runtime/family/{family_q}?levels=metadata,commands"
    )

    results["skill_full"] = get_json(
        f"{base}/v6/skills/runtime/skill/{skill_q}?levels=metadata,instructions,commands,evidence,schema"
    )

    print(json.dumps({
        "index_status": results["index"].get("status"),
        "index_skill_count": results["index"].get("skill_count"),
        "validate_status": results["validate"].get("status"),
        "validate_verdict": results["validate"].get("result", {}).get("verdict"),
        "family_status": results["family_metadata"].get("status"),
        "family_loaded_levels": results["family_metadata"].get("runtime_context", {}).get("loaded_levels"),
        "family_commands_loaded_levels": results["family_commands"].get("runtime_context", {}).get("loaded_levels"),
        "family_commands_content_embedded": results["family_commands"].get("runtime_context", {}).get("runtime_api", {}).get("content_embedded"),
        "skill_full_status": results["skill_full"].get("status"),
        "skill_full_loaded_levels": results["skill_full"].get("runtime_context", {}).get("loaded_levels"),
        "skill_full_content_embedded": results["skill_full"].get("runtime_context", {}).get("runtime_api", {}).get("content_embedded"),
    }, ensure_ascii=False, indent=2))

    assert results["index"].get("status") == "ok"
    assert results["index"].get("skill_count", 0) >= 1
    assert results["validate"].get("status") == "ok"
    assert results["validate"].get("result", {}).get("verdict") == "pass"

    family_context = results["family_metadata"].get("runtime_context", {})
    assert results["family_metadata"].get("status") == "ok"
    assert family_context.get("matched") is True
    assert family_context.get("skill_name") == args.skill
    assert family_context.get("loaded_levels") == ["metadata"]

    family_commands_context = results["family_commands"].get("runtime_context", {})
    assert family_commands_context.get("loaded_levels") == ["metadata", "commands"]
    assert family_commands_context.get("runtime_api", {}).get("content_embedded") is True

    skill_full_context = results["skill_full"].get("runtime_context", {})
    assert results["skill_full"].get("status") == "ok"
    assert skill_full_context.get("skill_name") == args.skill
    assert skill_full_context.get("loaded_levels") == ["metadata", "instructions", "commands", "evidence", "schema"]
    assert skill_full_context.get("runtime_api", {}).get("content_embedded") is True

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
