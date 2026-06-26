#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from netaiops.safety_policy import evaluate_plan_safety


def candidates(count, unsafe=False):
    out = []
    for idx in range(count):
        if unsafe and idx == count - 1:
            out.append({
                "capability": "",
                "command": "clear counters",
                "readonly": True,
            })
        else:
            out.append({
                "capability": "",
                "command": f"show clock",
                "readonly": True,
            })
    return out


def plan_for_family(family, playbook_id, count, unsafe=False):
    return {
        "request_id": "unit_test_safety_exception",
        "family_result": {"family": family},
        "classification": {
            "family": family,
            "auto_execute_allowed": True,
        },
        "playbook_runtime": {
            "family": family,
            "playbook_id": playbook_id,
            "execution": {
                "readonly_only": True,
                "auto_execute_allowed": True,
                "max_commands": 30,
            },
        },
        "playbook": {
            "playbook_id": playbook_id,
        },
        "target_scope": {
            "device_ip": "10.189.250.8",
            "hostname": "WG404-H0304-C95-INT-ACC",
        },
        "execution_candidates": candidates(count, unsafe=unsafe),
    }


def assert_case(name, condition, detail):
    print(f"{name}={condition}")
    if not condition:
        raise AssertionError(detail)


def main():
    # 1. 普通 family 仍然受全局 15 条限制，不能被放开。
    normal = plan_for_family(
        "interface_traffic_anomaly",
        "cisco_interface_traffic_anomaly",
        16,
    )
    normal_result = evaluate_plan_safety(normal)
    print("normal_result=", normal_result)
    assert_case(
        "normal_family_still_blocked_over_15",
        normal_result.get("allowed") is False and "too_many_commands" in (normal_result.get("reasons") or []),
        normal_result,
    )
    assert_case(
        "normal_family_max_still_15",
        int(normal_result.get("max_commands_per_request")) == 15,
        normal_result,
    )

    # 2. interface_or_link_utilization_high 25 条允许。
    util = plan_for_family(
        "interface_or_link_utilization_high",
        "cisco_interface_or_link_utilization_high",
        25,
    )
    util_result = evaluate_plan_safety(util)
    print("util_result=", util_result)
    assert_case(
        "utilization_family_allowed_25",
        util_result.get("allowed") is True and "too_many_commands" not in (util_result.get("reasons") or []),
        util_result,
    )
    assert_case(
        "utilization_family_max_30",
        int(util_result.get("max_commands_per_request")) == 30,
        util_result,
    )
    assert_case(
        "utilization_exception_marked",
        (util_result.get("family_max_commands_exception") or {}).get("matched") is True,
        util_result,
    )

    # 3. interface_or_link_utilization_high 超过 30 仍阻断。
    util_over = plan_for_family(
        "interface_or_link_utilization_high",
        "cisco_interface_or_link_utilization_high",
        31,
    )
    util_over_result = evaluate_plan_safety(util_over)
    print("util_over_result=", util_over_result)
    assert_case(
        "utilization_family_blocked_over_30",
        util_over_result.get("allowed") is False and "too_many_commands" in (util_over_result.get("reasons") or []),
        util_over_result,
    )

    # 4. 即使是 interface_or_link_utilization_high，如果命令本身危险，也必须阻断。
    util_unsafe = plan_for_family(
        "interface_or_link_utilization_high",
        "cisco_interface_or_link_utilization_high",
        10,
        unsafe=True,
    )
    util_unsafe_result = evaluate_plan_safety(util_unsafe)
    print("util_unsafe_result=", util_unsafe_result)
    assert_case(
        "utilization_family_still_blocks_unsafe_candidate",
        util_unsafe_result.get("allowed") is False and "unsafe_candidate" in (util_unsafe_result.get("reasons") or []),
        util_unsafe_result,
    )

    print("[OK] interface utilization safety exception tests passed")


if __name__ == "__main__":
    main()
