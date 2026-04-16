import json
import sys
from pathlib import Path

BASE_DIR = Path("/opt/netaiops-webhook")
PLAN_DIR = BASE_DIR / "data" / "plans"


def main():
    if len(sys.argv) != 4:
        print("Usage: python tools_make_manual_plan.py <request_id> <hostname> <device_ip>")
        raise SystemExit(1)

    request_id = sys.argv[1]
    hostname = sys.argv[2]
    device_ip = sys.argv[3]

    plan = {
        "request_id": request_id,
        "plan_id": f"plan_{request_id}",
        "source": "manual",
        "plan_type": "network_readonly_diagnosis",
        "plan_status": "confirmed",
        "readonly_only": True,
        "requires_confirmation": False,
        "confidence": "manual",
        "summary": "Manual MCP integration test for a real Cisco NX-OS device.",
        "recommended_next_step": "Run readonly commands through the real MCP helper.",
        "target_scope": {
            "vendor": "cisco",
            "hostname": hostname,
            "device_ip": device_ip,
            "alarm_type": "manual_readonly_test"
        },
        "execution_candidates": [
            {
                "order": 1,
                "command": "show clock",
                "reason": "manual_real_mcp_test",
                "risk": "low",
                "readonly": True
            },
            {
                "order": 2,
                "command": "show ip interface brief",
                "reason": "manual_real_mcp_test",
                "risk": "low",
                "readonly": True
            }
        ],
        "guard_result": {
            "all_readonly": True,
            "allowed_count": 2,
            "blocked_count": 0,
            "allowed_commands": [
                "show clock",
                "show ip interface brief"
            ],
            "blocked_commands": []
        },
        "classification": {
            "vendor": "cisco",
            "source": "manual",
            "alarm_type": "manual_readonly_test",
            "severity": "",
            "metric_name": "",
            "object_type": "",
            "object_name": "",
            "playbook_type": "cisco_nxos_basic_readonly",
            "prompt_profile": "quick",
            "auto_execute_allowed": True,
            "classification_confidence": "manual",
            "match_reason": "manual_real_device_test"
        },
        "playbook": {
            "matched": True,
            "playbook_id": "cisco_nxos_basic_readonly",
            "playbook_file": "/opt/netaiops-webhook/playbooks/cisco_nxos_basic_readonly.yaml"
        },
        "execution_source": "manual",
        "auto_confirm_recommended": False,
        "policy_result": {
            "auto_confirm_allowed": True,
            "reasons": [],
            "policy_summary": "manual_confirmed",
            "checked_items": {
                "readonly_only": True,
                "command_count": 2
            }
        }
    }

    plan_file = PLAN_DIR / f"manual_{request_id}.plan.json"
    plan_file.parent.mkdir(parents=True, exist_ok=True)

    with open(plan_file, "w", encoding="utf-8") as f:
        json.dump(plan, f, ensure_ascii=False, indent=2)

    print(str(plan_file))


if __name__ == "__main__":
    main()
