import json
import unittest
from datetime import datetime, timezone

from netaiops.normalizers import normalize_alertmanager
from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


HILLSTONE_E2E_CASES = [
    {
        "alertname": "主备状态变化",
        "expected_playbook_id": "hillstone_ha_status_change",
        "expected_family": "hillstone_ha_status_change",
        "command_hint": "show ha cluster",
    },
    {
        "alertname": "CPU利用率",
        "expected_playbook_id": "hillstone_cpu_high",
        "expected_family": "hillstone_cpu_high",
        "command_hint": "show system resource",
    },
    {
        "alertname": "内存利用率",
        "expected_playbook_id": "hillstone_memory_high",
        "expected_family": "hillstone_memory_high",
        "command_hint": "show system resource",
    },
    {
        "alertname": "活动连接数",
        "expected_playbook_id": "hillstone_connection_capacity_high",
        "expected_family": "hillstone_connection_capacity_high",
        "command_hint": "show session generic",
    },
    {
        "alertname": "新建连接数(TCP)",
        "expected_playbook_id": "hillstone_connection_capacity_high",
        "expected_family": "hillstone_connection_capacity_high",
        "command_hint": "show session generic",
    },
]


def build_payload(alertname):
    labels = {
        "alertname": alertname,
        "severity": "critical",
        "vendor": "hillstone",
        "job": "FW-HILLSTONE-V8-INT",
        "instance": "test-hillstone.example.local",
        "ip": "10.255.255.50",
    }

    return {
        "receiver": "netaiops-hillstone-e2e-dryrun",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": labels,
                "annotations": {
                    "summary": alertname,
                    "description": f"{alertname} net-hillstone 端到端 dry-run 测试",
                },
                "startsAt": datetime.now(timezone.utc).isoformat(),
                "endsAt": "0001-01-01T00:00:00Z",
                "generatorURL": "http://prometheus.example.local/graph?g0.expr=hillstone_e2e_dryrun",
            }
        ],
        "commonLabels": {
            "alertname": alertname,
            "severity": "critical",
            "vendor": "hillstone",
        },
        "commonAnnotations": {
            "summary": alertname,
        },
        "externalURL": "http://alertmanager.example.local",
        "version": "4",
        "groupKey": f"hillstone-e2e:{alertname}",
    }


class TestV711HillstoneEndToEndDryrun(unittest.TestCase):
    def test_alertmanager_payload_to_playbook_and_skill_for_each_hillstone_alert(self):
        summary = []

        for case in HILLSTONE_E2E_CASES:
            with self.subTest(alertname=case["alertname"]):
                payload = build_payload(case["alertname"])
                events = normalize_alertmanager(payload)
                self.assertEqual(len(events), 1)

                event = events[0]
                self.assertEqual(event.get("source"), "alertmanager")
                self.assertEqual(event.get("status"), "firing")
                self.assertEqual(event.get("vendor"), "hillstone")
                self.assertEqual(event.get("alarm_type"), case["alertname"])

                event["platform"] = "stoneos"

                classification = classify_event(event)
                self.assertIsInstance(classification, dict)

                playbook = find_best_playbook(event, classification)
                self.assertIsNotNone(playbook)
                self.assertEqual(playbook.get("playbook_id"), case["expected_playbook_id"])

                candidates = build_execution_candidates_from_playbook(playbook, event)
                self.assertTrue(candidates)
                self.assertTrue(all(x.get("readonly") for x in candidates))

                commands = [x.get("command", "") for x in candidates]
                commands_joined = " ".join(commands).lower()
                self.assertIn(case["command_hint"].lower(), commands_joined)

                skill_ctx = build_runtime_context_for_family(
                    case["expected_family"],
                    base_dir="/opt/netaiops-webhook",
                    levels=["metadata", "instructions", "commands", "evidence", "schema"],
                )
                self.assertTrue(skill_ctx.get("matched"))
                self.assertEqual(skill_ctx.get("family"), case["expected_family"])
                self.assertIn("commands", skill_ctx)
                self.assertIn("evidence", skill_ctx)
                self.assertIn("schema", skill_ctx)

                summary.append(
                    {
                        "alertname": case["alertname"],
                        "family": case["expected_family"],
                        "playbook_id": playbook.get("playbook_id"),
                        "command_count": len(commands),
                        "first_command": commands[0] if commands else "",
                        "skill_matched": bool(skill_ctx.get("matched")),
                    }
                )

        print()
        print("===== HILLSTONE_E2E_DRYRUN_SUMMARY =====")
        print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    unittest.main()
