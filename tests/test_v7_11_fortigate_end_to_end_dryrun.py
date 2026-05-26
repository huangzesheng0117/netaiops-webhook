import json
import unittest
from datetime import datetime, timezone

from netaiops.normalizers import normalize_alertmanager
from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


def build_payload(alertname, labels=None, annotations=None):
    labels = labels or {}
    annotations = annotations or {}

    base_labels = {
        "alertname": alertname,
        "severity": "critical",
        "vendor": "fortigate",
        "job": labels.get("job", "FW-FORTIGATE-E2E-DRYRUN"),
        "instance": labels.get("instance", "test-fortigate.example.local"),
        "ip": labels.get("ip", "10.255.255.30"),
    }
    base_labels.update(labels)

    base_annotations = {
        "summary": alertname,
        "description": annotations.get("description", f"{alertname} 端到端 dry-run 测试"),
    }
    base_annotations.update(annotations)

    return {
        "receiver": "netaiops-fortigate-e2e-dryrun",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": base_labels,
                "annotations": base_annotations,
                "startsAt": datetime.now(timezone.utc).isoformat(),
                "endsAt": "0001-01-01T00:00:00Z",
                "generatorURL": "http://prometheus.example.local/graph?g0.expr=fortigate_e2e_dryrun",
            }
        ],
        "commonLabels": {
            "alertname": alertname,
            "severity": "critical",
            "vendor": "fortigate",
        },
        "commonAnnotations": {
            "summary": alertname,
        },
        "externalURL": "http://alertmanager.example.local",
        "version": "4",
        "groupKey": f"fortigate-e2e:{alertname}",
    }


FORTIGATE_E2E_CASES = [
    {
        "alertname": "主备状态切换",
        "expected_playbook_id": "fortigate_ha_status_change",
        "expected_family": "fortigate_ha_status_change",
        "command_hint": "get sys ha status",
    },
    {
        "alertname": "同步状态",
        "expected_playbook_id": "fortigate_ha_sync_abnormal",
        "expected_family": "fortigate_ha_sync_abnormal",
        "command_hint": "diagnose sys ha checksum show",
    },
    {
        "alertname": "CPU平均利用率",
        "expected_playbook_id": "fortigate_cpu_high",
        "expected_family": "fortigate_cpu_high",
        "command_hint": "get system performance status",
    },
    {
        "alertname": "CPU单核利用率",
        "expected_playbook_id": "fortigate_cpu_high",
        "expected_family": "fortigate_cpu_high",
        "command_hint": "diagnose sys top",
    },
    {
        "alertname": "内存利用率",
        "expected_playbook_id": "fortigate_memory_high",
        "expected_family": "fortigate_memory_high",
        "command_hint": "diagnose hardware sysinfo memory",
    },
    {
        "alertname": "硬件传感器状态",
        "expected_playbook_id": "fortigate_hardware_sensor_abnormal",
        "expected_family": "fortigate_hardware_sensor_abnormal",
        "command_hint": "get hardware status",
    },
    {
        "alertname": "活动连接数",
        "expected_playbook_id": "fortigate_connection_capacity_high",
        "expected_family": "fortigate_connection_capacity_high",
        "command_hint": "diagnose sys session stat",
    },
    {
        "alertname": "新建连接数(TCP)",
        "expected_playbook_id": "fortigate_connection_capacity_high",
        "expected_family": "fortigate_connection_capacity_high",
        "command_hint": "diagnose sys session stat",
    },
    {
        "alertname": "活动连接数突增",
        "expected_playbook_id": "fortigate_connection_anomaly",
        "expected_family": "fortigate_connection_anomaly",
        "command_hint": "diagnose sys session stat",
    },
    {
        "alertname": "活动连接数突降",
        "expected_playbook_id": "fortigate_connection_anomaly",
        "expected_family": "fortigate_connection_anomaly",
        "command_hint": "diagnose sys session stat",
    },
    {
        "alertname": "新建连接数突增",
        "expected_playbook_id": "fortigate_connection_anomaly",
        "expected_family": "fortigate_connection_anomaly",
        "command_hint": "diagnose sys session stat",
    },
    {
        "alertname": "新建连接数突降",
        "expected_playbook_id": "fortigate_connection_anomaly",
        "expected_family": "fortigate_connection_anomaly",
        "command_hint": "diagnose sys session stat",
    },
]


class TestV711FortigateEndToEndDryrun(unittest.TestCase):
    def test_alertmanager_payload_to_playbook_and_skill_for_each_fortigate_alert(self):
        summary = []

        for case in FORTIGATE_E2E_CASES:
            with self.subTest(alertname=case["alertname"]):
                payload = build_payload(
                    case["alertname"],
                    labels={
                        "job": "FW-FORTIGATE-400",
                        "vendor": "fortigate",
                    },
                )

                events = normalize_alertmanager(payload)
                self.assertEqual(len(events), 1)

                event = events[0]
                self.assertEqual(event.get("source"), "alertmanager")
                self.assertEqual(event.get("status"), "firing")
                self.assertEqual(event.get("vendor"), "fortigate")
                self.assertEqual(event.get("alarm_type"), case["alertname"])

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
        print("===== FORTIGATE_E2E_DRYRUN_SUMMARY =====")
        print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    unittest.main()
