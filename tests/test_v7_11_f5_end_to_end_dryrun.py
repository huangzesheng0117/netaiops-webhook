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
        "vendor": "f5",
        "job": labels.get("job", "F5-E2E-DRYRUN"),
        "instance": labels.get("instance", "test-f5.example.local"),
        "ip": labels.get("ip", "10.255.255.10"),
    }
    base_labels.update(labels)

    base_annotations = {
        "summary": alertname,
        "description": annotations.get("description", f"{alertname} 端到端 dry-run 测试"),
    }
    base_annotations.update(annotations)

    return {
        "receiver": "netaiops-e2e-dryrun",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": base_labels,
                "annotations": base_annotations,
                "startsAt": datetime.now(timezone.utc).isoformat(),
                "endsAt": "0001-01-01T00:00:00Z",
                "generatorURL": "http://prometheus.example.local/graph?g0.expr=e2e_dryrun",
            }
        ],
        "commonLabels": {
            "alertname": alertname,
            "severity": "critical",
            "vendor": "f5",
        },
        "commonAnnotations": {
            "summary": alertname,
        },
        "externalURL": "http://alertmanager.example.local",
        "version": "4",
        "groupKey": f"e2e:{alertname}",
    }


F5_E2E_CASES = [
    {
        "alertname": "主备状态变化",
        "expected_playbook_id": "f5_ha_status_change",
        "expected_family": "f5_ha_status_change",
        "command_hint": "tmsh show sys failover",
        "labels": {"job": "LTM-F5"},
    },
    {
        "alertname": "全局CPU利用率",
        "expected_playbook_id": "f5_cpu_high",
        "expected_family": "f5_cpu_high",
        "command_hint": "tmsh show sys cpu",
        "labels": {"job": "LTM-F5"},
    },
    {
        "alertname": "全局内存利用率",
        "expected_playbook_id": "f5_memory_high",
        "expected_family": "f5_memory_high",
        "command_hint": "tmsh show sys memory",
        "labels": {"job": "LTM-F5"},
    },
    {
        "alertname": "磁盘利用率",
        "expected_playbook_id": "f5_disk_high",
        "expected_family": "f5_disk_high",
        "command_hint": "tmsh show sys disk",
        "labels": {"job": "LTM-F5"},
    },
    {
        "alertname": "机框风扇状态",
        "expected_playbook_id": "f5_hardware_component_abnormal",
        "expected_family": "f5_hardware_component_abnormal",
        "command_hint": "tmsh show sys hardware",
        "labels": {"job": "LTM-F5"},
    },
    {
        "alertname": "CPU温度",
        "expected_playbook_id": "f5_temperature_high",
        "expected_family": "f5_temperature_high",
        "command_hint": "tmsh show sys hardware",
        "labels": {"job": "LTM-F5"},
    },
    {
        "alertname": "活动连接数",
        "expected_playbook_id": "f5_connection_capacity_high",
        "expected_family": "f5_connection_capacity_high",
        "command_hint": "tmsh show sys performance connections",
        "labels": {"job": "LTM-F5"},
    },
    {
        "alertname": "新建HTTP请求数",
        "expected_playbook_id": "f5_http_request_rate_high",
        "expected_family": "f5_http_request_rate_high",
        "command_hint": "tmsh show ltm virtual",
        "labels": {"job": "LTM-F5"},
    },
    {
        "alertname": "新建连接数(SSL)",
        "expected_playbook_id": "f5_ssl_connection_rate_high",
        "expected_family": "f5_ssl_connection_rate_high",
        "command_hint": "tmsh show ltm virtual",
        "labels": {"job": "LTM-F5"},
    },
    {
        "alertname": "吞吐量-入向",
        "expected_playbook_id": "f5_throughput_high",
        "expected_family": "f5_throughput_high",
        "command_hint": "tmsh show sys performance throughput",
        "labels": {"job": "LTM-F5"},
    },
    {
        "alertname": "收光功率",
        "expected_playbook_id": "f5_optical_power_abnormal",
        "expected_family": "f5_optical_power_abnormal",
        "command_hint": "tmsh show net interface",
        "labels": {
            "job": "LTM-F5",
            "sysSwitchDdmStatName": "1.1",
            "name": "1.1",
        },
    },
    {
        "alertname": "f5端口状态",
        "expected_playbook_id": "f5_interface_status_abnormal",
        "expected_family": "f5_interface_status_abnormal",
        "command_hint": "tmsh show net interface",
        "labels": {
            "job": "LTM-F5",
            "ifName": "1.1",
            "name": "1.1",
        },
    },
    {
        "alertname": "DNS请求率",
        "expected_playbook_id": "f5_dns_request_rate_high",
        "expected_family": "f5_dns_request_rate_high",
        "command_hint": "tmsh show gtm wideip",
        "labels": {"job": "DNS-F5"},
    },
    {
        "alertname": "DNS解析率",
        "expected_playbook_id": "f5_dns_resolution_quality_low",
        "expected_family": "f5_dns_resolution_quality_low",
        "command_hint": "tmsh show gtm wideip",
        "labels": {"job": "DNS-F5"},
    },
    {
        "alertname": "F5活跃连接数突增",
        "expected_playbook_id": "f5_connection_anomaly",
        "expected_family": "f5_connection_anomaly",
        "command_hint": "tmsh show sys performance connections",
        "labels": {"job": "LTM-F5"},
    },
    {
        "alertname": "DNS每秒请求率突增",
        "expected_playbook_id": "f5_dns_rate_anomaly",
        "expected_family": "f5_dns_rate_anomaly",
        "command_hint": "tmsh show gtm wideip",
        "labels": {"job": "DNS-F5"},
    },
]


class TestV711F5EndToEndDryrun(unittest.TestCase):
    def test_alertmanager_payload_to_playbook_and_skill_for_each_f5_family(self):
        summary = []

        for case in F5_E2E_CASES:
            with self.subTest(alertname=case["alertname"]):
                payload = build_payload(
                    case["alertname"],
                    labels=case.get("labels"),
                    annotations=case.get("annotations"),
                )

                events = normalize_alertmanager(payload)
                self.assertEqual(len(events), 1)

                event = events[0]
                self.assertEqual(event.get("source"), "alertmanager")
                self.assertEqual(event.get("status"), "firing")
                self.assertEqual(event.get("vendor"), "f5")
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
        print("===== F5_E2E_DRYRUN_SUMMARY =====")
        print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    unittest.main()
