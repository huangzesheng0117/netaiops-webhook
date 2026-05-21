import json
import tempfile
import unittest
from pathlib import Path

from netaiops.memory_store import (
    build_memory_for_request_id,
    query_incident_memories,
    validate_no_raw_sensitive_values,
)


class TestIncidentMemoryStore(unittest.TestCase):
    def test_build_incident_memory_masks_ip_and_extracts_multi_interface(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            rid = "20260519_150115_014287_1f8f0606"

            (base / "data" / "reviews").mkdir(parents=True)

            review = {
                "request_id": rid,
                "family": "interface_or_link_utilization_high",
                "generated_at": "2026-05-19T11:50:07+00:00",
                "target_scope": {
                    "hostname": "WG404-H0304-C95-INT-ACC",
                    "device_ip": "10.189.250.8",
                    "alarm_type": "WG88互联网线路_电信_100M_利用率-出向",
                },
                "stats": {
                    "execution_status": "completed",
                    "total_commands": 5,
                    "completed_commands": 5,
                    "failed_commands": 0,
                    "partial_commands": 0,
                    "hard_error_count": 0,
                },
                "evidence_summary": {
                    "family": "interface_or_link_utilization_high",
                    "facts": {
                        "alarm_direction": "out",
                        "business_bandwidth_bps": 100000000,
                        "business_bandwidth_text": "100M",
                        "multi_interfaces": [
                            "TenGigabitEthernet1/0/1",
                            "TenGigabitEthernet2/0/1",
                        ],
                        "aggregate_output_utilization_percent_business_estimated": 81.18,
                        "crc": 0,
                        "parsed_facts_enabled": True,
                        "parsed_fact_sources": ["cisco_show_interfaces"],
                    },
                    "conclusion": "多接口只读取证完成；已按这些接口进行汇总分析。",
                },
            }

            with (base / "data" / "reviews" / f"alertmanager_{rid}.review.json").open("w", encoding="utf-8") as f:
                json.dump(review, f, ensure_ascii=False)

            record = build_memory_for_request_id(rid, base_dir=base, write=True)
            text = json.dumps(record, ensure_ascii=False)

            self.assertEqual(record["request_id"], rid)
            self.assertEqual(record["hostname"], "WG404-H0304-C95-INT-ACC")
            self.assertTrue(record["device_ip_hash"].startswith("hash_"))
            self.assertNotIn("10.189.250.8", text)
            self.assertEqual(len(record["interfaces"]), 2)
            self.assertEqual(record["direction"], "out")
            self.assertEqual(record["alarm_bandwidth_mbps"], 100.0)
            self.assertTrue(validate_no_raw_sensitive_values(record)["ok"])

            rows = query_incident_memories(
                base_dir=base,
                family="interface_or_link_utilization_high",
                interface="Te1/0/1",
                limit=10,
            )

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["request_id"], rid)


if __name__ == "__main__":
    unittest.main()
