import json
import tempfile
import unittest
from pathlib import Path

from netaiops.relation_engine import (
    build_pair_relation,
    build_relation_graph,
    find_relations_for_request_id,
    query_relation_graph,
)


class TestRelationEngine(unittest.TestCase):
    def _record(self, rid, host, ifaces, circuit="WG88互联网线路_电信_100M", direction="out", util=81.18):
        return {
            "schema_version": "v7.1.incident_memory.v1",
            "memory_type": "incident_memory",
            "request_id": rid,
            "event_time": "2026-05-19T11:50:07+00:00",
            "family": "interface_or_link_utilization_high",
            "hostname": host,
            "device_ip_hash": "hash_device_a",
            "interfaces": ifaces,
            "circuit_alias": circuit,
            "direction": direction,
            "alarm_type": "WG88互联网线路_电信_100M_利用率-出向",
            "alarm_bandwidth_mbps": 100.0,
            "evidence_facts": {
                "aggregate_output_utilization_percent_business_estimated": util,
            },
            "command_summary": {
                "execution_status": "completed",
                "total_commands": 5,
                "completed_commands": 5,
                "failed_commands": 0,
            },
        }

    def test_pair_relation_detects_strong_recurrence(self):
        a = self._record("20260519_150115_014287_1f8f0606", "WG404-H0304-C95-INT-ACC", ["Te1/0/1", "Te2/0/1"])
        b = self._record("20260519_145615_001275_3c9d8dbf", "WG404-H0304-C95-INT-ACC", ["TenGigabitEthernet1/0/1", "TenGigabitEthernet2/0/1"])

        rel = build_pair_relation(a, b)

        self.assertIsNotNone(rel)
        self.assertGreaterEqual(rel["score"], 75)
        self.assertEqual(rel["relation_type"], "strong_recurrence")
        self.assertIn("same_family", rel["reasons"])
        self.assertIn("same_interface", rel["reasons"])
        self.assertIn("same_circuit_alias", rel["reasons"])

    def test_build_and_query_relation_graph(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            memory_dir = base / "data" / "memory"
            memory_dir.mkdir(parents=True)

            records = [
                self._record("20260519_150115_014287_1f8f0606", "WG404-H0304-C95-INT-ACC", ["Te1/0/1", "Te2/0/1"]),
                self._record("20260519_145615_001275_3c9d8dbf", "WG404-H0304-C95-INT-ACC", ["TenGigabitEthernet1/0/1", "TenGigabitEthernet2/0/1"]),
                self._record("20260518_143814_965182_c4678b99", "OTHER-HOST", ["Gi1/0/1"], circuit="", util=20.0),
            ]

            with (memory_dir / "incidents.jsonl").open("w", encoding="utf-8") as f:
                for item in records:
                    f.write(json.dumps(item, ensure_ascii=False) + "\n")

            graph = build_relation_graph(base_dir=base, write=True)

            self.assertEqual(graph["stage"], "v7.2_relation_engine")
            self.assertGreaterEqual(graph["relation_count"], 1)
            self.assertGreaterEqual(graph["cluster_count"], 1)

            result = query_relation_graph(
                base_dir=base,
                interface="Te1/0/1",
                min_score=60,
                limit=10,
            )

            self.assertGreaterEqual(result["relation_count"], 1)

            detail = find_relations_for_request_id(
                "20260519_150115_014287_1f8f0606",
                base_dir=base,
            )

            self.assertGreaterEqual(detail["relation_count"], 1)
            self.assertGreaterEqual(detail["cluster_count"], 1)


if __name__ == "__main__":
    unittest.main()
