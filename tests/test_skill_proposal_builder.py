import json
import tempfile
import unittest
from pathlib import Path

from netaiops.relation_engine import build_relation_graph
from netaiops.skill_proposal_builder import (
    build_skill_proposals,
    query_skill_proposals,
    validate_proposal_safety,
)


class TestSkillProposalBuilder(unittest.TestCase):
    def _record(self, rid, util=81.18):
        return {
            "schema_version": "v7.1.incident_memory.v1",
            "memory_type": "incident_memory",
            "request_id": rid,
            "event_time": "2026-05-19T11:50:07+00:00",
            "family": "interface_or_link_utilization_high",
            "hostname": "WG404-H0304-C95-INT-ACC",
            "device_ip_hash": "hash_device_a",
            "interfaces": [
                "TenGigabitEthernet1/0/1",
                "TenGigabitEthernet2/0/1",
            ],
            "circuit_alias": "WG88互联网线路_电信_100M",
            "direction": "out",
            "alarm_type": "WG88互联网线路_电信_100M_利用率-出向",
            "alarm_bandwidth_mbps": 100.0,
            "evidence_facts": {
                "business_bandwidth_text": "100M",
                "business_bandwidth_bps": 100000000,
                "multi_interfaces": [
                    "TenGigabitEthernet1/0/1",
                    "TenGigabitEthernet2/0/1",
                ],
                "aggregate_output_utilization_percent_business_estimated": util,
                "crc": 0,
                "parsed_facts_enabled": True,
                "parsed_fact_sources": ["cisco_show_interfaces"],
            },
            "parser_summary": {
                "parsed_facts_enabled": True,
                "parsed_fact_sources": ["cisco_show_interfaces"],
                "parse_status_counts": {"parsed": 5},
            },
            "command_summary": {
                "execution_status": "completed",
                "total_commands": 5,
                "completed_commands": 5,
                "failed_commands": 0,
                "partial_commands": 0,
                "hard_error_count": 0,
            },
            "judgement": "多接口只读取证完成；已按这些接口进行汇总分析。",
        }

    def test_build_skill_proposal_from_recurrent_cluster(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            mem_dir = base / "data" / "memory"
            skill_dir = base / "skills" / "interface_utilization_high"
            mem_dir.mkdir(parents=True)
            skill_dir.mkdir(parents=True)

            (skill_dir / "SKILL.md").write_text(
                "family: interface_or_link_utilization_high\ninterface utilization high skill",
                encoding="utf-8",
            )

            records = [
                self._record("20260519_150115_014287_1f8f0606", 81.18),
                self._record("20260519_145615_001275_3c9d8dbf", 82.10),
                self._record("20260519_145114_980493_fa3d7719", 79.80),
            ]

            with (mem_dir / "incidents.jsonl").open("w", encoding="utf-8") as f:
                for item in records:
                    f.write(json.dumps(item, ensure_ascii=False) + "\n")

            graph = build_relation_graph(base_dir=base, write=True)
            self.assertGreaterEqual(graph["cluster_count"], 1)

            result = build_skill_proposals(base_dir=base, write=True)
            self.assertTrue(result["ok"])
            self.assertGreaterEqual(result["proposal_count"], 1)

            proposal = result["proposals"][0]
            self.assertEqual(proposal["proposal_status"], "draft_review_required")
            self.assertTrue(proposal["manual_review_required"])
            self.assertFalse(proposal["auto_merge_enabled"])
            self.assertEqual(proposal["proposal_type"], "enhance_existing_skill")
            self.assertGreaterEqual(proposal["reuse_value"]["total_score"], 65)
            self.assertTrue(validate_proposal_safety(proposal)["ok"])

            proposal_text = json.dumps(proposal, ensure_ascii=False)
            self.assertNotIn("10.191.96.43", proposal_text)

            rows = query_skill_proposals(base_dir=base, min_score=60, limit=10)
            self.assertGreaterEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main()
