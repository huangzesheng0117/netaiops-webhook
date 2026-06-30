import json
import tempfile
import unittest
from pathlib import Path

from netaiops.evidence_hub.list_api import (
    get_evidence_list,
    iter_evidence_request_summaries,
    list_api_route_manifest,
)


class TestEvidenceHubListApi(unittest.TestCase):
    def _write_json(self, path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def _make_detail(
        self,
        base: Path,
        rid: str,
        *,
        family: str,
        hostname: str,
        device_ip: str,
        object_name: str,
        generated_at: str,
    ) -> None:
        detail_dir = base / "data" / "evidence_hub" / "requests" / rid
        summary_data = {
            "request_id": rid,
            "title": f"NetAIOps告警分析 - {family}",
            "device": {"hostname": hostname, "device_ip": device_ip},
            "object": object_name,
            "family": family,
            "judgement": f"{hostname} current judgement",
            "recommendations": ["先确认业务影响", "再查看详情页"],
            "evidence_status": {"metrics": "found", "device": "found", "review": "found"},
            "command_stats": {"total_commands": 3, "failed_commands": 0},
            "detail_url": f"http://example/evidence-ui/{rid}",
        }
        self._write_json(detail_dir / "summary.json", {
            "schema_version": "v10.evidence_hub.detail.v1",
            "request_id": rid,
            "generated_at": generated_at,
            "summary": summary_data,
            "missing_sections": [],
            "read_error_sections": [],
        })
        self._write_json(detail_dir / "meta.json", {
            "section": "meta",
            "schema_version": "v10.evidence_hub.detail.v1",
            "status": "generated",
            "captured_at": generated_at,
            "data": {
                "request_id": rid,
                "family": family,
                "hostname": hostname,
                "device_ip": device_ip,
                "object_name": object_name,
                "detail_url": f"http://example/evidence-ui/{rid}",
            },
        })

    def test_list_latest_requests(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            self._make_detail(
                base,
                "20260630_130000_000001_a",
                family="interface_down",
                hostname="SW-A",
                device_ip="10.0.0.1",
                object_name="Gi1/0/1",
                generated_at="2026-06-30T13:00:00+00:00",
            )
            self._make_detail(
                base,
                "20260630_140000_000001_b",
                family="hardware_fault",
                hostname="SW-B",
                device_ip="10.0.0.2",
                object_name="Fan1",
                generated_at="2026-06-30T14:00:00+00:00",
            )
            result = get_evidence_list(base_dir=base, limit=10)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["total"], 2)
            self.assertEqual(result["count"], 2)
            self.assertEqual(result["requests"][0]["request_id"], "20260630_140000_000001_b")
            self.assertEqual(result["requests"][0]["hostname"], "SW-B")

    def test_filter_by_device_ip_family_hostname_and_q(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            self._make_detail(
                base,
                "rid_a",
                family="interface_down",
                hostname="SH16-G03-DCI-BN-SW01",
                device_ip="10.187.251.101",
                object_name="Te1/0/1",
                generated_at="2026-06-30T13:00:00+00:00",
            )
            self._make_detail(
                base,
                "rid_b",
                family="hardware_fault",
                hostname="SH8-G03-DCI-BN-SW02",
                device_ip="10.192.251.102",
                object_name="Fan1",
                generated_at="2026-06-30T14:00:00+00:00",
            )
            self.assertEqual(get_evidence_list(base_dir=base, device_ip="10.187.251.101")["total"], 1)
            self.assertEqual(get_evidence_list(base_dir=base, family="hardware")["requests"][0]["request_id"], "rid_b")
            self.assertEqual(get_evidence_list(base_dir=base, hostname="SH16-G03")["requests"][0]["request_id"], "rid_a")
            self.assertEqual(get_evidence_list(base_dir=base, q="Te1/0/1")["requests"][0]["request_id"], "rid_a")

    def test_limit_offset_and_limit_cap(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            for i in range(3):
                self._make_detail(
                    base,
                    f"rid_{i}",
                    family="interface_down",
                    hostname=f"SW-{i}",
                    device_ip=f"10.0.0.{i}",
                    object_name=f"Gi1/0/{i}",
                    generated_at=f"2026-06-30T1{i}:00:00+00:00",
                )
            result = get_evidence_list(base_dir=base, limit=1, offset=1)
            self.assertEqual(result["count"], 1)
            self.assertEqual(result["limit"], 1)
            self.assertEqual(result["offset"], 1)
            self.assertTrue(result["has_more"])
            capped = get_evidence_list(base_dir=base, limit=9999)
            self.assertEqual(capped["limit"], 500)

    def test_invalid_limit_and_offset(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            with self.assertRaises(ValueError):
                get_evidence_list(base_dir=base, limit=0)
            with self.assertRaises(ValueError):
                get_evidence_list(base_dir=base, offset=-1)

    def test_missing_root_returns_empty_ok(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            result = get_evidence_list(base_dir=base, limit=5)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["total"], 0)
            self.assertEqual(result["requests"], [])

    def test_manifest_contains_list_route(self):
        manifest = list_api_route_manifest()
        self.assertIn("GET /evidence", manifest["routes"])
        self.assertEqual(manifest["batch"], "v10_batch6")

    def test_iter_evidence_request_summaries(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            self._make_detail(
                base,
                "rid_iter",
                family="interface_down",
                hostname="SW-ITER",
                device_ip="10.0.0.9",
                object_name="Gi1/0/9",
                generated_at="2026-06-30T13:00:00+00:00",
            )
            items = list(iter_evidence_request_summaries(base_dir=base))
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]["request_id"], "rid_iter")


if __name__ == "__main__":
    unittest.main()
