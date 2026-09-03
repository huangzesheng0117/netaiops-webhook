from __future__ import annotations

import unittest
from unittest.mock import patch

from netaiops.v13.evidence_owner_builders import (
    EvidenceOwnerBuildError,
    build_device_material,
    build_metrics_request,
)


class OwnerBuilderTests(unittest.TestCase):
    def _plan(self):
        return {
            "request_id": "legacy-1",
            "source": "alertmanager",
            "family_result": {"family": "interface_status_or_flap"},
            "classification": {"family": "interface_status_or_flap"},
            "target_scope": {
                "device_ip": "10.0.0.1",
                "hostname": "sw01",
                "interface": "Gi1/0/1",
                "ifName": "Gi1/0/1",
                "vendor": "cisco",
            },
            "playbook": {
                "matched": True,
                "playbook_id": "interface_flap",
            },
            "execution_source": "playbook",
            "execution_candidates": [
                {
                    "order": 1,
                    "command": "show interfaces Gi1/0/1",
                    "capability": "show_interface_detail",
                    "readonly": True,
                }
            ],
            "playbook_runtime": {
                "prometheus_evidence_first": {
                    "enabled": True,
                    "evidence_profile": "interface_traffic",
                    "query_names": ["oper_status"],
                    "required_labels": ["device_ip", "if_name"],
                }
            },
        }

    def test_metrics_request_uses_template_identity_not_raw_promql(self):
        req = build_metrics_request(request_id="d3-builder-metrics", plan=self._plan())
        dumped = req.model_dump(mode="json")
        self.assertEqual(req.query_template_id, "prometheus:interface_traffic:oper_status")
        self.assertNotIn("promql", dumped)
        self.assertFalse(req.promql_generation_allowed)

    @patch("netaiops.v13.evidence_owner_builders.evaluate_plan_safety", return_value={"allowed": True})
    @patch("netaiops.v13.evidence_owner_builders.evaluate_candidate", return_value={"safe": True})
    @patch("netaiops.v13.evidence_owner_builders.command_is_readonly", return_value=True)
    def test_device_material_binds_existing_playbook_command(self, *_):
        material = build_device_material(request_id="d3-builder-device", plan=self._plan())
        dumped = material.request.model_dump(mode="json")
        self.assertEqual(material.playbook_id, "interface_flap")
        self.assertTrue(material.command.startswith("show "))
        self.assertNotIn("command", dumped)
        self.assertFalse(material.request.command_generation_allowed)

    def test_device_nonplaybook_rejected(self):
        plan = self._plan()
        plan["execution_source"] = "analysis"
        with self.assertRaises(EvidenceOwnerBuildError):
            build_device_material(request_id="d3-builder-bad", plan=plan)

    def test_unapproved_family_rejected(self):
        plan = self._plan()
        plan["family_result"]["family"] = "device_cpu_high"
        with self.assertRaises(EvidenceOwnerBuildError):
            build_metrics_request(request_id="d3-builder-family", plan=plan)

    def test_unknown_vendor_blocked_safe(self):
        plan = self._plan()
        plan["target_scope"]["vendor"] = "unknown"
        with self.assertRaises(EvidenceOwnerBuildError):
            build_metrics_request(request_id="d3-builder-vendor", plan=plan)

    def test_illegal_interface_blocked_safe(self):
        plan = self._plan()
        plan["target_scope"]["interface"] = "接口告警文本"
        plan["target_scope"]["ifName"] = ""
        with self.assertRaises(EvidenceOwnerBuildError):
            build_metrics_request(request_id="d3-builder-interface", plan=plan)

    def test_metrics_multi_interface_regex_is_allowed_when_each_interface_is_valid(self):
        plan = self._plan()
        plan["target_scope"]["interface"] = "Te1/0/1|Te2/0/1"
        plan["target_scope"]["ifName"] = "Te1/0/1|Te2/0/1"
        req = build_metrics_request(request_id="d3-builder-multi", plan=plan)
        self.assertIn("|", str(req.target.get("interface") or req.target.get("ifName")))


if __name__ == "__main__":
    unittest.main()
