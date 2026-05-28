import unittest

from netaiops.plan_builder import build_plan_from_analysis_data
from agent_runner.reachability_precheck import should_apply_reachability_precheck


class TestV712PipelineRuntimeFix(unittest.TestCase):
    def _analysis(self, vendor, platform, alertname, hostname, device_ip, interface=""):
        event = {
            "source": "alertmanager",
            "vendor": vendor,
            "platform": platform,
            "hostname": hostname,
            "device_ip": device_ip,
            "alarm_type": alertname,
            "raw_text": f"{alertname} {hostname} {interface}",
            "labels": {
                "alertname": alertname,
                "vendor": vendor,
                "hostname": hostname,
                "device_ip": device_ip,
                "interface": interface,
                "ifName": interface,
                "severity": "critical",
            },
            "annotations": {
                "description": alertname,
            },
        }
        if interface:
            event["interface"] = interface
            event["object_name"] = interface

        return {
            "request_id": "unit_v712_runtime_fix",
            "source": "alertmanager",
            "analysis_status": "success",
            "result": {
                "summary": "unit test",
                "recommended_next_step": "readonly diagnosis",
                "confidence": "medium",
            },
            "event": event,
        }

    def test_up_cisco_prefers_explicit_playbook_and_allows_auto_confirm(self):
        plan = build_plan_from_analysis_data(
            self._analysis("cisco", "nxos", "up", "test-cisco", "10.1.1.1")
        )
        self.assertEqual(plan.get("execution_source"), "playbook")
        self.assertEqual(plan.get("playbook", {}).get("playbook_id"), "cisco_device_reachability_down")
        self.assertTrue(plan.get("policy_result", {}).get("auto_confirm_allowed"))
        self.assertEqual(plan.get("policy_result", {}).get("policy_summary"), "allowed")

    def test_up_hillstone_policy_is_supported(self):
        plan = build_plan_from_analysis_data(
            self._analysis("hillstone", "stoneos", "up", "test-hillstone", "10.1.1.2")
        )
        self.assertEqual(plan.get("execution_source"), "playbook")
        self.assertEqual(plan.get("playbook", {}).get("playbook_id"), "hillstone_device_reachability_down")
        self.assertTrue(plan.get("policy_result", {}).get("auto_confirm_allowed"))
        self.assertEqual(plan.get("policy_result", {}).get("checked_items", {}).get("vendor"), "hillstone")

    def test_dci_traffic_spike_prefers_explicit_playbook(self):
        plan = build_plan_from_analysis_data(
            self._analysis(
                "cisco",
                "nxos",
                "DCI线路流量突增",
                "SH16-G03-DCI-BN-ACC-SW01",
                "10.187.251.107",
                "Ethernet1/1",
            )
        )
        self.assertEqual(plan.get("execution_source"), "playbook")
        self.assertEqual(plan.get("playbook", {}).get("playbook_id"), "cisco_interface_traffic_anomaly")
        self.assertTrue(plan.get("policy_result", {}).get("auto_confirm_allowed"))

    def test_reachability_precheck_applies_to_vendor_up_playbooks(self):
        for playbook_id in [
            "cisco_device_reachability_down",
            "fortigate_device_reachability_down",
            "f5_device_reachability_down",
            "hillstone_device_reachability_down",
        ]:
            with self.subTest(playbook_id=playbook_id):
                self.assertTrue(should_apply_reachability_precheck({"playbook_id": playbook_id}))

        self.assertFalse(should_apply_reachability_precheck({"playbook_id": "cisco_interface_traffic_anomaly"}))


if __name__ == "__main__":
    unittest.main()
