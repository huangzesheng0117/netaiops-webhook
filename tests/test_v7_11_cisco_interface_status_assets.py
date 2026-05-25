import unittest

from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


class TestV711CiscoInterfaceStatusAssets(unittest.TestCase):
    def test_cisco_interface_status_playbook_matches_net_cisco_alertnames(self):
        cases = [
            "非ACI端口状态",
            "Leaf-Spine互联端口状态",
            "BorderLeaf端口状态",
            "Spine端口状态",
        ]

        for alertname in cases:
            with self.subTest(alertname=alertname):
                event = {
                    "source": "alertmanager",
                    "vendor": "cisco",
                    "platform": "nxos",
                    "device_ip": "10.0.0.1",
                    "hostname": "test-device",
                    "alarm_type": alertname,
                    "object_name": "Ethernet1/1",
                    "interface": "Ethernet1/1",
                    "raw_text": alertname + " Ethernet1/1",
                    "labels": {
                        "severity": "critical",
                        "interface": "Ethernet1/1",
                    },
                    "annotations": {"description": alertname},
                }
                classification = classify_event(event)
                playbook = find_best_playbook(event, classification)
                self.assertIsNotNone(playbook)
                self.assertEqual(playbook.get("playbook_id"), "cisco_interface_down_or_oper_status")

                candidates = build_execution_candidates_from_playbook(playbook, event)
                self.assertTrue(candidates)
                self.assertTrue(all(x.get("readonly") for x in candidates))
                commands = " ".join(x.get("command", "") for x in candidates).lower()
                self.assertIn("show interface ethernet1/1", commands)
                self.assertIn("counters errors", commands)

    def test_interface_status_skill_is_loadable_by_family(self):
        ctx = build_runtime_context_for_family(
            "interface_down_or_oper_status",
            base_dir="/opt/netaiops-webhook",
            levels=["metadata", "instructions", "commands", "evidence", "schema"],
        )
        self.assertTrue(ctx.get("matched"))
        self.assertEqual(ctx.get("family"), "interface_down_or_oper_status")
        self.assertIn("commands", ctx)
        self.assertIn("evidence", ctx)
        self.assertIn("schema", ctx)


if __name__ == "__main__":
    unittest.main()
