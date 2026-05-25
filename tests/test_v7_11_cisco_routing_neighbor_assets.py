import unittest

from netaiops.classifier import classify_event
from netaiops.playbook_loader import find_best_playbook, build_execution_candidates_from_playbook
from netaiops.skill_runtime import build_runtime_context_for_family


class TestV711CiscoRoutingNeighborAssets(unittest.TestCase):
    def test_cisco_routing_neighbor_playbooks_match_net_cisco_alertnames(self):
        cases = [
            ("BGP邻居状态", "cisco_bgp_neighbor_down", "show bgp"),
            ("OSPF邻居状态", "cisco_ospf_neighbor_down", "show ip ospf"),
            ("BFD邻居状态", "cisco_bfd_neighbor_down", "show bfd"),
        ]

        for alertname, expected_playbook_id, command_hint in cases:
            with self.subTest(alertname=alertname):
                event = {
                    "source": "alertmanager",
                    "vendor": "cisco",
                    "platform": "nxos",
                    "device_ip": "10.0.0.1",
                    "hostname": "test-device",
                    "alarm_type": alertname,
                    "raw_text": alertname,
                    "labels": {"severity": "critical"},
                    "annotations": {"description": alertname},
                }
                classification = classify_event(event)
                playbook = find_best_playbook(event, classification)
                self.assertIsNotNone(playbook)
                self.assertEqual(playbook.get("playbook_id"), expected_playbook_id)

                candidates = build_execution_candidates_from_playbook(playbook, event)
                self.assertTrue(candidates)
                self.assertTrue(all(x.get("readonly") for x in candidates))
                commands = " ".join(x.get("command", "") for x in candidates).lower()
                self.assertIn(command_hint.lower(), commands)

    def test_routing_neighbor_skill_is_loadable_by_family(self):
        ctx = build_runtime_context_for_family(
            "routing_neighbor_down",
            base_dir="/opt/netaiops-webhook",
            levels=["metadata", "instructions", "commands", "evidence", "schema"],
        )
        self.assertTrue(ctx.get("matched"))
        self.assertEqual(ctx.get("family"), "routing_neighbor_down")
        self.assertIn("commands", ctx)
        self.assertIn("evidence", ctx)
        self.assertIn("schema", ctx)


if __name__ == "__main__":
    unittest.main()
