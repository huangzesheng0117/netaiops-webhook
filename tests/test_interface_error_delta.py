import json
import tempfile
import unittest
from pathlib import Path

from netaiops.interface_error_delta import (
    compare_snapshots,
    parse_counter_snapshot,
    run_delta_check,
)


BASELINE = """
port-channel45 is up
  admin state is up
  14805 input errors, 14805 CRC, 0 frame, 0 overrun, 0 ignored
  0 output errors, 0 collisions
"""

LATEST = """
Port          Align-Err    FCS-Err   Xmit-Err    Rcv-Err  UnderSize OutDiscards
Po45                  0      14820          0      14820          0           0
"""


class TestInterfaceErrorDelta(unittest.TestCase):
    def test_parse_and_compare_counters(self):
        b = parse_counter_snapshot(
            command="show interface port-channel45",
            output=BASELINE,
            interface="port-channel45",
        )
        l = parse_counter_snapshot(
            command="show interface port-channel45 counters errors",
            output=LATEST,
            interface="port-channel45",
        )

        self.assertTrue(b["matched"])
        self.assertTrue(l["matched"])
        self.assertEqual(b["input_errors"], 14805)
        self.assertEqual(l["input_errors"], 14820)

        cmp = compare_snapshots(b, l)
        self.assertEqual(cmp["status"], "still_increasing")
        self.assertEqual(cmp["deltas"]["input_errors"], 15)
        self.assertEqual(cmp["deltas"]["crc"], 15)

    def test_run_delta_check_with_latest_override(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            rid = "20260518_165700_000000_test0001"
            exec_dir = base / "data" / "execution"
            exec_dir.mkdir(parents=True)

            execution = {
                "request_id": rid,
                "family_result": {
                    "family": "interface_packet_loss_or_discards_high",
                    "target_scope": {
                        "hostname": "SH8-M05-ACI-1130",
                        "interface": "port-channel45",
                    },
                },
                "target_scope": {
                    "hostname": "SH8-M05-ACI-1130",
                    "interface": "port-channel45",
                },
                "command_results": [
                    {
                        "capability": "show_interface_detail",
                        "command": "show interface port-channel45",
                        "dispatch_status": "completed",
                        "output": BASELINE,
                    }
                ],
            }

            path = exec_dir / f"alertmanager_{rid}.execution.json"
            path.write_text(json.dumps(execution, ensure_ascii=False), encoding="utf-8")

            result = run_delta_check(
                request_id=rid,
                base_dir=base,
                delay_seconds=0,
                execute=False,
                latest_output_override=LATEST,
            )

            self.assertTrue(result["ok"])
            self.assertEqual(result["compare"]["status"], "still_increasing")
            self.assertEqual(result["compare"]["deltas"]["input_errors"], 15)
            self.assertTrue((base / "data" / "interface_error_delta" / f"{rid}.delta.json").exists())


if __name__ == "__main__":
    unittest.main()
