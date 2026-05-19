import json
import tempfile
import unittest
from pathlib import Path

from netaiops.execution_parser_enricher import enrich_execution_data, enrich_execution_file


SHOW_INTERFACES_SAMPLE = """TenGigabitEthernet1/0/1 is up, line protocol is up (connected)
  MTU 1500 bytes, BW 10000000 Kbit/sec, DLY 10 usec,
  Input queue: 0/2000/0/0 (size/max/drops/flushes); Total output drops: 0
  5 minute input rate 13385000 bits/sec, 7094 packets/sec
  5 minute output rate 24636000 bits/sec, 7561 packets/sec
     5856 input errors, 5733 CRC, 0 frame, 0 overrun, 0 ignored
     0 output errors, 0 collisions, 12 interface resets
"""

COUNTERS_SAMPLE = """Port           Align-Err     FCS-Err    Xmit-Err     Rcv-Err  UnderSize  OutDiscards
Te1/0/1                0        5733           0        5856          0            0

Port         Single-Col  Multi-Col   Late-Col  Excess-Col  Carri-Sen      Runts
Te1/0/1               0          0          0           0          0          0
"""

ETHERCHANNEL_SAMPLE = """Number of channel-groups in use: 1
Number of aggregators:           1

Group  Port-channel  Protocol    Ports
------+-------------+-----------+-----------------------------------------------
101    Po101(SU)       LACP        Te1/1/1(P)      Te2/1/1(P)
"""


class TestExecutionParserEnricher(unittest.TestCase):
    def test_enrich_execution_data_adds_parsed_to_supported_commands(self):
        data = {
            "command_results": [
                {
                    "command": "show interfaces TenGigabitEthernet1/0/1",
                    "platform": "cisco_iosxe",
                    "output": SHOW_INTERFACES_SAMPLE,
                },
                {
                    "command": "show interfaces TenGigabitEthernet1/0/1 counters errors",
                    "platform": "cisco_iosxe",
                    "output": COUNTERS_SAMPLE,
                },
                {
                    "command": "show etherchannel summary",
                    "platform": "cisco_iosxe",
                    "output": ETHERCHANNEL_SAMPLE,
                },
            ]
        }

        enriched, result = enrich_execution_data(data)

        self.assertTrue(result["ok"])
        self.assertEqual(result["command_count"], 3)
        self.assertEqual(result["parse_status_counts"]["parsed"], 3)

        self.assertEqual(enriched["command_results"][0]["parsed"]["parser"], "cisco_show_interfaces")
        self.assertEqual(enriched["command_results"][1]["parsed"]["parser"], "cisco_show_interfaces_counters_errors")
        self.assertEqual(enriched["command_results"][2]["parsed"]["parser"], "cisco_etherchannel_summary")

    def test_enrich_execution_file_persists_parsed(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "sample.execution.json"
            p.write_text(json.dumps({
                "command_results": [
                    {
                        "command": "show interfaces TenGigabitEthernet1/0/1",
                        "platform": "cisco_iosxe",
                        "output": SHOW_INTERFACES_SAMPLE,
                    }
                ]
            }, ensure_ascii=False), encoding="utf-8")

            result = enrich_execution_file(p)
            self.assertTrue(result["ok"])

            saved = json.loads(p.read_text(encoding="utf-8"))
            parsed = saved["command_results"][0]["parsed"]
            self.assertEqual(parsed["status"], "parsed")
            self.assertEqual(parsed["parsed"]["interface"], "TenGigabitEthernet1/0/1")


if __name__ == "__main__":
    unittest.main()
