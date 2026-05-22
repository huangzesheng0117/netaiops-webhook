import unittest

from netaiops.family_registry import classify_family
from netaiops.capability_registry import build_capability_plan
from netaiops.family_evidence import build_family_evidence_summary


SAMPLE_TRANSCEIVER_OUTPUT = """
Ethernet1/10
    transceiver is present
    type is 10Gbase-SR
    name is CISCO-JDSU
    part number is PLRXPL-SC-S43-CS
    revision is 1
    serial number is JUR18400CV7
    cisco product id is SFP-10G-SR

           SFP Detail Diagnostics Information (internal calibration)
  ----------------------------------------------------------------------------
                Current              Alarms                  Warnings
                Measurement     High        Low         High          Low
  ----------------------------------------------------------------------------
  Temperature   42.09 C        75.00 C     -5.00 C     70.00 C        0.00 C
  Voltage        3.29 V         3.63 V      2.97 V      3.46 V        3.13 V
  Current        7.13 mA       10.00 mA     2.59 mA     8.50 mA       3.00 mA
  Tx Power      -2.22 dBm       1.69 dBm  -11.30 dBm   -1.30 dBm     -7.30 dBm
  Rx Power     -25.22 dBm --    1.99 dBm  -13.97 dBm   -1.00 dBm     -9.91 dBm
  Transmit Fault Count = 0
  ----------------------------------------------------------------------------
  Note: ++  high-alarm; +  high-warning; --  low-alarm; -  low-warning
"""


class TestOpticalPowerEvidence(unittest.TestCase):
    def test_optical_power_family_overrides_hardware_power(self):
        event = {
            "hostname": "SH8-G16-WL-AGG-SW01",
            "device_ip": "10.192.251.121",
            "vendor": "cisco",
            "platform": "nxos",
            "alarm_type": "NXOS光功率",
            "description": "思科NXOS交换机接口Ethernet1/10接收光功率异常",
            "object_name": "Ethernet1/10",
        }

        family_result = classify_family(event)

        self.assertEqual(family_result["family"], "optical_power_abnormal")
        self.assertEqual(family_result["target_scope"]["interface"], "Ethernet1/10")

    def test_optical_power_capability_uses_transceiver_command(self):
        event = {
            "hostname": "SH8-G16-WL-AGG-SW01",
            "device_ip": "10.192.251.121",
            "vendor": "cisco",
            "platform": "nxos",
            "alarm_type": "NXOS光功率",
            "description": "思科NXOS交换机接口Ethernet1/10接收光功率异常",
            "object_name": "Ethernet1/10",
        }

        family_result = classify_family(event)
        plan = build_capability_plan(event, family_result)
        caps = [x.get("capability") for x in plan.get("selected_capabilities", [])]

        self.assertIn("show_interface_transceiver", caps)
        self.assertEqual(plan["selected_capabilities"][0]["arguments"]["interface"], "Ethernet1/10")

    def test_optical_power_evidence_parses_rx_low_alarm(self):
        execution_data = {
            "family_result": {
                "family": "optical_power_abnormal",
                "target_scope": {
                    "interface": "Ethernet1/10",
                },
            },
            "target_scope": {
                "interface": "Ethernet1/10",
            },
            "command_results": [
                {
                    "capability": "show_interface_transceiver",
                    "command": "show interface Ethernet1/10 transceiver details",
                    "dispatch_status": "completed",
                    "output": SAMPLE_TRANSCEIVER_OUTPUT,
                }
            ],
        }

        summary = build_family_evidence_summary(execution_data)
        facts = summary["facts"]

        self.assertTrue(summary["has_facts"])
        self.assertEqual(summary["family"], "optical_power_abnormal")
        self.assertEqual(facts["interface"], "Ethernet1/10")
        self.assertEqual(facts["rx_power_status"], "low_alarm")
        self.assertEqual(facts["rx_power_current"], -25.22)
        self.assertEqual(facts["tx_power_status"], "normal")
        self.assertIn("收光功率异常", " ".join(summary["key_findings"]))
        self.assertIn("对端发光功率", " ".join(summary["recommendations"]))


if __name__ == "__main__":
    unittest.main()
