import unittest

from netaiops.parser_registry import parse_command_output, validate_parser_registry


SHOW_INTERFACES_SAMPLE = """TenGigabitEthernet1/0/1 is up, line protocol is up (connected)
  Hardware is Ten Gigabit Ethernet, address is 88fc.5d7f.bb01 (bia 88fc.5d7f.bb01)
  Description: INTERNET_GDS_300M_610202112193_Active
  MTU 1500 bytes, BW 10000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Full-duplex, 10Gb/s, link type is auto, media type is SFP-10GBase-LR
  ARP type: ARPA, ARP Timeout 04:00:00
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

ETHERCHANNEL_SAMPLE = """Flags:  D - down        P - bundled in port-channel
        I - stand-alone s - suspended
        H - Hot-standby (LACP only)
        R - Layer3      S - Layer2
        U - in use      f - failed to allocate aggregator

Number of channel-groups in use: 3
Number of aggregators:           3

Group  Port-channel  Protocol    Ports
------+-------------+-----------+-----------------------------------------------
99     Po99(SD)        LACP        Te1/1/4(D)      Te2/1/4(D)
101    Po101(SU)       LACP        Te1/1/1(P)      Te2/1/1(P)
102    Po102(SU)       LACP        Te1/1/2(P)      Te2/1/2(P)
"""


class TestParserRegistry(unittest.TestCase):
    def test_parser_registry_valid(self):
        result = validate_parser_registry()
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["enabled_parser_count"], 3)

    def test_parse_cisco_show_interfaces(self):
        result = parse_command_output(
            command="show interfaces TenGigabitEthernet1/0/1",
            output=SHOW_INTERFACES_SAMPLE,
            platform="cisco_iosxe",
        )

        self.assertEqual(result["status"], "parsed")
        self.assertEqual(result["parser"], "cisco_show_interfaces")

        parsed = result["parsed"]
        self.assertEqual(parsed["interface"], "TenGigabitEthernet1/0/1")
        self.assertEqual(parsed["admin_status"], "up")
        self.assertEqual(parsed["oper_status"], "up")
        self.assertEqual(parsed["bandwidth_bps"], 10000000000)
        self.assertEqual(parsed["input_rate_bps"], 13385000)
        self.assertEqual(parsed["output_rate_bps"], 24636000)
        self.assertEqual(parsed["crc"], 5733)
        self.assertEqual(parsed["output_errors"], 0)
        self.assertEqual(parsed["output_drops"], 0)
        self.assertEqual(parsed["interface_resets"], 12)
        self.assertEqual(parsed["input_utilization_percent_estimated"], 0.13)
        self.assertEqual(parsed["output_utilization_percent_estimated"], 0.25)

    def test_parse_cisco_counters_errors(self):
        result = parse_command_output(
            command="show interfaces TenGigabitEthernet1/0/1 counters errors",
            output=COUNTERS_SAMPLE,
            platform="cisco_iosxe",
        )

        self.assertEqual(result["status"], "parsed")
        self.assertEqual(result["parser"], "cisco_show_interfaces_counters_errors")

        parsed = result["parsed"]
        self.assertEqual(parsed["interface"], "Te1/0/1")
        self.assertEqual(parsed["command_interface"], "TenGigabitEthernet1/0/1")
        self.assertEqual(parsed["fcs_err"], 5733)
        self.assertEqual(parsed["crc"], 5733)
        self.assertEqual(parsed["rcv_err"], 5856)
        self.assertEqual(parsed["input_errors"], 5856)
        self.assertEqual(parsed["xmit_err"], 0)
        self.assertEqual(parsed["out_discards"], 0)
        self.assertEqual(parsed["runts"], 0)

    def test_parse_cisco_etherchannel_summary(self):
        result = parse_command_output(
            command="show etherchannel summary",
            output=ETHERCHANNEL_SAMPLE,
            platform="cisco_iosxe",
        )

        self.assertEqual(result["status"], "parsed")
        self.assertEqual(result["parser"], "cisco_etherchannel_summary")

        parsed = result["parsed"]
        self.assertEqual(parsed["channel_group_count"], 3)
        self.assertEqual(parsed["aggregator_count"], 3)
        self.assertEqual(parsed["port_channel_count"], 3)
        self.assertEqual(parsed["member_count"], 6)
        self.assertEqual(parsed["bundled_member_count"], 4)
        self.assertEqual(parsed["down_member_count"], 2)

        po101 = [x for x in parsed["port_channels"] if x["port_channel"] == "Po101"][0]
        self.assertEqual(po101["flags"], "SU")
        self.assertEqual(po101["state"], "in_use")
        self.assertEqual(po101["member_count"], 2)

    def test_unknown_command_is_skipped(self):
        result = parse_command_output(
            command="show version",
            output="Cisco IOS XE Software",
            platform="cisco_iosxe",
        )

        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["reason"], "no_parser_matched")


if __name__ == "__main__":
    unittest.main()
