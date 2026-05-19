from __future__ import annotations

import re
from typing import Any


_CMD_INTF_RE = re.compile(
    r"show\s+interfaces?\s+(?P<interface>\S+)\s+counters\s+errors",
    re.IGNORECASE,
)

_PRIMARY_RE = re.compile(
    r"^(?P<port>\S+)\s+"
    r"(?P<align_err>\d+)\s+"
    r"(?P<fcs_err>\d+)\s+"
    r"(?P<xmit_err>\d+)\s+"
    r"(?P<rcv_err>\d+)\s+"
    r"(?P<undersize>\d+)\s+"
    r"(?P<out_discards>\d+)\s*$",
    re.IGNORECASE,
)

_SECONDARY_RE = re.compile(
    r"^(?P<port>\S+)\s+"
    r"(?P<single_col>\d+)\s+"
    r"(?P<multi_col>\d+)\s+"
    r"(?P<late_col>\d+)\s+"
    r"(?P<excess_col>\d+)\s+"
    r"(?P<carri_sen>\d+)\s+"
    r"(?P<runts>\d+)\s*$",
    re.IGNORECASE,
)


def _int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _command_interface(command: str) -> str:
    m = _CMD_INTF_RE.search(command or "")
    return m.group("interface") if m else ""


def parse_cisco_show_interfaces_counters_errors(command: str, output: str, platform: str = "") -> dict[str, Any]:
    output = output or ""
    parsed: dict[str, Any] = {
        "parser": "cisco_show_interfaces_counters_errors",
        "parser_version": "v6.2.0",
        "platform": platform or "",
        "command": command,
        "matched": False,
        "command_interface": _command_interface(command),
    }

    section = ""
    port = ""

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if "Align-Err" in line and "FCS-Err" in line and "OutDiscards" in line:
            section = "primary"
            continue

        if "Single-Col" in line and "Late-Col" in line and "Runts" in line:
            section = "secondary"
            continue

        if section == "primary":
            m = _PRIMARY_RE.match(line)
            if not m:
                continue

            parsed["matched"] = True
            port = m.group("port")
            parsed["interface"] = port
            parsed["align_err"] = _int(m.group("align_err"))
            parsed["fcs_err"] = _int(m.group("fcs_err"))
            parsed["crc"] = parsed["fcs_err"]
            parsed["xmit_err"] = _int(m.group("xmit_err"))
            parsed["rcv_err"] = _int(m.group("rcv_err"))
            parsed["input_errors"] = parsed["rcv_err"]
            parsed["undersize"] = _int(m.group("undersize"))
            parsed["out_discards"] = _int(m.group("out_discards"))
            parsed["output_discards"] = parsed["out_discards"]
            continue

        if section == "secondary":
            m = _SECONDARY_RE.match(line)
            if not m:
                continue

            parsed["matched"] = True
            parsed.setdefault("interface", m.group("port") or port)
            parsed["single_col"] = _int(m.group("single_col"))
            parsed["multi_col"] = _int(m.group("multi_col"))
            parsed["late_col"] = _int(m.group("late_col"))
            parsed["excess_col"] = _int(m.group("excess_col"))
            parsed["carri_sen"] = _int(m.group("carri_sen"))
            parsed["runts"] = _int(m.group("runts"))

    return parsed


def can_parse(command: str, platform: str = "") -> bool:
    c = (command or "").strip().lower()
    p = (platform or "").strip().lower()

    if "show interfaces" not in c:
        return False

    if "counters errors" not in c:
        return False

    if p and p not in {"cisco_iosxe", "cisco_ios", "iosxe", "ios"}:
        return False

    return True
