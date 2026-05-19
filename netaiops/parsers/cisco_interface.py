from __future__ import annotations

import re
from typing import Any


_INT_STATUS_RE = re.compile(
    r"^(?P<interface>\S+) is (?P<admin_status>administratively down|up|down), line protocol is (?P<oper_status>up|down)(?:\s+\((?P<oper_detail>[^)]*)\))?",
    re.IGNORECASE,
)

_BW_RE = re.compile(r"\bBW\s+(?P<bw_kbit>\d+)\s+Kbit/sec", re.IGNORECASE)
_INPUT_RATE_RE = re.compile(r"5 minute input rate\s+(?P<input_rate_bps>\d+)\s+bits/sec", re.IGNORECASE)
_OUTPUT_RATE_RE = re.compile(r"5 minute output rate\s+(?P<output_rate_bps>\d+)\s+bits/sec", re.IGNORECASE)
_ERR_RE = re.compile(
    r"(?P<input_errors>\d+)\s+input errors,\s+(?P<crc>\d+)\s+CRC,\s+(?P<frame>\d+)\s+frame,\s+(?P<overrun>\d+)\s+overrun,\s+(?P<ignored>\d+)\s+ignored",
    re.IGNORECASE,
)
_OUTPUT_ERR_RE = re.compile(r"(?P<output_errors>\d+)\s+output errors", re.IGNORECASE)
_OUTPUT_DROPS_RE = re.compile(r"Total output drops:\s+(?P<output_drops>\d+)", re.IGNORECASE)
_RESETS_RE = re.compile(r"(?P<interface_resets>\d+)\s+interface resets", re.IGNORECASE)
_DUPLEX_SPEED_RE = re.compile(r"(?P<duplex>Full-duplex|Half-duplex|Auto-duplex),\s+(?P<speed>[^,\n]+)", re.IGNORECASE)
_DESC_RE = re.compile(r"^\s*Description:\s*(?P<description>.+?)\s*$", re.IGNORECASE | re.MULTILINE)


def _int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _first_line(output: str) -> str:
    for line in (output or "").splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def parse_cisco_show_interfaces(command: str, output: str, platform: str = "") -> dict[str, Any]:
    output = output or ""
    first_line = _first_line(output)

    parsed: dict[str, Any] = {
        "parser": "cisco_show_interfaces",
        "parser_version": "v6.2.0",
        "platform": platform or "",
        "command": command,
        "matched": False,
    }

    m = _INT_STATUS_RE.search(first_line)
    if m:
        admin_raw = m.group("admin_status").lower()
        admin_status = "down" if admin_raw == "administratively down" else admin_raw
        oper_status = m.group("oper_status").lower()

        parsed.update({
            "matched": True,
            "interface": m.group("interface"),
            "admin_status": admin_status,
            "admin_status_raw": m.group("admin_status"),
            "oper_status": oper_status,
            "oper_detail": m.group("oper_detail") or "",
        })

    patterns = [
        ("bandwidth_kbit", _BW_RE, "bw_kbit"),
        ("input_rate_bps", _INPUT_RATE_RE, "input_rate_bps"),
        ("output_rate_bps", _OUTPUT_RATE_RE, "output_rate_bps"),
        ("output_drops", _OUTPUT_DROPS_RE, "output_drops"),
        ("interface_resets", _RESETS_RE, "interface_resets"),
        ("output_errors", _OUTPUT_ERR_RE, "output_errors"),
    ]

    for key, regex, group in patterns:
        mm = regex.search(output)
        if mm:
            parsed[key] = _int(mm.group(group))

    if "bandwidth_kbit" in parsed and parsed["bandwidth_kbit"] is not None:
        parsed["bandwidth_bps"] = parsed["bandwidth_kbit"] * 1000

    mm = _ERR_RE.search(output)
    if mm:
        parsed["input_errors"] = _int(mm.group("input_errors"))
        parsed["crc"] = _int(mm.group("crc"))
        parsed["frame"] = _int(mm.group("frame"))
        parsed["overrun"] = _int(mm.group("overrun"))
        parsed["ignored"] = _int(mm.group("ignored"))

    mm = _DUPLEX_SPEED_RE.search(output)
    if mm:
        parsed["duplex"] = mm.group("duplex")
        parsed["speed"] = mm.group("speed").strip()

    mm = _DESC_RE.search(output)
    if mm:
        parsed["description"] = mm.group("description").strip()

    if parsed.get("input_rate_bps") is not None and parsed.get("bandwidth_bps"):
        parsed["input_utilization_percent_estimated"] = round(parsed["input_rate_bps"] * 100 / parsed["bandwidth_bps"], 2)

    if parsed.get("output_rate_bps") is not None and parsed.get("bandwidth_bps"):
        parsed["output_utilization_percent_estimated"] = round(parsed["output_rate_bps"] * 100 / parsed["bandwidth_bps"], 2)

    return parsed


def can_parse(command: str, platform: str = "") -> bool:
    c = (command or "").strip().lower()
    p = (platform or "").strip().lower()
    if not c.startswith("show interfaces "):
        return False
    if " counters errors" in c:
        return False
    if p and p not in {"cisco_iosxe", "cisco_ios", "iosxe", "ios"}:
        return False
    return True
