from __future__ import annotations

import re
from typing import Any


_GROUP_COUNT_RE = re.compile(r"Number of channel-groups in use:\s+(?P<count>\d+)", re.IGNORECASE)
_AGG_COUNT_RE = re.compile(r"Number of aggregators:\s+(?P<count>\d+)", re.IGNORECASE)

_PORT_CHANNEL_RE = re.compile(r"^(?P<name>[A-Za-z]+\d+)\((?P<flags>[^)]*)\)$")
_GROUP_LINE_RE = re.compile(
    r"^\s*(?P<group>\d+)\s+"
    r"(?P<port_channel>\S+)\s+"
    r"(?P<protocol>\S+)\s*"
    r"(?P<ports>.*)$"
)

_MEMBER_RE = re.compile(r"(?P<interface>[A-Za-z]+[A-Za-z]*\d+(?:/\d+)+)\((?P<flags>[^)]*)\)")


def _int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _parse_port_channel(value: str) -> tuple[str, str]:
    m = _PORT_CHANNEL_RE.match(value or "")
    if not m:
        return value or "", ""
    return m.group("name"), m.group("flags")


def _member_state(flags: str) -> str:
    flags = flags or ""
    if "P" in flags:
        return "bundled"
    if "D" in flags:
        return "down"
    if "I" in flags:
        return "standalone"
    if "s" in flags:
        return "suspended"
    if "H" in flags:
        return "hot_standby"
    return "unknown"


def _port_channel_state(flags: str) -> str:
    flags = flags or ""
    if "U" in flags:
        return "in_use"
    if "D" in flags:
        return "down"
    if "S" in flags:
        return "layer2"
    if "R" in flags:
        return "layer3"
    return "unknown"


def parse_cisco_etherchannel_summary(command: str, output: str, platform: str = "") -> dict[str, Any]:
    output = output or ""

    parsed: dict[str, Any] = {
        "parser": "cisco_etherchannel_summary",
        "parser_version": "v6.2.0",
        "platform": platform or "",
        "command": command,
        "matched": False,
        "port_channels": [],
        "members": [],
    }

    m = _GROUP_COUNT_RE.search(output)
    if m:
        parsed["channel_group_count"] = _int(m.group("count"))

    m = _AGG_COUNT_RE.search(output)
    if m:
        parsed["aggregator_count"] = _int(m.group("count"))

    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        m = _GROUP_LINE_RE.match(line)
        if not m:
            continue

        group = _int(m.group("group"))
        pc_raw = m.group("port_channel")
        protocol = m.group("protocol")
        ports_raw = m.group("ports") or ""

        pc_name, pc_flags = _parse_port_channel(pc_raw)

        members = []
        for mm in _MEMBER_RE.finditer(ports_raw):
            item = {
                "interface": mm.group("interface"),
                "flags": mm.group("flags"),
                "state": _member_state(mm.group("flags")),
                "port_channel": pc_name,
                "group": group,
            }
            members.append(item)
            parsed["members"].append(item)

        parsed["port_channels"].append({
            "group": group,
            "port_channel": pc_name,
            "raw_port_channel": pc_raw,
            "flags": pc_flags,
            "state": _port_channel_state(pc_flags),
            "protocol": protocol,
            "members": members,
            "member_count": len(members),
        })

        parsed["matched"] = True

    parsed["port_channel_count"] = len(parsed["port_channels"])
    parsed["member_count"] = len(parsed["members"])
    parsed["bundled_member_count"] = len([x for x in parsed["members"] if x.get("state") == "bundled"])
    parsed["down_member_count"] = len([x for x in parsed["members"] if x.get("state") == "down"])

    return parsed


def can_parse(command: str, platform: str = "") -> bool:
    c = (command or "").strip().lower()
    p = (platform or "").strip().lower()

    if c not in {"show etherchannel summary", "show port-channel summary"}:
        return False

    if p and p not in {"cisco_iosxe", "cisco_ios", "iosxe", "ios"}:
        return False

    return True
