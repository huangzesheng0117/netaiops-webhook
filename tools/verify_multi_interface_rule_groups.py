#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List

try:
    import yaml
except Exception as exc:
    raise SystemExit(f"ERROR: PyYAML is required: {exc}")

import sys

BASE_DIR = Path("/opt/netaiops-webhook")
sys.path.insert(0, str(BASE_DIR))

from netaiops.family_registry import classify_family
from netaiops.capability_registry import build_capability_plan
from netaiops.platform_command_matrix import resolve_execution_candidates

RULE_FILES = [
    BASE_DIR / "rules.txt",
    BASE_DIR / "input" / "rules.txt",
    BASE_DIR / "input" / "prometheus_rules.txt",
]
GROUP_FILE = BASE_DIR / "config" / "interface_groups.yaml"


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def iter_rules(obj: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(obj, dict):
        if isinstance(obj.get("rules"), list):
            for item in obj["rules"]:
                if isinstance(item, dict):
                    yield item

        for value in obj.values():
            yield from iter_rules(value)

    elif isinstance(obj, list):
        for item in obj:
            yield from iter_rules(item)


def load_rules() -> List[Dict[str, Any]]:
    for path in RULE_FILES:
        if path.exists():
            return list(iter_rules(json.loads(path.read_text(encoding="utf-8", errors="replace"))))

    raise SystemExit("ERROR: rules file not found")


def extract_ip(query: str) -> str:
    m = re.search(r'ip\s*=~\s*"([^"]+)"', query)
    if not m:
        return ""
    value = m.group(1)
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", value):
        return value
    return ""


def extract_ifnames(query: str) -> List[str]:
    m = re.search(r'ifName\s*=~\s*"([^"]+\|[^"]+)"', query)
    if not m:
        return []

    items = []
    seen = set()

    for item in m.group(1).split("|"):
        item = item.strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_\-./]+", item):
            continue
        if item in seen:
            continue
        seen.add(item)
        items.append(item)

    return items if len(items) >= 2 else []


def full_iosxe_name(interface: str) -> str:
    m = re.match(r"^Te(\d+/\d+/\d+)$", interface, flags=re.I)
    if m:
        return "TenGigabitEthernet" + m.group(1)

    m = re.match(r"^Gi(\d+/\d+/\d+)$", interface, flags=re.I)
    if m:
        return "GigabitEthernet" + m.group(1)

    m = re.match(r"^Po(\d+)$", interface, flags=re.I)
    if m:
        return "Port-channel" + m.group(1)

    return interface


def command_has_interface(commands: List[str], interface: str) -> bool:
    aliases = {interface, full_iosxe_name(interface)}

    return any(any(alias in cmd for alias in aliases if alias) for cmd in commands)


def interesting_rules() -> List[Dict[str, Any]]:
    result = []

    for rule in load_rules():
        name = safe_text(rule.get("name"))
        query = safe_text(rule.get("query"))
        annotations = rule.get("annotations") if isinstance(rule.get("annotations"), dict) else {}
        description = safe_text(annotations.get("description"))

        if "利用率" not in f"{name} {description}":
            continue

        interfaces = extract_ifnames(query)
        device_ip = extract_ip(query)

        if len(interfaces) < 2 or not device_ip:
            continue

        result.append(
            {
                "name": name,
                "description": description.replace("{{$labels.sysName}}", "").strip(),
                "query": query,
                "device_ip": device_ip,
                "interfaces": interfaces,
            }
        )

    return result


def main() -> None:
    if not GROUP_FILE.exists():
        raise SystemExit("ERROR: config/interface_groups.yaml not found")

    data = yaml.safe_load(GROUP_FILE.read_text(encoding="utf-8")) or {}
    groups = data.get("interface_groups", []) or []

    print("interface_group_count =", len(groups))

    rules = interesting_rules()

    print("multi_interface_utilization_rule_count =", len(rules))

    failed = []

    for rule in rules:
        interfaces = rule["interfaces"]

        event = {
            "source": "alertmanager",
            "status": "firing",
            "vendor": "Cisco",
            "os_family": "ios-xe",
            "platform": "cisco_iosxe",
            "device_ip": rule["device_ip"],
            "hostname": "TEST-DEVICE",
            "interface": interfaces[0],
            "alarm_type": rule["name"],
            "raw_text": f"{rule['name']} {rule['description']}",
        }

        family_result = classify_family(event)
        plan = build_capability_plan(event, family_result)
        candidates = resolve_execution_candidates(event, family_result, plan)
        commands = [safe_text(x.get("command")) for x in candidates if isinstance(x, dict)]

        print("=====", rule["name"], "=====")
        print("device_ip =", rule["device_ip"])
        print("interfaces =", interfaces)
        print("family =", family_result.get("family"))
        print("plan_source =", plan.get("plan_source"))
        print("commands =")
        for command in commands:
            print(command)

        if family_result.get("family") != "interface_or_link_utilization_high":
            failed.append((rule["name"], "family_not_utilization"))
            continue

        for interface in interfaces:
            if not command_has_interface(commands, interface):
                failed.append((rule["name"], f"missing_interface_command:{interface}"))

    if failed:
        print("FAILED_ITEMS =", failed)
        raise SystemExit("ERROR: some multi-interface utilization rules are not covered")

    print("VERIFY_MULTI_INTERFACE_RULE_GROUPS_CHECK=PASS")


if __name__ == "__main__":
    main()
