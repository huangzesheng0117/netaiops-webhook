import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

BASE_DIR = Path("/opt/netaiops-webhook")
PLAYBOOK_DIR = BASE_DIR / "playbooks"

def _safe_lower(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()

def load_playbook_file(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def list_playbook_files() -> List[Path]:
    return sorted(PLAYBOOK_DIR.glob("*.yaml"))

def load_all_playbooks() -> List[Dict[str, Any]]:
    result = []
    for path in list_playbook_files():
        data = load_playbook_file(path)
        data["_file"] = str(path)
        result.append(data)
    return result

def _split_interfaces(value: Any) -> List[str]:
    if not value:
        return []
    if isinstance(value, list):
        out = []
        for x in value:
            out.extend(_split_interfaces(x))
        return out
    parts = re.split(r"[|,]", str(value))
    return [p.strip() for p in parts if p.strip()]

def playbook_matches(playbook: Dict[str, Any], event: Dict[str, Any], classification: Dict[str, Any]) -> bool:
    match = playbook.get("match", {}) or {}

    playbook_vendor = _safe_lower(match.get("vendor"))
    playbook_alarm_type = _safe_lower(match.get("alarm_type"))
    playbook_playbook_type = _safe_lower(match.get("playbook_type"))
    alertname = _safe_lower(event.get("alarm_type") or event.get("event_type"))
    playbook_alertname = _safe_lower(match.get("alertname"))
    playbook_alertname_regex = match.get("alertname_regex", "")

    event_vendor = _safe_lower(event.get("vendor"))
    event_alarm_type = alertname
    classified_playbook_type = _safe_lower(classification.get("playbook_type"))

    if playbook_vendor and playbook_vendor != event_vendor:
        return False
    if playbook_alarm_type and playbook_alarm_type != event_alarm_type:
        return False
    if playbook_playbook_type and playbook_playbook_type != classified_playbook_type:
        return False
    if playbook_alertname and playbook_alertname != alertname:
        return False
    if playbook_alertname_regex:
        try:
            if not re.search(playbook_alertname_regex, event_alarm_type, flags=re.IGNORECASE):
                return False
        except re.error:
            return False

    return True

def find_best_playbook(event: Dict[str, Any], classification: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    playbooks = load_all_playbooks()
    for playbook in playbooks:
        if playbook_matches(playbook, event, classification):
            return playbook
    return None

def render_command_template(template: str, event: Dict[str, Any], interface_each: str = "") -> str:
    values = {
        "device_ip": event.get("device_ip", "") or event.get("ip", "") or event.get("host_ip", ""),
        "hostname": event.get("hostname", ""),
        "peer_ip": event.get("peer_ip", "") or event.get("object_id", ""),
        "interface": event.get("interface", "") or event.get("object_id", ""),
        "interface_each": interface_each or event.get("interface", ""),
        "if_alias": event.get("if_alias", "") or event.get("ifAlias", ""),
        "job": event.get("job", ""),
        "carrier": event.get("carrier", ""),
        "link_name": event.get("link_name", ""),
        "pool_member": event.get("pool_member", "") or event.get("object_id", ""),
    }
    try:
        return template.format(**values).strip()
    except Exception:
        return template.strip()

def is_readonly_command(command: str) -> bool:
    c = _safe_lower(command)
    return c.startswith(("show ", "display ", "get ", "tmsh show", "tmsh list", "ping ", "traceroute "))

def build_execution_candidates_from_playbook(playbook: Dict[str, Any], event: Dict[str, Any]) -> List[Dict[str, Any]]:
    execution = playbook.get("execution", {}) or {}
    commands = execution.get("commands", []) or []

    result = []
    idx = 1
    interfaces = _split_interfaces(event.get("interfaces") or event.get("interface"))

    for cmd in commands:
        templates = []
        if "{interface_each}" in str(cmd):
            if interfaces:
                for iface in interfaces:
                    templates.append((cmd, iface))
            else:
                templates.append((cmd, event.get("interface", "")))
        else:
            templates.append((cmd, ""))

        for template, iface in templates:
            rendered = render_command_template(template, event, interface_each=iface)
            readonly = is_readonly_command(rendered)
            result.append(
                {
                    "order": idx,
                    "command": rendered,
                    "reason": f"playbook:{playbook.get('playbook_id', 'unknown')}",
                    "risk": "low" if readonly else "unknown",
                    "readonly": readonly,
                }
            )
            idx += 1
    return result
