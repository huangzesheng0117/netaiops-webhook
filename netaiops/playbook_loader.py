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

# ===== v7.11 FortiGate readonly wrapper begin =====
# FortiGate uses some "diagnose" commands for read-only evidence collection.
# They are not configuration commands, but the legacy playbook loader may not
# classify them as readonly by default. Wrap candidate generation and mark only
# explicitly allowlisted FortiGate diagnostic commands as readonly.
_FORTIGATE_READONLY_DIAGNOSE_PREFIXES_V711 = (
    "diagnose sys ha checksum show",
    "diagnose sys top",
    "diagnose hardware sysinfo memory",
    "diagnose sys session stat",
    "diagnose sys session full-stat",
    "diagnose sys session session stat",
)


def _v711_is_fortigate_readonly_diagnose(command: str) -> bool:
    normalized = " ".join(str(command or "").strip().lower().split())
    return any(
        normalized.startswith(prefix)
        for prefix in _FORTIGATE_READONLY_DIAGNOSE_PREFIXES_V711
    )


try:
    _v711_original_build_execution_candidates_from_playbook = build_execution_candidates_from_playbook
except NameError:
    _v711_original_build_execution_candidates_from_playbook = None


if _v711_original_build_execution_candidates_from_playbook is not None:
    def build_execution_candidates_from_playbook(playbook, event):
        candidates = _v711_original_build_execution_candidates_from_playbook(playbook, event)

        for item in candidates or []:
            command = item.get("command") or item.get("cmd") or ""
            if _v711_is_fortigate_readonly_diagnose(command):
                item["readonly"] = True
                item.setdefault("readonly_reason", "fortigate_v7_11_diagnose_allowlist")

        return candidates
# ===== v7.11 FortiGate readonly wrapper end =====

# ===== v9.5 interface utilization playbook event enrichment begin =====
# build_execution_candidates_from_playbook 当前只接收 event，不接收 family_result.target_scope。
# 因此需要在这里针对接口/链路利用率高告警做一次轻量补全：
# - WG88互联网线路_电信_100M_利用率 => Te1/0/1|Te2/0/1
# - 对 {interface_each} 按 interfaces 展开
import re as _v95_pl_re
import json as _v95_pl_json

try:
    _v95_pl_original_build_execution_candidates_from_playbook = build_execution_candidates_from_playbook
except NameError:
    _v95_pl_original_build_execution_candidates_from_playbook = None


def _v95_pl_text(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        try:
            return _v95_pl_json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)
    return str(value).strip()


def _v95_pl_blob(event):
    if not isinstance(event, dict):
        return _v95_pl_text(event)
    return " ".join([
        _v95_pl_text(event),
        _v95_pl_text(event.get("labels")),
        _v95_pl_text(event.get("annotations")),
    ])


def _v95_pl_enrich_event(playbook, event):
    if not isinstance(event, dict):
        return event
    pbid = str((playbook or {}).get("playbook_id") or "")
    blob = _v95_pl_blob(event)

    if "utilization" not in pbid and "利用率" not in blob and "WG88互联网线路_电信_100M" not in blob:
        return event

    enriched = dict(event)

    # labels/annotations 里可能有目标字段，先扁平化补充。
    for src_name in ("labels", "annotations"):
        src = event.get(src_name)
        if isinstance(src, dict):
            for key in ("device_ip", "ip", "instance", "hostname", "sysName", "interface", "ifName", "if_name", "object_name", "direction", "capacity_bps"):
                if not enriched.get(key) and src.get(key):
                    enriched[key] = src.get(key)

    if "WG88互联网线路_电信_100M" in blob:
        enriched.setdefault("hostname", "WG404-H0304-C95-INT-ACC")
        enriched.setdefault("device_ip", "10.189.250.8")
        enriched.setdefault("ip", enriched.get("device_ip") or "10.189.250.8")
        enriched.setdefault("instance", enriched.get("device_ip") or "10.189.250.8")
        enriched["interfaces"] = ["Te1/0/1", "Te2/0/1"]
        enriched["interface"] = "Te1/0/1|Te2/0/1"
        enriched["ifName"] = "Te1/0/1|Te2/0/1"
        enriched["if_name"] = "Te1/0/1|Te2/0/1"
        enriched["interface_name"] = "Te1/0/1|Te2/0/1"
        enriched["interface_regex"] = "Te1/0/1|Te2/0/1"
        enriched["capacity_bps"] = "100000000"
        enriched["link_capacity_bps"] = "100000000"
        enriched["link_name"] = "WG88互联网线路_电信_100M"
        enriched["aggregate_circuit"] = True
        enriched["interface_count"] = 2
        if "出向" in blob:
            enriched["direction"] = "out"
            enriched["traffic_direction"] = "out"

    if enriched.get("interfaces") and not enriched.get("interface"):
        interfaces = enriched.get("interfaces")
        if isinstance(interfaces, (list, tuple)):
            joined = "|".join(str(x).strip() for x in interfaces if str(x).strip())
            enriched["interface"] = joined
            enriched["ifName"] = joined
            enriched["if_name"] = joined
            enriched["interface_regex"] = joined

    return enriched


if _v95_pl_original_build_execution_candidates_from_playbook is not None:
    def build_execution_candidates_from_playbook(playbook, event):
        enriched_event = _v95_pl_enrich_event(playbook, event)
        return _v95_pl_original_build_execution_candidates_from_playbook(playbook, enriched_event)
# ===== v9.5 interface utilization playbook event enrichment end =====
