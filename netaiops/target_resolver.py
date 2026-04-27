import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List

import yaml


BASE_DIR = Path("/opt/netaiops-webhook")
CATALOG_DIR = BASE_DIR / "catalogs" / "three_layer"
INVENTORY_PATH = CATALOG_DIR / "device_inventory.normalized.yaml"
TARGET_LOOKUP_PATH = CATALOG_DIR / "target_lookup.yaml"


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def is_exporter_endpoint(value: Any) -> bool:
    text = safe_text(value)
    if not text:
        return False
    return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}:\d+$", text))


def is_plain_ip(value: Any) -> bool:
    text = safe_text(value)
    if not text:
        return False
    return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", text))


@lru_cache(maxsize=8)
def load_yaml_records(path_str: str) -> List[Dict[str, Any]]:
    path = Path(path_str)
    if not path.exists():
        return []

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]

    if isinstance(data, dict):
        for key in ("devices", "items", "records", "targets"):
            value = data.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]

    return []


def iter_records() -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    records.extend(load_yaml_records(str(INVENTORY_PATH)))
    records.extend(load_yaml_records(str(TARGET_LOOKUP_PATH)))
    return records


def find_record_by_device_ip(device_ip: str) -> Dict[str, Any]:
    ip = safe_text(device_ip)
    if not ip:
        return {}

    for rec in iter_records():
        candidates = [
            safe_text(rec.get("device_ip")),
            safe_text(rec.get("ip")),
            safe_text(rec.get("mgmt_ip")),
            safe_text(rec.get("instance")),
        ]
        if ip in candidates:
            return rec

    return {}


def best_device_name(record: Dict[str, Any], fallback_hostname: str = "", fallback_ip: str = "") -> str:
    for key in ("sysname", "hostname", "device_name", "name"):
        value = safe_text(record.get(key))
        if value and not is_exporter_endpoint(value):
            return value

    fallback_hostname = safe_text(fallback_hostname)
    if fallback_hostname and not is_exporter_endpoint(fallback_hostname):
        return fallback_hostname

    return safe_text(fallback_ip)


def resolve_device_identity(target_scope: Dict[str, Any]) -> Dict[str, Any]:
    target_scope = target_scope or {}

    device_ip = safe_text(target_scope.get("device_ip"))
    hostname = safe_text(target_scope.get("hostname"))

    record = find_record_by_device_ip(device_ip)
    display_name = best_device_name(record, fallback_hostname=hostname, fallback_ip=device_ip)

    return {
        "display_name": display_name,
        "device_ip": device_ip,
        "raw_hostname": hostname,
        "resolved_from_inventory": bool(record),
        "inventory_record": record,
    }


def resolve_device_display(target_scope: Dict[str, Any], fallback_mcp_name: str = "") -> str:
    identity = resolve_device_identity(target_scope)
    display_name = safe_text(identity.get("display_name"))
    device_ip = safe_text(identity.get("device_ip"))
    fallback_mcp_name = safe_text(fallback_mcp_name)

    if fallback_mcp_name and not is_exporter_endpoint(fallback_mcp_name):
        display_name = fallback_mcp_name

    if display_name and device_ip and display_name != device_ip:
        return f"{display_name}（{device_ip}）"
    if display_name:
        return display_name
    if device_ip:
        return device_ip
    return "无"
