import json
import re
from pathlib import Path
from urllib.parse import unquote, urlparse, parse_qs

import yaml

BASE_DIR = Path("/opt/netaiops-webhook")
CAT_DIR = BASE_DIR / "catalogs" / "three_layer"

def _load_yaml(path: Path):
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

_LAYER2 = _load_yaml(CAT_DIR / "layer2_classifier_mapping.enhanced.yaml").get("layer2_classifier_mapping", [])
_LAYER3 = _load_yaml(CAT_DIR / "layer3_context_enrichment.enhanced.yaml").get("layer3_context_enrichment", [])
_DEVICES = _load_yaml(CAT_DIR / "device_inventory.normalized.yaml").get("devices", [])
_TARGETS = _load_yaml(CAT_DIR / "target_lookup.yaml").get("targets", [])

_CONFIG_INDEX = []
cfg_idx_path = CAT_DIR / "config_interface_index.json"
if cfg_idx_path.exists():
    try:
        _CONFIG_INDEX = json.loads(cfg_idx_path.read_text(encoding="utf-8"))
    except Exception:
        _CONFIG_INDEX = []

DEV_BY_IP = {str(x.get("device_ip") or "").strip(): x for x in _DEVICES if str(x.get("device_ip") or "").strip()}
TGT_BY_IP = {str(x.get("ip") or "").strip(): x for x in _TARGETS if str(x.get("ip") or "").strip()}
L2_BY_ALERT = {}
for item in _LAYER2:
    alertname = str((item.get("match") or {}).get("alertname") or "").strip()
    if alertname:
        L2_BY_ALERT[alertname] = item
L3_BY_ALERT = {str(x.get("alertname") or "").strip(): x for x in _LAYER3 if str(x.get("alertname") or "").strip()}

def safe_lower(v):
    if v is None:
        return ""
    return str(v).strip().lower()

def split_interfaces(value):
    if not value:
        return []
    if isinstance(value, list):
        raw = []
        for x in value:
            raw.extend(split_interfaces(x))
        return raw
    parts = re.split(r"[|,]", str(value))
    out = []
    seen = set()
    for p in parts:
        s = p.strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out

def infer_vendor_from_job(job: str):
    j = safe_lower(job)
    if "fortigate" in j or j.startswith("fw-"):
        return "fortigate"
    if "hillstone" in j:
        return "hillstone"
    if "f5" in j or "ltm" in j or "dns-f5" in j or "gtm" in j:
        return "f5"
    if "h3c" in j or "comware" in j:
        return "h3c"
    if "huawei" in j:
        return "huawei"
    if "cisco" in j or "nxos" in j or "catalyst" in j or j.startswith("sw-"):
        return "cisco"
    if "cimc" in j:
        return "cimc"
    return ""

def extract_ip(text: str):
    if not text:
        return ""
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(text))
    return m.group(0) if m else ""

def parse_generator_url(url: str):
    result = {"generator_expr": "", "ips": [], "ifnames": [], "jobs": []}
    if not url:
        return result
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        expr = ""
        for k in ("g0.expr", "expr", "query"):
            if qs.get(k):
                expr = qs[k][0]
                break
        expr = unquote(expr)
        result["generator_expr"] = expr
        result["ips"] = _extract_list(expr, "ip")
        result["ifnames"] = _extract_list(expr, "ifName")
        result["jobs"] = _extract_list(expr, "job")
    except Exception:
        pass
    return result

def _extract_list(expr: str, key: str):
    if not expr:
        return []
    out = []
    for m in re.finditer(rf'{re.escape(key)}\s*=~?\s*"([^"]+)"', expr):
        out.extend(split_interfaces(m.group(1)))
    for m in re.finditer(rf"{re.escape(key)}\s*=~?\s*'([^']+)'", expr):
        out.extend(split_interfaces(m.group(1)))
    return out

def infer_direction(alarm_type: str, description: str):
    text = f"{alarm_type} {description}"
    if "入向" in text:
        return "inbound"
    if "出向" in text:
        return "outbound"
    return ""

def infer_carrier(alarm_type: str, description: str):
    text = f"{alarm_type} {description}"
    for item in ("电信", "联通", "移动", "鹏博士", "BGP", "互联网"):
        if item in text:
            return item
    return ""

def infer_link_name(alarm_type: str):
    text = str(alarm_type or "")
    for sep in ("利用率", "丢包", "错包", "BGP", "状态", "-入向", "-出向"):
        if sep in text:
            text = text.split(sep)[0]
            break
    return text.strip("_- ")

def find_device_by_interface_ip(interface_ip: str):
    if not interface_ip:
        return {}
    for rec in _CONFIG_INDEX:
        ips = rec.get("ipv4_addresses") or []
        if interface_ip in ips:
            return {
                "hostname": rec.get("sysname", ""),
                "device_ip": rec.get("mgmt_ip", ""),
                "vendor": "",
                "platform": "",
                "site": "",
                "matched_by": "config_interface_ip",
                "interface": rec.get("interface", ""),
                "description": rec.get("description", ""),
            }
    return {}

def enrich_event_from_catalog(event: dict) -> dict:
    event = dict(event or {})
    labels = dict(event.get("labels") or {})
    annotations = dict(event.get("annotations") or {})

    alarm_type = str(event.get("alarm_type") or labels.get("alertname") or "").strip()
    description = str(annotations.get("description") or annotations.get("summary") or "")
    generator_url = str(event.get("generator_url") or labels.get("generatorURL") or "")
    expression = str(event.get("expression") or "")
    gen = parse_generator_url(generator_url)

    l2 = L2_BY_ALERT.get(alarm_type, {})
    l3 = L3_BY_ALERT.get(alarm_type, {})

    runtime_ip = str(labels.get("ip") or extract_ip(labels.get("instance") or "") or "").strip()
    static_ip = ""
    if (l3.get("static_extract") or {}).get("ip_matchers"):
        static_ip = str((l3.get("static_extract") or {}).get("ip_matchers")[0] or "").strip()
    gen_ip = gen["ips"][0] if gen["ips"] else ""

    interface = str(
        event.get("interface")
        or labels.get("ifName")
        or labels.get("interface")
        or ""
    ).strip()
    if not interface and gen["ifnames"]:
        interface = gen["ifnames"][0]
    if not interface:
        vals = (l3.get("static_extract") or {}).get("ifname_matchers") or []
        if vals:
            interface = str(vals[0])
    interfaces = split_interfaces(interface)

    job = str(labels.get("job") or "")
    if not job and gen["jobs"]:
        job = gen["jobs"][0]
    if not job:
        vals = (l3.get("static_extract") or {}).get("job_matchers") or []
        if vals:
            job = str(vals[0])

    device_ip = str(event.get("device_ip") or runtime_ip or gen_ip or static_ip).strip()
    if_alias = str(labels.get("ifAlias") or "")
    instance = str(labels.get("instance") or "")
    monitor = str(labels.get("monitor") or "")
    sysname_label = str(labels.get("sysName") or labels.get("hostname") or "")

    resolved = {}
    if device_ip and device_ip in DEV_BY_IP:
        resolved = DEV_BY_IP[device_ip]
    elif device_ip and device_ip in TGT_BY_IP:
        resolved = TGT_BY_IP[device_ip]
    else:
        resolved = find_device_by_interface_ip(device_ip)

    vendor = str(event.get("vendor") or labels.get("vendor") or resolved.get("vendor") or "").strip()
    if not vendor:
        vendor = infer_vendor_from_job(job)
    if not vendor and l2.get("vendor_hint") and l2.get("vendor_hint") != "generic_network":
        vendor = str(l2.get("vendor_hint"))

    hostname = str(event.get("hostname") or sysname_label or resolved.get("hostname") or "").strip()
    if not hostname and instance and ":" not in instance:
        hostname = instance

    if not event.get("object_type") and interfaces:
        event["object_type"] = "interface"
    if not event.get("object_name"):
        event["object_name"] = if_alias or (interfaces[0] if interfaces else alarm_type)

    event["alarm_type"] = alarm_type
    event["description"] = description
    event["generator_url"] = generator_url
    event["generator_expr"] = gen.get("generator_expr") or expression
    event["device_ip"] = device_ip
    event["hostname"] = hostname
    event["vendor"] = vendor
    event["interface"] = interfaces[0] if interfaces else interface
    event["interfaces"] = interfaces
    event["if_alias"] = if_alias
    event["job"] = job
    event["instance"] = instance
    event["monitor"] = monitor
    event["direction"] = infer_direction(alarm_type, description)
    event["carrier"] = infer_carrier(alarm_type, description)
    event["link_name"] = infer_link_name(alarm_type)
    event["playbook_type_hint"] = str(l2.get("playbook_type") or "")
    event["family"] = str(l2.get("family") or "")
    event["catalog_rule_id"] = str(l2.get("rule_id") or "")
    return event

def classify_event_by_catalog(event: dict):
    playbook_type = str(event.get("playbook_type_hint") or "").strip()
    if not playbook_type:
        return None

    severity = safe_lower(event.get("severity"))
    status = safe_lower(event.get("status"))
    device_ip = str(event.get("device_ip") or "").strip()
    interface = str(event.get("interface") or "").strip()
    vendor = safe_lower(event.get("vendor"))

    prompt_profile = "detailed" if severity in ("critical","major","error") else "quick"
    confidence = "high" if device_ip and (interface or playbook_type in ("device_cpu_high","device_memory_high","hardware_component_abnormal")) else "medium"
    auto_execute_allowed = bool(device_ip and status != "resolved")

    return {
        "vendor": vendor,
        "source": safe_lower(event.get("source")),
        "alarm_type": safe_lower(event.get("alarm_type")),
        "severity": severity,
        "metric_name": safe_lower(event.get("metric_name")),
        "object_type": safe_lower(event.get("object_type")),
        "object_name": safe_lower(event.get("object_name")),
        "playbook_type": playbook_type,
        "prompt_profile": prompt_profile,
        "auto_execute_allowed": auto_execute_allowed,
        "classification_confidence": confidence,
        "match_reason": "matched_catalog_alertname",
    }
