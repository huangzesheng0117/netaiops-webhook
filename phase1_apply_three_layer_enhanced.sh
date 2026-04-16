#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/opt/netaiops-webhook"
INPUT_DIR="${BASE_DIR}/input/monitoring"
TOOLS_DIR="${BASE_DIR}/tools"
CAT_DIR="${BASE_DIR}/catalogs/three_layer"
PLAYBOOK_DIR="${BASE_DIR}/playbooks"
NETAIOPS_DIR="${BASE_DIR}/netaiops"
BACKUP_DIR="${BASE_DIR}/backup/three_layer_phase1_$(date +%F_%H%M%S)"

mkdir -p "${INPUT_DIR}" "${TOOLS_DIR}" "${CAT_DIR}" "${PLAYBOOK_DIR}" "${BACKUP_DIR}"

echo "==> 输入文件请放到以下路径："
echo "    ${INPUT_DIR}/rules.txt"
echo "    ${INPUT_DIR}/alerts.txt"
echo "    ${INPUT_DIR}/targets.txt"
echo "    ${INPUT_DIR}/device_inventory.xlsx"
echo "    ${INPUT_DIR}/device_configs.zip"
echo

for f in rules.txt alerts.txt targets.txt device_inventory.xlsx device_configs.zip; do
  if [ ! -f "${INPUT_DIR}/${f}" ]; then
    echo "missing required file: ${INPUT_DIR}/${f}"
    exit 1
  fi
done

cd "${BASE_DIR}"
source venv/bin/activate

python - <<'PY'
import importlib.util
import subprocess
import sys
need = []
for mod in ("yaml", "openpyxl"):
    if importlib.util.find_spec(mod) is None:
        need.append(mod)
if need:
    subprocess.check_call([
        sys.executable, "-m", "pip", "install",
        "-i", "https://pypi.tuna.tsinghua.edu.cn/simple",
        *need
    ])
print("python deps ok")
PY

cat > "${TOOLS_DIR}/build_three_layer_enhanced.py" <<'PY'
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import unquote, urlparse, parse_qs

import yaml
from openpyxl import load_workbook

BASE_DIR = Path("/opt/netaiops-webhook")
INPUT_DIR = BASE_DIR / "input" / "monitoring"
OUT_DIR = BASE_DIR / "catalogs" / "three_layer"

def read_json(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def safe_lower(v):
    if v is None:
        return ""
    return str(v).strip().lower()

def split_multi(v: str):
    if not v:
        return []
    parts = re.split(r"[|,]", v)
    return [p.strip() for p in parts if p.strip()]

def extract_list_from_query(query: str, key: str):
    if not query:
        return []
    # ip=~"a|b" / ip="a"
    out = []
    for m in re.finditer(rf'{re.escape(key)}\s*=~?\s*"([^"]+)"', query):
        out.extend(split_multi(m.group(1)))
    # key='...'
    for m in re.finditer(rf"{re.escape(key)}\s*=~?\s*'([^']+)'", query):
        out.extend(split_multi(m.group(1)))
    # de-dup keep order
    seen = set()
    result = []
    for x in out:
        if x not in seen:
            seen.add(x)
            result.append(x)
    return result

def infer_direction(name: str, desc: str):
    text = f"{name} {desc}"
    if "入向" in text or "inbound" in safe_lower(text):
        return "inbound"
    if "出向" in text or "outbound" in safe_lower(text):
        return "outbound"
    return ""

def infer_carrier(name: str, desc: str):
    text = f"{name} {desc}"
    for carrier in ["电信", "联通", "移动", "鹏博士", "BGP", "互联网"]:
        if carrier in text:
            return carrier
    return ""

def infer_link_name(name: str):
    text = str(name or "")
    for sep in ["利用率", "丢包", "错包", "BGP", "状态", "_100M", "_200M", "-入向", "-出向"]:
        if sep in text:
            text = text.split(sep)[0]
            break
    return text.strip("_- ")

def detect_family(name: str, query: str, desc: str):
    text = f"{name} {query} {desc}".lower()
    if any(k in text for k in ["bgp邻居", "ospf邻居", "bfd邻居"]):
        return "routing_neighbor_down"
    if "光功率" in f"{name}{desc}":
        return "optical_power_abnormal"
    if any(k in f"{name}{desc}" for k in ["丢包", "错包", "discard", "crc", "FC端口错误"]):
        return "interface_packet_loss_or_discards_high"
    if any(k in f"{name}{desc}" for k in ["利用率", "带宽"]):
        return "interface_or_link_utilization_high"
    if any(k in f"{name}{desc}" for k in ["连接数", "会话"]):
        return "connection_or_session_anomaly"
    if any(k in f"{name}{desc}" for k in ["风扇", "电源", "温度", "板卡", "机框", "主板", "处理器", "存储", "Flash"]):
        return "hardware_component_abnormal"
    if any(k in f"{name}{desc}" for k in ["CPU", "cpu"]):
        return "device_cpu_high"
    if any(k in f"{name}{desc}" for k in ["内存", "TMM"]):
        return "device_memory_high"
    if any(k in f"{name}{desc}" for k in ["DNS", "解析率", "请求率"]):
        return "dns_quality_or_traffic_anomaly"
    if any(k in f"{name}{desc}" for k in ["down", "flap", "状态"]) and ("interface" in text or "端口" in f"{name}{desc}" or "OperState" in query):
        return "interface_status_or_flap"
    return "generic_network_readonly"

def infer_vendor_hint(name: str, query: str, file_name: str, sample_jobs):
    text = f"{name} {query} {file_name} {' '.join(sample_jobs)}".lower()
    if "fortigate" in text or "fg" in text:
        return "fortigate"
    if "hillstone" in text:
        return "hillstone"
    if "f5" in text or "ltm" in text or "gtm" in text or "dns-f5" in text:
        return "f5"
    if "huawei" in text:
        return "huawei"
    if "h3c" in text or "comware" in text:
        return "h3c"
    if "cimc" in text:
        return "cimc"
    if any(k in text for k in ["cisco", "nxos", "catalyst", "sw-cisco", "ios-xe"]):
        return "cisco"
    return "generic_network"

def load_inventory(path: Path):
    wb = load_workbook(path, data_only=True)
    ws = wb.active
    headers = [str(c.value).strip() if c.value is not None else "" for c in next(ws.iter_rows(min_row=1, max_row=1))]
    rows = []
    for row in ws.iter_rows(min_row=2, values_only=True):
        item = {headers[i]: row[i] for i in range(len(headers))}
        device_ip = str(item.get("hostname") or "").strip()
        rows.append({
            "site": str(item.get("idc") or "").strip(),
            "hostname": str(item.get("sysname") or "").strip(),
            "device_ip": device_ip,
            "vendor": str(item.get("vendor") or "").strip(),
            "platform": str(item.get("model") or item.get("os_family") or "").strip(),
            "os_family": str(item.get("os_family") or "").strip(),
            "role": str(item.get("role") or "").strip(),
            "ssh_port": str(item.get("ssh_port") or "22").strip(),
        })
    return rows

def build():
    rules_json = read_json(INPUT_DIR / "rules.txt")
    alerts_json = read_json(INPUT_DIR / "alerts.txt")
    targets_json = read_json(INPUT_DIR / "targets.txt")

    inventory_rows = load_inventory(INPUT_DIR / "device_inventory.xlsx")
    inventory_by_ip = {x["device_ip"]: x for x in inventory_rows if x["device_ip"]}

    target_rows = []
    for t in targets_json.get("data", {}).get("activeTargets", []):
        labels = t.get("labels", {}) or {}
        ip = str(labels.get("ip") or "").strip()
        job = str(labels.get("job") or "").strip()
        instance = str(labels.get("instance") or "").strip()
        target_rows.append({
            "ip": ip,
            "job": job,
            "instance": instance,
            "health": t.get("health", ""),
            "sysname": inventory_by_ip.get(ip, {}).get("hostname", ""),
            "vendor": inventory_by_ip.get(ip, {}).get("vendor", ""),
            "platform": inventory_by_ip.get(ip, {}).get("platform", ""),
            "site": inventory_by_ip.get(ip, {}).get("site", ""),
        })

    alerts_by_name = defaultdict(list)
    for a in alerts_json.get("data", {}).get("alerts", []):
        alerts_by_name[str(a.get("name") or "")].append(a)

    layer1 = {
        "layer1_alert_families": {
            "interface_or_link_utilization_high": {
                "layer1_name": "接口/链路利用率过高",
                "playbook_seed": "interface_or_link_utilization_high",
            },
            "interface_packet_loss_or_discards_high": {
                "layer1_name": "接口丢包/错包/丢弃异常",
                "playbook_seed": "interface_packet_loss_or_discards_high",
            },
            "interface_status_or_flap": {
                "layer1_name": "接口状态/抖动异常",
                "playbook_seed": "interface_status_or_flap",
            },
            "routing_neighbor_down": {
                "layer1_name": "路由邻居异常",
                "playbook_seed": "routing_neighbor_down",
            },
            "device_cpu_high": {
                "layer1_name": "CPU 利用率过高",
                "playbook_seed": "device_cpu_high",
            },
            "device_memory_high": {
                "layer1_name": "内存利用率过高",
                "playbook_seed": "device_memory_high",
            },
            "hardware_component_abnormal": {
                "layer1_name": "硬件部件异常",
                "playbook_seed": "hardware_component_abnormal",
            },
            "optical_power_abnormal": {
                "layer1_name": "光功率异常",
                "playbook_seed": "optical_power_abnormal",
            },
            "connection_or_session_anomaly": {
                "layer1_name": "连接数/会话异常",
                "playbook_seed": "connection_or_session_anomaly",
            },
            "dns_quality_or_traffic_anomaly": {
                "layer1_name": "DNS 质量/流量异常",
                "playbook_seed": "dns_quality_or_traffic_anomaly",
            },
            "generic_network_readonly": {
                "layer1_name": "通用只读排障",
                "playbook_seed": "generic_network_readonly",
            },
        }
    }

    layer2 = []
    layer3 = []

    for group in rules_json.get("data", {}).get("groups", []):
        for rule in group.get("rules", []):
            name = str(rule.get("name") or "").strip()
            query = str(rule.get("query") or "").strip()
            file_name = os.path.basename(str(rule.get("file") or ""))
            desc = str((rule.get("annotations") or {}).get("description") or "").strip()
            severity = str((rule.get("labels") or {}).get("severity") or "").strip()

            sample_alerts = alerts_by_name.get(name, [])
            sample_jobs = []
            sample_keys = set()
            sample_label_values = {}
            for a in sample_alerts[:5]:
                labels = a.get("labels", {}) or {}
                sample_jobs.append(str(labels.get("job") or ""))
                for k,v in labels.items():
                    sample_keys.add(k)
                    if k not in sample_label_values and v not in (None, ""):
                        sample_label_values[k] = str(v)

            family = detect_family(name, query, desc)
            vendor_hint = infer_vendor_hint(name, query, file_name, sample_jobs)
            static_extract = {
                "ip_matchers": extract_list_from_query(query, "ip"),
                "ifname_matchers": extract_list_from_query(query, "ifName"),
                "instance_matchers": extract_list_from_query(query, "instance"),
                "job_matchers": extract_list_from_query(query, "job"),
            }
            runtime_templates = [k for k in ["ip","ifName","ifAlias","instance","job","monitor","sysName","hostname","vendor"] if k in sample_keys]
            layer2.append({
                "rule_id": f"{group.get('name','')}::{(rule.get('labels') or {}).get('group','')}::{name}",
                "match": {"alertname": name},
                "source_rule_file": file_name,
                "vendor_hint": vendor_hint,
                "family": family,
                "playbook_type": family,
                "severity": severity,
                "job_patterns": [x for x in (static_extract["job_matchers"] + sample_jobs) if x],
                "notes": desc,
                "runtime_label_templates": runtime_templates,
            })

            layer3.append({
                "rule_id": f"{group.get('name','')}::{(rule.get('labels') or {}).get('group','')}::{name}",
                "alertname": name,
                "source_rule_file": file_name,
                "vendor_hint": vendor_hint,
                "family": family,
                "enrichment_strategy": "hybrid_rule_expr_plus_runtime_labels",
                "static_extract": static_extract,
                "runtime_label_templates": runtime_templates,
                "direction": infer_direction(name, desc),
                "carrier": infer_carrier(name, desc),
                "link_name": infer_link_name(name),
                "sample_label_values": sample_label_values,
                "recommended_next_action": "优先使用 runtime labels，其次回退到 query/generatorURL 静态提取",
            })

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUT_DIR / "layer1_alert_families.enhanced.yaml", "w", encoding="utf-8") as f:
        yaml.safe_dump(layer1, f, allow_unicode=True, sort_keys=False)
    with open(OUT_DIR / "layer2_classifier_mapping.enhanced.yaml", "w", encoding="utf-8") as f:
        yaml.safe_dump({"layer2_classifier_mapping": layer2}, f, allow_unicode=True, sort_keys=False)
    with open(OUT_DIR / "layer3_context_enrichment.enhanced.yaml", "w", encoding="utf-8") as f:
        yaml.safe_dump({"layer3_context_enrichment": layer3}, f, allow_unicode=True, sort_keys=False)
    with open(OUT_DIR / "device_inventory.normalized.yaml", "w", encoding="utf-8") as f:
        yaml.safe_dump({"devices": inventory_rows}, f, allow_unicode=True, sort_keys=False)
    with open(OUT_DIR / "target_lookup.yaml", "w", encoding="utf-8") as f:
        yaml.safe_dump({"targets": target_rows}, f, allow_unicode=True, sort_keys=False)

    print("generated:")
    print(OUT_DIR / "layer1_alert_families.enhanced.yaml")
    print(OUT_DIR / "layer2_classifier_mapping.enhanced.yaml")
    print(OUT_DIR / "layer3_context_enrichment.enhanced.yaml")
    print(OUT_DIR / "device_inventory.normalized.yaml")
    print(OUT_DIR / "target_lookup.yaml")

if __name__ == "__main__":
    build()
PY

cat > "${TOOLS_DIR}/extract_config_desc_index.py" <<'PY'
import json
import re
import zipfile
from pathlib import Path

BASE_DIR = Path("/opt/netaiops-webhook")
INPUT_DIR = BASE_DIR / "input" / "monitoring"
OUT_DIR = BASE_DIR / "catalogs" / "three_layer"

CFG_ZIP = INPUT_DIR / "device_configs.zip"

def parse():
    records = []
    with zipfile.ZipFile(CFG_ZIP, "r") as zf:
        for name in zf.namelist():
            if not name.lower().endswith(".txt"):
                continue
            base = Path(name).name
            m = re.match(r"(.+?)_(\d+\.\d+\.\d+\.\d+)_", base)
            sysname = m.group(1) if m else ""
            mgmt_ip = m.group(2) if m else ""
            try:
                text = zf.read(name).decode("utf-8", errors="ignore")
            except Exception:
                continue

            cur_intf = ""
            cur_desc = ""
            cur_ips = []
            for line in text.splitlines():
                raw = line.rstrip("\n")
                s = raw.strip()
                m_if = re.match(r"^interface\s+(.+)$", s, flags=re.IGNORECASE)
                if m_if:
                    if cur_intf and (cur_desc or cur_ips):
                        records.append({
                            "sysname": sysname,
                            "mgmt_ip": mgmt_ip,
                            "interface": cur_intf,
                            "description": cur_desc,
                            "ipv4_addresses": cur_ips,
                            "source_file": name,
                        })
                    cur_intf = m_if.group(1).strip()
                    cur_desc = ""
                    cur_ips = []
                    continue
                if cur_intf:
                    m_desc = re.match(r"^description\s+(.+)$", s, flags=re.IGNORECASE)
                    if m_desc:
                        cur_desc = m_desc.group(1).strip()
                    m_ip = re.search(r"\bip address\s+(\d+\.\d+\.\d+\.\d+)\b", s, flags=re.IGNORECASE)
                    if m_ip:
                        cur_ips.append(m_ip.group(1))
                    if s in ("!", "#", "return"):
                        if cur_intf and (cur_desc or cur_ips):
                            records.append({
                                "sysname": sysname,
                                "mgmt_ip": mgmt_ip,
                                "interface": cur_intf,
                                "description": cur_desc,
                                "ipv4_addresses": cur_ips,
                                "source_file": name,
                            })
                        cur_intf = ""
                        cur_desc = ""
                        cur_ips = []
            if cur_intf and (cur_desc or cur_ips):
                records.append({
                    "sysname": sysname,
                    "mgmt_ip": mgmt_ip,
                    "interface": cur_intf,
                    "description": cur_desc,
                    "ipv4_addresses": cur_ips,
                    "source_file": name,
                })
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / "config_interface_index.json"
    out.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
    print(out)

if __name__ == "__main__":
    parse()
PY

python "${TOOLS_DIR}/build_three_layer_enhanced.py"
python "${TOOLS_DIR}/extract_config_desc_index.py"

cat > "${NETAIOPS_DIR}/context_catalog.py" <<'PY'
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
PY

for f in normalizers.py classifier.py playbook_loader.py; do
  if [ -f "${NETAIOPS_DIR}/${f}" ]; then
    cp "${NETAIOPS_DIR}/${f}" "${BACKUP_DIR}/${f}.bak"
  fi
done

cat > "${NETAIOPS_DIR}/normalizers.py" <<'PY'
import re
from datetime import datetime, timezone

from netaiops.context_catalog import enrich_event_from_catalog

def now_utc_str() -> str:
    return datetime.now(timezone.utc).isoformat()

def extract_ip(text: str) -> str:
    if not text:
        return ""
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(text))
    return match.group(0) if match else ""

def normalize_alertmanager(payload: dict) -> list:
    events = []

    alerts = payload.get("alerts", [])
    common_labels = payload.get("commonLabels", {}) or {}
    common_annotations = payload.get("commonAnnotations", {}) or {}

    for alert in alerts:
        labels = alert.get("labels", {}) or {}
        annotations = alert.get("annotations", {}) or {}

        merged_labels = {**common_labels, **labels}
        merged_annotations = {**common_annotations, **annotations}

        raw_text = " ".join(
            [
                str(merged_labels.get("alertname", "")),
                str(merged_annotations.get("summary", "")),
                str(merged_annotations.get("description", "")),
            ]
        ).strip()

        event = {
            "source": "alertmanager",
            "timestamp": alert.get("startsAt") or now_utc_str(),
            "alarm_type": merged_labels.get("alertname", ""),
            "severity": merged_labels.get("severity", ""),
            "status": alert.get("status", payload.get("status", "")),
            "hostname": merged_labels.get("instance", "") or merged_labels.get("hostname", ""),
            "device_ip": merged_labels.get("ip", "") or extract_ip(
                merged_labels.get("instance", "") or merged_annotations.get("description", "") or raw_text
            ),
            "vendor": merged_labels.get("vendor", ""),
            "object_type": merged_labels.get("job", "") or merged_labels.get("type", ""),
            "object_name": merged_labels.get("interface", "") or merged_labels.get("name", ""),
            "raw_text": raw_text,
            "labels": merged_labels,
            "annotations": merged_annotations,
            "generator_url": alert.get("generatorURL", ""),
            "expression": alert.get("expression", ""),
        }
        event = enrich_event_from_catalog(event)
        events.append(event)

    return events

def normalize_elastic(payload: dict) -> list:
    events = []

    hits = (((payload or {}).get("hits") or {}).get("hits") or [])
    if not hits and isinstance(payload, dict):
        src = payload.get("_source")
        if src:
            hits = [payload]

    for hit in hits:
        source_data = hit.get("_source", {}) if isinstance(hit, dict) else {}
        message = str(source_data.get("message", "") or source_data.get("log", "") or "")

        host_obj = source_data.get("host", {})
        if not isinstance(host_obj, dict):
            host_obj = {}

        agent_obj = source_data.get("agent", {})
        if not isinstance(agent_obj, dict):
            agent_obj = {}

        observer_obj = source_data.get("observer", {})
        if not isinstance(observer_obj, dict):
            observer_obj = {}

        event_obj = source_data.get("event", {})
        if not isinstance(event_obj, dict):
            event_obj = {}

        log_obj = source_data.get("log", {})
        if not isinstance(log_obj, dict):
            log_obj = {}

        rule_obj = source_data.get("rule", {})
        if not isinstance(rule_obj, dict):
            rule_obj = {}

        hostname = (
            host_obj.get("name", "")
            or source_data.get("host", "")
            or agent_obj.get("name", "")
        )

        vendor = (
            source_data.get("vendor", "")
            or observer_obj.get("vendor", "")
        )

        event = {
            "source": "elastic",
            "timestamp": source_data.get("@timestamp", now_utc_str()),
            "alarm_type": event_obj.get("kind", "") or rule_obj.get("name", ""),
            "severity": log_obj.get("level", ""),
            "status": event_obj.get("outcome", ""),
            "hostname": hostname,
            "device_ip": source_data.get("ip", "") or extract_ip(message),
            "vendor": vendor,
            "object_type": event_obj.get("category", ""),
            "object_name": rule_obj.get("name", ""),
            "raw_text": message,
            "labels": source_data,
            "annotations": {},
            "expression": "",
            "generator_url": "",
        }
        event = enrich_event_from_catalog(event)
        events.append(event)

    return events
PY

cat > "${NETAIOPS_DIR}/classifier.py" <<'PY'
from typing import Any, Dict

from netaiops.context_catalog import classify_event_by_catalog

def _safe_lower(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()

def classify_event(event: Dict[str, Any]) -> Dict[str, Any]:
    catalog_result = classify_event_by_catalog(event)
    if catalog_result:
        return catalog_result

    vendor = _safe_lower(event.get("vendor"))
    alarm_type = _safe_lower(event.get("alarm_type") or event.get("event_type"))
    severity = _safe_lower(event.get("severity"))
    metric_name = _safe_lower(event.get("metric_name"))
    source = _safe_lower(event.get("source"))

    object_type = _safe_lower(event.get("object_type"))
    object_name = _safe_lower(event.get("object_name"))
    raw_text = _safe_lower(event.get("raw_text"))
    status = _safe_lower(event.get("status"))

    playbook_type = "generic_network_readonly"
    confidence = "low"
    auto_execute_allowed = False
    prompt_profile = "quick"
    match_reason = "default_generic"

    if "bgp" in alarm_type and ("down" in alarm_type or "peer" in alarm_type):
        playbook_type = "bgp_neighbor_down"
        confidence = "high"
        auto_execute_allowed = True
        match_reason = "matched_alarm_type_bgp_neighbor_down"

    elif "ospf" in alarm_type and "down" in alarm_type:
        playbook_type = "ospf_neighbor_down"
        confidence = "high"
        auto_execute_allowed = True
        match_reason = "matched_alarm_type_ospf_neighbor_down"

    elif "bfd" in alarm_type and ("down" in alarm_type or "neighbor" in alarm_type):
        playbook_type = "routing_neighbor_down"
        confidence = "high"
        auto_execute_allowed = True
        match_reason = "matched_alarm_type_bfd_neighbor_down"

    elif "interface" in alarm_type and ("flap" in alarm_type or "down" in alarm_type):
        playbook_type = "interface_flap"
        confidence = "medium"
        auto_execute_allowed = True
        match_reason = "matched_alarm_type_interface_flap"

    elif "pool" in alarm_type and "down" in alarm_type:
        playbook_type = "f5_pool_member_down"
        confidence = "medium"
        auto_execute_allowed = True
        match_reason = "matched_alarm_type_f5_pool_member_down"

    elif "bgp" in raw_text and ("idle" in raw_text or "down" in raw_text):
        playbook_type = "bgp_neighbor_down"
        confidence = "medium"
        auto_execute_allowed = True
        match_reason = "matched_raw_text_bgp_neighbor_down"

    elif "ospf" in raw_text and ("down" in raw_text or "neighbor" in raw_text):
        playbook_type = "ospf_neighbor_down"
        confidence = "medium"
        auto_execute_allowed = True
        match_reason = "matched_raw_text_ospf"

    elif "interface" in raw_text and ("down" in raw_text or "flap" in raw_text):
        playbook_type = "interface_flap"
        confidence = "medium"
        auto_execute_allowed = True
        match_reason = "matched_raw_text_interface"

    elif "pool member" in raw_text and "down" in raw_text:
        playbook_type = "f5_pool_member_down"
        confidence = "medium"
        auto_execute_allowed = True
        match_reason = "matched_raw_text_pool_member_down"

    if status == "resolved":
        auto_execute_allowed = False
        match_reason = f"{match_reason}_resolved"

    if severity in ("critical", "major", "error"):
        prompt_profile = "detailed"
    elif severity in ("warning", "minor"):
        prompt_profile = "quick"

    return {
        "vendor": vendor,
        "source": source,
        "alarm_type": alarm_type,
        "severity": severity,
        "metric_name": metric_name,
        "object_type": object_type,
        "object_name": object_name,
        "playbook_type": playbook_type,
        "prompt_profile": prompt_profile,
        "auto_execute_allowed": auto_execute_allowed,
        "classification_confidence": confidence,
        "match_reason": match_reason,
    }
PY

cat > "${NETAIOPS_DIR}/playbook_loader.py" <<'PY'
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
PY

cat > "${PLAYBOOK_DIR}/cisco_interface_or_link_utilization_high.yaml" <<'YAML'
playbook_id: cisco_interface_or_link_utilization_high
match:
  vendor: cisco
  playbook_type: interface_or_link_utilization_high
execution:
  commands:
    - "show interface {interface_each}"
    - "show interface {interface_each} counters"
    - "show interface description | include {interface_each}"
    - "show logging | include {interface_each}|LINK|LINEPROTO"
    - "show processes cpu sort"
YAML

cat > "${PLAYBOOK_DIR}/h3c_interface_or_link_utilization_high.yaml" <<'YAML'
playbook_id: h3c_interface_or_link_utilization_high
match:
  vendor: h3c
  playbook_type: interface_or_link_utilization_high
execution:
  commands:
    - "display interface {interface_each}"
    - "display interface brief | include {interface_each}"
    - "display current-configuration interface {interface_each}"
    - "display logbuffer | include {interface_each}"
    - "display cpu-usage"
YAML

cat > "${PLAYBOOK_DIR}/cisco_interface_packet_loss_or_discards_high.yaml" <<'YAML'
playbook_id: cisco_interface_packet_loss_or_discards_high
match:
  vendor: cisco
  playbook_type: interface_packet_loss_or_discards_high
execution:
  commands:
    - "show interface {interface_each}"
    - "show interface {interface_each} counters errors"
    - "show interface description | include {interface_each}"
    - "show logging | include {interface_each}|CRC|error|discard"
    - "show processes cpu sort"
YAML

cat > "${PLAYBOOK_DIR}/h3c_interface_packet_loss_or_discards_high.yaml" <<'YAML'
playbook_id: h3c_interface_packet_loss_or_discards_high
match:
  vendor: h3c
  playbook_type: interface_packet_loss_or_discards_high
execution:
  commands:
    - "display interface {interface_each}"
    - "display interface brief | include {interface_each}"
    - "display counters interface {interface_each}"
    - "display logbuffer | include {interface_each}|error|discard|crc"
    - "display cpu-usage"
YAML

cat > "${PLAYBOOK_DIR}/cisco_device_cpu_high.yaml" <<'YAML'
playbook_id: cisco_device_cpu_high
match:
  vendor: cisco
  playbook_type: device_cpu_high
execution:
  commands:
    - "show processes cpu sort"
    - "show processes cpu history"
    - "show system resources"
    - "show logging | include CPU|HOG|Process"
YAML

python -m py_compile "${TOOLS_DIR}/build_three_layer_enhanced.py"
python -m py_compile "${TOOLS_DIR}/extract_config_desc_index.py"
python -m py_compile "${NETAIOPS_DIR}/context_catalog.py"
python -m py_compile "${NETAIOPS_DIR}/normalizers.py"
python -m py_compile "${NETAIOPS_DIR}/classifier.py"
python -m py_compile "${NETAIOPS_DIR}/playbook_loader.py"

echo
echo "==> phase1 files generated successfully"
echo "    catalogs: ${CAT_DIR}"
echo "    backups : ${BACKUP_DIR}"
echo
echo "==> next:"
echo "    sudo systemctl restart netaiops-webhook"
echo "    sudo systemctl status netaiops-webhook --no-pager"
echo "    ls -lt ${CAT_DIR} | head"
