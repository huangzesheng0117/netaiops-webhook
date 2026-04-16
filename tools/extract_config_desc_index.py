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
