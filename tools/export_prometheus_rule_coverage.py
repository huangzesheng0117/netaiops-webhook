#!/usr/bin/env python3
import argparse
import json
import re
import sys
import zipfile
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple
from xml.sax.saxutils import escape, quoteattr

BASE_DIR = Path("/opt/netaiops-webhook")
DEFAULT_OUTPUT = BASE_DIR / "docs" / "webhook_v5_prometheus_rule_coverage.xlsx"

sys.path.insert(0, str(BASE_DIR))


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value).strip()


def to_plain(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: to_plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_plain(x) for x in value]
    if hasattr(value, "__dict__"):
        return {k: to_plain(v) for k, v in value.__dict__.items() if not k.startswith("_")}
    return value


def load_current_registry() -> Dict[str, Any]:
    out = {
        "families": set(),
        "capabilities": {},
        "platform_matrix": {},
    }

    try:
        import netaiops.capability_registry as cr
        cap = getattr(cr, "CAPABILITY_REGISTRY", {}) or {}
        if isinstance(cap, dict):
            out["capabilities"] = cap
    except Exception:
        pass

    try:
        import netaiops.platform_command_matrix as pm
        matrix = getattr(pm, "PLATFORM_COMMAND_MATRIX", {}) or {}
        if isinstance(matrix, dict):
            out["platform_matrix"] = matrix
    except Exception:
        pass

    known_families = {
        "interface_or_link_utilization_high",
        "interface_or_link_traffic_drop",
        "interface_packet_loss_or_discards_high",
        "interface_status_or_flap",
        "interface_flap",
        "bgp_neighbor_down",
        "ospf_neighbor_down",
        "routing_neighbor_down",
        "device_cpu_high",
        "device_memory_high",
        "f5_pool_member_down",
        "generic_network_readonly",
    }

    try:
        import netaiops.family_registry as fr

        for name, value in vars(fr).items():
            if name.startswith("_"):
                continue
            value = to_plain(value)
            if isinstance(value, dict):
                for key, item in value.items():
                    if isinstance(key, str) and "_" in key:
                        known_families.add(key)
                    if isinstance(item, dict):
                        fam = safe_text(item.get("family") or item.get("name") or item.get("id"))
                        if fam:
                            known_families.add(fam)
            elif isinstance(value, (list, set, tuple)):
                for item in value:
                    if isinstance(item, str) and "_" in item:
                        known_families.add(item)
                    elif isinstance(item, dict):
                        fam = safe_text(item.get("family") or item.get("name") or item.get("id"))
                        if fam:
                            known_families.add(fam)
    except Exception:
        pass

    out["families"] = known_families
    return out


def try_load_json(path: Path) -> Any:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return {}

    try:
        return json.loads(text)
    except Exception:
        pass

    # 有些导出是多段 JSON 拼接，尝试包一层数组。
    try:
        return json.loads("[" + text.replace("}\n{", "},{") + "]")
    except Exception:
        pass

    return {"_raw_text": text}


def walk_objects(obj: Any) -> List[Dict[str, Any]]:
    found = []

    if isinstance(obj, dict):
        if any(k in obj for k in ("name", "alert", "alertname")) and any(k in obj for k in ("query", "expr", "expression", "alerts", "labels", "annotations")):
            found.append(obj)

        for value in obj.values():
            found.extend(walk_objects(value))

    elif isinstance(obj, list):
        for item in obj:
            found.extend(walk_objects(item))

    return found


def parse_rules_from_raw_text(text: str) -> List[Dict[str, Any]]:
    rules = []

    # 尽量从 vmalert JSON 文本中抓取每个规则对象的常用字段。
    pattern = re.compile(
        r'"name"\s*:\s*"(?P<name>(?:\\.|[^"\\])*)".{0,4000}?'
        r'(?:"query"|"expr"|"expression")\s*:\s*"(?P<query>(?:\\.|[^"\\])*)".{0,4000}?'
        r'"file"\s*:\s*"(?P<file>(?:\\.|[^"\\])*)"',
        flags=re.DOTALL,
    )

    for m in pattern.finditer(text):
        name = bytes(m.group("name"), "utf-8").decode("unicode_escape")
        query = bytes(m.group("query"), "utf-8").decode("unicode_escape")
        file_name = bytes(m.group("file"), "utf-8").decode("unicode_escape")
        rules.append(
            {
                "name": name,
                "query": query,
                "file": file_name,
                "labels": {},
                "annotations": {},
                "state": "",
                "raw_source": "regex",
            }
        )

    return rules


def extract_rule_records(path: Path) -> List[Dict[str, Any]]:
    data = try_load_json(path)
    raw_text = path.read_text(encoding="utf-8", errors="replace")

    objects = walk_objects(data)

    records = []
    seen = set()

    for obj in objects:
        name = safe_text(obj.get("name") or obj.get("alert") or obj.get("alertname"))
        query = safe_text(obj.get("query") or obj.get("expr") or obj.get("expression"))
        labels = obj.get("labels", {}) or {}
        annotations = obj.get("annotations", {}) or {}

        description = ""
        if isinstance(annotations, dict):
            description = safe_text(annotations.get("description") or annotations.get("summary"))

        file_name = safe_text(obj.get("file"))
        group_name = safe_text(obj.get("group_name") or obj.get("group"))
        state = safe_text(obj.get("state"))
        severity = ""
        if isinstance(labels, dict):
            severity = safe_text(labels.get("severity"))

        rule_id = safe_text(obj.get("rule_id") or obj.get("id"))

        if not name and isinstance(labels, dict):
            name = safe_text(labels.get("alertname"))

        if not query:
            query = safe_text(obj.get("expression"))

        if not name and not query:
            continue

        key = (name, query, file_name, rule_id)
        if key in seen:
            continue
        seen.add(key)

        records.append(
            {
                "rule_id": rule_id,
                "name": name,
                "state": state,
                "severity": severity,
                "group_name": group_name,
                "file": file_name,
                "query": query,
                "description": description,
                "labels": labels,
                "annotations": annotations,
                "datasourceType": safe_text(obj.get("datasourceType")),
                "source": safe_text(obj.get("source")),
            }
        )

    if not records and isinstance(data, dict) and data.get("_raw_text"):
        records = parse_rules_from_raw_text(raw_text)

    if not records:
        records = parse_rules_from_raw_text(raw_text)

    return records


def norm(s: Any) -> str:
    return safe_text(s).lower()


def text_blob(rule: Dict[str, Any]) -> str:
    return " ".join(
        [
            safe_text(rule.get("name")),
            safe_text(rule.get("description")),
            safe_text(rule.get("query")),
            safe_text(rule.get("file")),
            safe_text(rule.get("labels")),
            safe_text(rule.get("annotations")),
        ]
    ).lower()


def infer_family(rule: Dict[str, Any]) -> str:
    t = text_blob(rule)

    if any(x in t for x in ["利用率-入向", "利用率-出向", "utilization", "ifhcinoctets", "ifhcoutoctets", "ifinutil", "ifoututil", "吞吐量"]):
        if "f5" in t and ("connection" in t or "sysclient" in t or "活跃连接" in t or "连接数" in t):
            return "f5_connection_rate_anomaly"
        if "dns" in t:
            return "dns_request_rate_anomaly"
        return "interface_or_link_utilization_high"

    if any(x in t for x in ["流量突降", "traffic drop", "突降", "低于"]):
        return "interface_or_link_traffic_drop"

    if any(x in t for x in ["丢包", "discard", "error packet", "错包", "crc", "ifindiscards", "ifouterrors", "ifinerrors", "ifoutdiscards"]):
        return "interface_packet_loss_or_discards_high"

    if any(x in t for x in ["端口down", "接口down", "link down", "operstatus", "ifoperstatus", "接口状态"]):
        return "interface_status_or_flap"

    if any(x in t for x in ["bgp", "peer down", "邻居down"]):
        return "bgp_neighbor_down"

    if any(x in t for x in ["ospf"]):
        return "ospf_neighbor_down"

    if any(x in t for x in ["cpu", "处理器"]):
        return "device_cpu_high"

    if any(x in t for x in ["memory", "内存"]):
        return "device_memory_high"

    if any(x in t for x in ["disk", "磁盘"]):
        return "device_disk_high"

    if any(x in t for x in ["风扇", "fan", "cefcfantrayoperstatus", "syschassisfanstatus"]):
        return "hardware_fan_abnormal"

    if any(x in t for x in ["电源", "power", "powersupply", "cefcfrupoweroperstatus", "syschassispowersupplystatus"]):
        return "hardware_power_abnormal"

    if any(x in t for x in ["温度", "temperature", "temp", "entphyssensortemperature"]):
        return "hardware_temperature_high"

    if any(x in t for x in ["光功率", "ddm", "rxdbm", "txdbm", "receive power", "transmit power", "entsensorvalue"]):
        return "optical_power_abnormal"

    if any(x in t for x in ["板卡", "slot", "module", "chassis", "syschassisslot", "cluster", "ha state", "hastate"]):
        if "ha" in t or "cluster" in t:
            return "ha_or_cluster_state_abnormal"
        return "chassis_slot_or_module_abnormal"

    if "dns" in t and any(x in t for x in ["请求", "request", "qps", "query"]):
        return "dns_request_rate_anomaly"

    if "dns" in t and any(x in t for x in ["响应", "response", "answer"]):
        return "dns_response_rate_anomaly"

    if "f5" in t and any(x in t for x in ["pool", "member"]):
        return "f5_pool_member_down"

    if "f5" in t and any(x in t for x in ["连接", "connection", "conn"]):
        return "f5_connection_rate_anomaly"

    if any(x in t for x in ["主备", "ha", "failover", "cluster"]):
        return "ha_or_cluster_state_abnormal"

    if any(x in t for x in ["cimc", "主板", "storage controller", "controller", "processor", "psu"]):
        return "cimc_hardware_abnormal"

    return "generic_network_readonly"


SUGGESTED_CAPABILITIES = {
    "hardware_fan_abnormal": ["show_device_environment", "show_fan_status", "query_prometheus_metric_window"],
    "hardware_power_abnormal": ["show_device_environment", "show_power_status", "query_prometheus_metric_window"],
    "hardware_temperature_high": ["show_environment_temperature", "query_prometheus_metric_window"],
    "chassis_slot_or_module_abnormal": ["show_chassis_status", "show_module_status", "show_inventory", "query_prometheus_metric_window"],
    "optical_power_abnormal": ["show_interface_transceiver", "show_interface_detail", "query_prometheus_metric_window"],
    "device_disk_high": ["show_device_disk", "query_prometheus_metric_window"],
    "dns_request_rate_anomaly": ["query_prometheus_metric_window", "query_elastic_related_logs"],
    "dns_response_rate_anomaly": ["query_prometheus_metric_window", "query_elastic_related_logs"],
    "f5_connection_rate_anomaly": ["show_f5_connections", "show_f5_performance", "query_prometheus_metric_window"],
    "ha_or_cluster_state_abnormal": ["show_ha_state", "query_prometheus_metric_window", "query_elastic_related_logs"],
    "cimc_hardware_abnormal": ["show_cimc_hardware_status", "query_prometheus_metric_window"],
    "interface_or_link_utilization_high": ["show_interface_detail", "show_interface_error_counters", "show_portchannel_summary", "query_prometheus_metric_window"],
    "interface_or_link_traffic_drop": ["show_interface_detail", "show_interface_error_counters", "show_portchannel_summary", "query_prometheus_metric_window"],
    "interface_packet_loss_or_discards_high": ["show_interface_detail", "show_interface_error_counters", "show_portchannel_summary", "query_prometheus_metric_window"],
    "interface_status_or_flap": ["show_interface_detail", "show_interface_brief", "show_portchannel_summary", "query_elastic_related_logs"],
    "bgp_neighbor_down": ["show_bgp_peer_detail", "show_route_to_peer", "ping_peer", "show_interface_brief", "show_bgp_config_snippet"],
    "ospf_neighbor_down": ["show_ospf_peer_detail", "show_interface_brief", "query_elastic_related_logs"],
    "device_cpu_high": ["show_device_cpu", "query_prometheus_metric_window"],
    "device_memory_high": ["show_device_memory", "query_prometheus_metric_window"],
    "f5_pool_member_down": ["show_f5_pool_list", "show_f5_pool_members", "show_f5_pool_config", "show_f5_connections", "show_f5_performance"],
}


def classify_coverage(rule: Dict[str, Any], current_families: set, current_capabilities: Dict[str, Any]) -> Dict[str, Any]:
    fam = infer_family(rule)
    suggested_caps = SUGGESTED_CAPABILITIES.get(fam, [])
    missing_caps = [x for x in suggested_caps if x not in current_capabilities]

    family_exists = fam in current_families
    if family_exists and not missing_caps:
        status = "covered_family_and_capability"
    elif family_exists and missing_caps:
        status = "family_exists_capability_missing"
    else:
        status = "family_missing"

    needs_mcp = any(x.startswith("show_") or x in ("ping_peer",) for x in suggested_caps)
    needs_prom = "query_prometheus_metric_window" in suggested_caps
    needs_elastic = "query_elastic_related_logs" in suggested_caps

    priority = "P2"
    if fam in (
        "hardware_fan_abnormal",
        "hardware_power_abnormal",
        "hardware_temperature_high",
        "chassis_slot_or_module_abnormal",
        "optical_power_abnormal",
        "device_disk_high",
        "ha_or_cluster_state_abnormal",
    ):
        priority = "P1"
    if fam in (
        "interface_or_link_utilization_high",
        "interface_or_link_traffic_drop",
        "interface_packet_loss_or_discards_high",
        "interface_status_or_flap",
        "bgp_neighbor_down",
        "ospf_neighbor_down",
        "device_cpu_high",
        "device_memory_high",
        "f5_pool_member_down",
    ):
        priority = "P0"
    if fam in ("cimc_hardware_abnormal",):
        priority = "P3"

    return {
        "recommended_family": fam,
        "family_exists": family_exists,
        "suggested_capabilities": suggested_caps,
        "missing_capabilities": missing_caps,
        "coverage_status": status,
        "need_mcp": needs_mcp,
        "need_prometheus": needs_prom,
        "need_elastic": needs_elastic,
        "priority": priority,
    }


def col_letter(n: int) -> str:
    s = ""
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def cell_ref(row: int, col: int) -> str:
    return f"{col_letter(col)}{row}"


def sheet_name_safe(name: str) -> str:
    name = re.sub(r"[:\\/?*\[\]]", "_", name)
    return name[:31] or "Sheet"


def estimate_width(rows: List[List[Any]], col_idx: int) -> float:
    max_len = 8
    for row in rows[:500]:
        if col_idx < len(row):
            value = safe_text(row[col_idx])
            visual_len = 0
            for ch in value:
                visual_len += 2 if ord(ch) > 127 else 1
            max_len = max(max_len, min(80, visual_len))
    return max(10, min(60, max_len + 2))


def sheet_xml(rows: List[List[Any]]) -> str:
    row_count = len(rows)
    col_count = max((len(r) for r in rows), default=1)
    last_ref = f"{col_letter(col_count)}{max(row_count, 1)}"

    cols_xml = ["<cols>"]
    for c in range(1, col_count + 1):
        cols_xml.append(f'<col min="{c}" max="{c}" width="{estimate_width(rows, c - 1):.1f}" customWidth="1"/>')
    cols_xml.append("</cols>")

    sheet_data = ["<sheetData>"]
    for r_idx, row in enumerate(rows, start=1):
        sheet_data.append(f'<row r="{r_idx}">')
        for c_idx in range(1, col_count + 1):
            value = row[c_idx - 1] if c_idx - 1 < len(row) else ""
            ref = cell_ref(r_idx, c_idx)
            style = 1 if r_idx == 1 else 0
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                sheet_data.append(f'<c r="{ref}" s="{style}"><v>{value}</v></c>')
            else:
                text = escape(safe_text(value))
                sheet_data.append(f'<c r="{ref}" t="inlineStr" s="{style}"><is><t xml:space="preserve">{text}</t></is></c>')
        sheet_data.append("</row>")
    sheet_data.append("</sheetData>")

    freeze = (
        '<sheetViews><sheetView workbookViewId="0">'
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
        '</sheetView></sheetViews>'
    )

    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        + freeze
        + "".join(cols_xml)
        + "".join(sheet_data)
        + f'<autoFilter ref="A1:{last_ref}"/>'
        + "</worksheet>"
    )


def workbook_xml(sheet_names: List[str]) -> str:
    sheets = []
    for idx, name in enumerate(sheet_names, start=1):
        sheets.append(f'<sheet name={quoteattr(name)} sheetId="{idx}" r:id="rId{idx}"/>')
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        "<sheets>" + "".join(sheets) + "</sheets></workbook>"
    )


def workbook_rels_xml(sheet_count: int) -> str:
    rels = []
    for idx in range(1, sheet_count + 1):
        rels.append(
            f'<Relationship Id="rId{idx}" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            f'Target="worksheets/sheet{idx}.xml"/>'
        )
    rels.append(
        f'<Relationship Id="rId{sheet_count + 1}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(rels)
        + "</Relationships>"
    )


def root_rels_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        "</Relationships>"
    )


def content_types_xml(sheet_count: int) -> str:
    parts = [
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
        '<Default Extension="xml" ContentType="application/xml"/>',
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>',
    ]
    for idx in range(1, sheet_count + 1):
        parts.append(
            f'<Override PartName="/xl/worksheets/sheet{idx}.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        + "".join(parts)
        + "</Types>"
    )


def styles_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="2">'
        '<font><sz val="11"/><name val="Calibri"/></font>'
        '<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>'
        '</fonts>'
        '<fills count="3">'
        '<fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FF1F4E78"/><bgColor indexed="64"/></patternFill></fill>'
        '</fills>'
        '<borders count="2">'
        '<border><left/><right/><top/><bottom/><diagonal/></border>'
        '<border><left style="thin"/><right style="thin"/><top style="thin"/><bottom style="thin"/><diagonal/></border>'
        '</borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="2">'
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0"><alignment vertical="top" wrapText="1"/></xf>'
        '<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf>'
        '</cellXfs>'
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        '</styleSheet>'
    )


def save_xlsx(sheets: List[Tuple[str, List[List[Any]]]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    sheet_names = [sheet_name_safe(name) for name, _ in sheets]

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types_xml(len(sheets)))
        z.writestr("_rels/.rels", root_rels_xml())
        z.writestr("xl/workbook.xml", workbook_xml(sheet_names))
        z.writestr("xl/_rels/workbook.xml.rels", workbook_rels_xml(len(sheets)))
        z.writestr("xl/styles.xml", styles_xml())

        for idx, (_, rows) in enumerate(sheets, start=1):
            z.writestr(f"xl/worksheets/sheet{idx}.xml", sheet_xml(rows))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules", required=True)
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()

    rules_path = Path(args.rules)
    output_path = Path(args.output)

    if not rules_path.exists():
        raise SystemExit(f"ERROR: rules file not found: {rules_path}")

    registry = load_current_registry()
    current_families = registry["families"]
    current_capabilities = registry["capabilities"]

    rules = extract_rule_records(rules_path)

    enriched = []
    for rule in rules:
        coverage = classify_coverage(rule, current_families, current_capabilities)
        enriched.append({**rule, **coverage})

    coverage_counter = Counter(x["coverage_status"] for x in enriched)
    family_counter = Counter(x["recommended_family"] for x in enriched)
    priority_counter = Counter(x["priority"] for x in enriched)

    readme_rows = [
        ["项目", "内容"],
        ["导出时间", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["rules文件", str(rules_path)],
        ["输出文件", str(output_path)],
        ["规则数量", len(enriched)],
        ["当前代码family数量", len(current_families)],
        ["当前代码capability数量", len(current_capabilities)],
        ["covered_family_and_capability", coverage_counter.get("covered_family_and_capability", 0)],
        ["family_exists_capability_missing", coverage_counter.get("family_exists_capability_missing", 0)],
        ["family_missing", coverage_counter.get("family_missing", 0)],
        ["说明", "本表用于分析 Prometheus rules 到 webhook_v5 family/capability 的覆盖情况。"],
    ]

    rule_rows = [[
        "rule_name",
        "state",
        "severity",
        "group_name",
        "file",
        "description",
        "query",
        "recommended_family",
        "coverage_status",
        "priority",
        "family_exists",
        "suggested_capabilities",
        "missing_capabilities",
        "need_mcp",
        "need_prometheus",
        "need_elastic",
        "rule_id",
    ]]

    for item in enriched:
        rule_rows.append([
            item.get("name"),
            item.get("state"),
            item.get("severity"),
            item.get("group_name"),
            item.get("file"),
            item.get("description"),
            item.get("query"),
            item.get("recommended_family"),
            item.get("coverage_status"),
            item.get("priority"),
            item.get("family_exists"),
            safe_text(item.get("suggested_capabilities")),
            safe_text(item.get("missing_capabilities")),
            item.get("need_mcp"),
            item.get("need_prometheus"),
            item.get("need_elastic"),
            item.get("rule_id"),
        ])

    uncovered_rows = [[
        "rule_name",
        "description",
        "query",
        "recommended_family",
        "coverage_status",
        "priority",
        "suggested_capabilities",
        "missing_capabilities",
        "suggested_action",
    ]]

    for item in enriched:
        if item.get("coverage_status") == "covered_family_and_capability":
            continue

        fam = item.get("recommended_family")
        if item.get("coverage_status") == "family_missing":
            action = f"在 family_registry.py 中新增 {fam}，并在 capability_registry.py 中绑定能力。"
        else:
            action = f"在 capability_registry.py / platform_command_matrix.py 中补齐 {fam} 缺失能力：{safe_text(item.get('missing_capabilities'))}"

        uncovered_rows.append([
            item.get("name"),
            item.get("description"),
            item.get("query"),
            fam,
            item.get("coverage_status"),
            item.get("priority"),
            safe_text(item.get("suggested_capabilities")),
            safe_text(item.get("missing_capabilities")),
            action,
        ])

    family_summary_rows = [[
        "recommended_family",
        "rule_count",
        "coverage_status_count",
        "priority",
        "family_exists",
        "suggested_capabilities",
        "missing_capabilities_union",
        "need_mcp",
        "need_prometheus",
        "need_elastic",
    ]]

    grouped = defaultdict(list)
    for item in enriched:
        grouped[item["recommended_family"]].append(item)

    for fam in sorted(grouped.keys()):
        items = grouped[fam]
        status_count = Counter(x["coverage_status"] for x in items)
        missing_union = sorted(set(y for x in items for y in x.get("missing_capabilities", [])))
        caps_union = sorted(set(y for x in items for y in x.get("suggested_capabilities", [])))
        priorities = sorted(set(x["priority"] for x in items))
        family_summary_rows.append([
            fam,
            len(items),
            safe_text(dict(status_count)),
            ",".join(priorities),
            fam in current_families,
            safe_text(caps_union),
            safe_text(missing_union),
            any(x.get("need_mcp") for x in items),
            any(x.get("need_prometheus") for x in items),
            any(x.get("need_elastic") for x in items),
        ])

    new_family_rows = [[
        "recommended_family",
        "rule_count",
        "priority",
        "suggested_capabilities",
        "reason",
    ]]

    for fam, count in family_counter.most_common():
        if fam in current_families:
            continue

        sample_items = grouped[fam]
        sample_names = "；".join([safe_text(x.get("name")) for x in sample_items[:5]])
        new_family_rows.append([
            fam,
            count,
            ",".join(sorted(set(x["priority"] for x in sample_items))),
            safe_text(SUGGESTED_CAPABILITIES.get(fam, [])),
            f"Prometheus rules 中存在相关告警，例如：{sample_names}",
        ])

    priority_rows = [["priority", "rule_count"]]
    for pri, count in sorted(priority_counter.items()):
        priority_rows.append([pri, count])

    current_family_rows = [["current_family"]]
    for fam in sorted(current_families):
        current_family_rows.append([fam])

    sheets = [
        ("说明", readme_rows),
        ("Prometheus规则清单", rule_rows),
        ("未覆盖告警清单", uncovered_rows),
        ("family覆盖汇总", family_summary_rows),
        ("建议新增family", new_family_rows),
        ("优先级统计", priority_rows),
        ("当前已有family", current_family_rows),
    ]

    save_xlsx(sheets, output_path)

    print("PROM_RULE_COVERAGE_EXPORT_OK")
    print("rules_file =", rules_path)
    print("output =", output_path)
    print("rule_count =", len(enriched))
    print("coverage_status =", dict(coverage_counter))
    print("family_count =", len(family_counter))
    print("new_family_count =", len(new_family_rows) - 1)
    print("top_recommended_families =", family_counter.most_common(20))


if __name__ == "__main__":
    main()
